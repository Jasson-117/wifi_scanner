#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "freertos/semphr.h"
#include "nvs_flash.h"
#include "esp_netif.h"
#include "esp_event.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_http_server.h"
#include "esp_heap_caps.h"
#include "esp_random.h"
#include <stdarg.h>

/* ---------- Configura tu red (solo 2.4 GHz) ---------- */
#define WIFI_SSID "fh_0ef478"
#define WIFI_PASS "wlanf10b87"

#define MAX_AP_RECORDS 32
#define GOT_IP_BIT     BIT0
#define MAX_SEND       120   /* máx. escaneos por respuesta de /api/history */

static const char *TAG = "WIFI_SCAN";
static EventGroupHandle_t s_wifi_events;
static SemaphoreHandle_t s_scan_mutex;

/* index.html embebido en el binario (ver CMakeLists.txt) */
extern const char index_html_start[] asm("_binary_index_html_start");

/* ------------------------------------------------------------------ */
/*  Utilidades (las mismas de tu código original)                      */
/* ------------------------------------------------------------------ */
static const char *auth_mode_to_str(wifi_auth_mode_t authmode)
{
    switch (authmode) {
        case WIFI_AUTH_OPEN:            return "OPEN";
        case WIFI_AUTH_WEP:             return "WEP";
        case WIFI_AUTH_WPA_PSK:         return "WPA_PSK";
        case WIFI_AUTH_WPA2_PSK:        return "WPA2_PSK";
        case WIFI_AUTH_WPA_WPA2_PSK:    return "WPA/WPA2_PSK";
        case WIFI_AUTH_WPA3_PSK:        return "WPA3_PSK";
        case WIFI_AUTH_WPA2_WPA3_PSK:   return "WPA2/WPA3_PSK";
        case WIFI_AUTH_WAPI_PSK:        return "WAPI_PSK";
        case WIFI_AUTH_OWE:             return "OWE";
        case WIFI_AUTH_WPA3_ENT_192:    return "WPA3_ENT_192";
        default:                        return "UNKNOWN";
    }
}

static int cmp_rssi_desc(const void *a, const void *b)
{
    const wifi_ap_record_t *ap_a = (const wifi_ap_record_t *)a;
    const wifi_ap_record_t *ap_b = (const wifi_ap_record_t *)b;
    return ap_b->rssi - ap_a->rssi;
}

static void mac_to_str(const uint8_t mac[6], char out[18])
{
    snprintf(out, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void phy_to_str(const wifi_ap_record_t *ap, char out[8])
{
    int n = 0;
    if (ap->phy_11b) out[n++] = 'b';
    if (ap->phy_11g) out[n++] = 'g';
    if (ap->phy_11n) out[n++] = 'n';
    if (n == 0)      out[n++] = '?';
    out[n] = '\0';
}

/* Canal real considerando HT40 (segundo canal) */
static int real_channel(const wifi_ap_record_t *ap)
{
    if (ap->second == WIFI_SECOND_CHAN_ABOVE) return ap->primary + 4;
    if (ap->second == WIFI_SECOND_CHAN_BELOW) return ap->primary - 4;
    return ap->primary;
}

/* Escapa un string para ponerlo dentro de un JSON */
static void json_escape(const char *in, char *out, size_t out_size)
{
    size_t o = 0;
    for (; *in && o + 7 < out_size; in++) {
        unsigned char c = (unsigned char)*in;
        if (c == '"' || c == '\\') {
            out[o++] = '\\';
            out[o++] = (char)c;
        } else if (c < 0x20) {
            o += snprintf(out + o, out_size - o, "\\u%04X", c);
        } else {
            out[o++] = (char)c;
        }
    }
    out[o] = '\0';
}

/* ------------------------------------------------------------------ */
/*  Escaneo                                                            */
/* ------------------------------------------------------------------ */
static esp_err_t do_scan(wifi_ap_record_t **out, uint16_t *n_out, uint16_t *total_out)
{
    wifi_scan_config_t scan_config = {
        .ssid = NULL,
        .bssid = NULL,
        .channel = 0,
        .show_hidden = true,
        .scan_type = WIFI_SCAN_TYPE_ACTIVE,
        .scan_time.active.min = 100,
        .scan_time.active.max = 300,
    };

    *out = NULL;
    *n_out = 0;
    *total_out = 0;

    esp_err_t err = esp_wifi_scan_start(&scan_config, true);
    if (err != ESP_OK) return err;

    uint16_t total = 0;
    err = esp_wifi_scan_get_ap_num(&total);
    if (err != ESP_OK) return err;
    *total_out = total;
    if (total == 0) return ESP_OK;

    uint16_t n = (total > MAX_AP_RECORDS) ? MAX_AP_RECORDS : total;
    wifi_ap_record_t *recs = calloc(n, sizeof(*recs));
    if (!recs) return ESP_ERR_NO_MEM;

    err = esp_wifi_scan_get_ap_records(&n, recs);
    if (err != ESP_OK) {
        free(recs);
        return err;
    }
    qsort(recs, n, sizeof(*recs), cmp_rssi_desc);

    *out = recs;
    *n_out = n;
    return ESP_OK;
}

/* ------------------------------------------------------------------ */
/*  Servidor web                                                       */
/* ------------------------------------------------------------------ */
static esp_err_t send_error(httpd_req_t *req, const char *status, const char *msg)
{
    char body[96];
    snprintf(body, sizeof(body), "{\"error\":\"%s\"}", msg);
    httpd_resp_set_status(req, status);
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_sendstr(req, body);
}

static esp_err_t index_handler(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    return httpd_resp_send(req, index_html_start, HTTPD_RESP_USE_STRLEN);
}

/* ---------- Historial: buffer circular en PSRAM (o RAM si no hay) ---------- */
typedef struct {
    uint8_t bssid[6];
    char    ssid[33];
    int8_t  rssi;
    uint8_t primary, second, authmode, phy;   /* phy: bit0=b bit1=g bit2=n */
} ap_entry_t;

typedef struct {
    int64_t    ts_ms;
    uint16_t   total, count;
    ap_entry_t aps[MAX_AP_RECORDS];
} snapshot_t;

static snapshot_t *s_hist;
static int s_cap, s_len;
static bool s_psram;
static uint32_t s_seq_next = 1;          /* el escaneo n se guarda en la posición (n-1) % cap */
static uint32_t s_boot_id;               /* cambia en cada reinicio: el navegador lo detecta */
static volatile uint32_t s_auto_s;       /* intervalo del escaneo automático; 0 = apagado */
static SemaphoreHandle_t s_hist_mutex;

static void history_init(void)
{
    s_hist_mutex = xSemaphoreCreateMutex();
    s_boot_id = esp_random();
    s_hist = heap_caps_calloc(120, sizeof(snapshot_t), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (s_hist) { s_cap = 120; s_psram = true; return; }
    s_hist = heap_caps_calloc(30, sizeof(snapshot_t), MALLOC_CAP_8BIT);
    s_cap = s_hist ? 30 : 0;
}

static uint32_t store_snapshot(const wifi_ap_record_t *recs, uint16_t n, uint16_t total)
{
    if (!s_cap) return 0;
    xSemaphoreTake(s_hist_mutex, portMAX_DELAY);
    uint32_t seq = s_seq_next++;
    snapshot_t *sn = &s_hist[(seq - 1) % s_cap];
    sn->ts_ms = esp_timer_get_time() / 1000;
    sn->total = total;
    sn->count = n;
    for (uint16_t i = 0; i < n; i++) {
        ap_entry_t *e = &sn->aps[i];
        const wifi_ap_record_t *r = &recs[i];
        memcpy(e->bssid, r->bssid, 6);
        strlcpy(e->ssid, (const char *)r->ssid, sizeof(e->ssid));
        e->rssi = r->rssi;
        e->primary = r->primary;
        e->second = r->second;
        e->authmode = r->authmode;
        e->phy = r->phy_11b | (r->phy_11g << 1) | (r->phy_11n << 2);
    }
    if (s_len < s_cap) s_len++;
    xSemaphoreGive(s_hist_mutex);
    return seq;
}

/* Escanea y guarda en el historial. ESP_ERR_INVALID_STATE = ya hay un escaneo en curso */
static esp_err_t scan_and_store(uint32_t *seq_out)
{
    if (xSemaphoreTake(s_scan_mutex, 0) != pdTRUE) return ESP_ERR_INVALID_STATE;
    wifi_ap_record_t *recs = NULL;
    uint16_t n = 0, total = 0;
    esp_err_t err = do_scan(&recs, &n, &total);
    if (err == ESP_OK) {
        uint32_t seq = store_snapshot(recs, n, total);
        if (seq_out) *seq_out = seq;
    }
    free(recs);
    xSemaphoreGive(s_scan_mutex);
    return err;
}

static void auto_scan_task(void *arg)
{
    uint32_t waited = 0;
    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(1000));
        if (s_auto_s == 0) { waited = 0; continue; }
        if (++waited >= s_auto_s) {
            waited = 0;
            scan_and_store(NULL);
        }
    }
}

/* ---------- JSON por bloques (agrupa en 1 KB antes de enviar) ---------- */
typedef struct { httpd_req_t *req; size_t len; char buf[1024]; } jw_t;

static void jw_flush(jw_t *w)
{
    if (w->len) httpd_resp_send_chunk(w->req, w->buf, w->len);
    w->len = 0;
}

static void jw_printf(jw_t *w, const char *fmt, ...)
{
    char tmp[480];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    if (n <= 0) return;
    if (n >= (int)sizeof(tmp)) n = sizeof(tmp) - 1;
    if (w->len + n > sizeof(w->buf)) jw_flush(w);
    memcpy(w->buf + w->len, tmp, n);
    w->len += n;
}

static void jw_snapshot(jw_t *w, uint32_t seq, const snapshot_t *sn)
{
    jw_printf(w, "{\"seq\":%u,\"timestamp_ms\":%lld,\"total\":%u,\"shown\":%u,\"aps\":[",
              (unsigned)seq, (long long)sn->ts_ms, sn->total, sn->count);
    for (uint16_t i = 0; i < sn->count; i++) {
        const ap_entry_t *e = &sn->aps[i];
        char ssid_esc[200], bssid[18], phy[8];
        int k = 0, ch2 = e->primary;
        mac_to_str(e->bssid, bssid);
        json_escape(e->ssid, ssid_esc, sizeof(ssid_esc));
        if (e->phy & 1) phy[k++] = 'b';
        if (e->phy & 2) phy[k++] = 'g';
        if (e->phy & 4) phy[k++] = 'n';
        if (!k) phy[k++] = '?';
        phy[k] = '\0';
        if (e->second == WIFI_SECOND_CHAN_ABOVE) ch2 += 4;
        else if (e->second == WIFI_SECOND_CHAN_BELOW) ch2 -= 4;
        jw_printf(w, "%s{\"ssid\":\"%s\",\"bssid\":\"%s\",\"primary\":%d,\"channel\":%d,"
                     "\"rssi\":%d,\"phy\":\"%s\",\"auth\":\"%s\"}",
                  i ? "," : "", ssid_esc, bssid, e->primary, ch2, e->rssi, phy,
                  auth_mode_to_str((wifi_auth_mode_t)e->authmode));
    }
    jw_printf(w, "]}");
}

/* ---------- Handlers ---------- */

/* GET /api/scan -> escanea ahora, guarda en el historial y devuelve ese escaneo */
static esp_err_t scan_handler(httpd_req_t *req)
{
    uint32_t seq = 0;
    esp_err_t err = scan_and_store(&seq);
    if (err == ESP_ERR_INVALID_STATE) return send_error(req, "409 Conflict", "Ya hay un escaneo en curso");
    if (err != ESP_OK || !seq) return send_error(req, "500 Internal Server Error", "Error al escanear, intenta de nuevo");

    jw_t w = { .req = req };
    httpd_resp_set_type(req, "application/json");
    xSemaphoreTake(s_hist_mutex, portMAX_DELAY);
    jw_snapshot(&w, seq, &s_hist[(seq - 1) % s_cap]);
    xSemaphoreGive(s_hist_mutex);
    jw_flush(&w);
    return httpd_resp_send_chunk(req, NULL, 0);
}

/* GET /api/history?after=SEQ&boot=ID -> solo los escaneos nuevos */
static esp_err_t history_handler(httpd_req_t *req)
{
    char q[64] = "", v[16];
    uint32_t after = 0, boot = 0;
    if (httpd_req_get_url_query_str(req, q, sizeof(q)) == ESP_OK) {
        if (httpd_query_key_value(q, "after", v, sizeof(v)) == ESP_OK) after = strtoul(v, NULL, 10);
        if (httpd_query_key_value(q, "boot", v, sizeof(v)) == ESP_OK) boot = strtoul(v, NULL, 10);
    }
    bool reset = (boot != s_boot_id);   /* el ESP32 se reinició: el navegador debe empezar de cero */
    if (reset) after = 0;

    jw_t w = { .req = req };
    httpd_resp_set_type(req, "application/json");

    xSemaphoreTake(s_hist_mutex, portMAX_DELAY);
    uint32_t latest = s_seq_next - 1;
    uint32_t oldest = s_seq_next - s_len;
    uint32_t start = after + 1;
    if (start < oldest) start = oldest;
    if (latest >= MAX_SEND && start < latest - MAX_SEND + 1) start = latest - MAX_SEND + 1;

    jw_printf(&w, "{\"boot\":%u,\"reset\":%s,\"latest\":%u,\"cap\":%d,\"psram\":%s,\"interval\":%u,\"snaps\":[",
              (unsigned)s_boot_id, reset ? "true" : "false", (unsigned)latest, s_cap,
              s_psram ? "true" : "false", (unsigned)s_auto_s);
    for (uint32_t k = start; k <= latest; k++) {
        if (k > start) jw_printf(&w, ",");
        jw_snapshot(&w, k, &s_hist[(k - 1) % s_cap]);
    }
    xSemaphoreGive(s_hist_mutex);

    jw_printf(&w, "]}");
    jw_flush(&w);
    return httpd_resp_send_chunk(req, NULL, 0);
}

/* POST /api/auto?interval=N -> escaneo automático cada N s (0 = apagado, mín. 10) */
static esp_err_t auto_handler(httpd_req_t *req)
{
    char q[32] = "", v[12];
    if (httpd_req_get_url_query_str(req, q, sizeof(q)) == ESP_OK &&
        httpd_query_key_value(q, "interval", v, sizeof(v)) == ESP_OK) {
        uint32_t n = strtoul(v, NULL, 10);
        s_auto_s = (n == 0) ? 0 : (n < 10 ? 10 : (n > 3600 ? 3600 : n));
    }
    char body[40];
    snprintf(body, sizeof(body), "{\"interval\":%u}", (unsigned)s_auto_s);
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_sendstr(req, body);
}

static void start_webserver(void)
{
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.stack_size = 8192;

    httpd_handle_t server = NULL;
    if (httpd_start(&server, &config) != ESP_OK) {
        ESP_LOGE(TAG, "No se pudo iniciar el servidor web");
        return;
    }

    static const httpd_uri_t uris[] = {
        { .uri = "/",            .method = HTTP_GET,  .handler = index_handler },
        { .uri = "/api/scan",    .method = HTTP_GET,  .handler = scan_handler },
        { .uri = "/api/history", .method = HTTP_GET,  .handler = history_handler },
        { .uri = "/api/auto",    .method = HTTP_POST, .handler = auto_handler },
    };
    for (size_t i = 0; i < sizeof(uris) / sizeof(uris[0]); i++) {
        httpd_register_uri_handler(server, &uris[i]);
    }
}

/* ------------------------------------------------------------------ */
/*  Wi-Fi (STA) y arranque                                             */
/* ------------------------------------------------------------------ */
static void wifi_event_handler(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        esp_wifi_connect();                       /* reintenta siempre */
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *e = (ip_event_got_ip_t *)data;
        /* Único mensaje por consola: la IP para entrar a la página. */
        ESP_LOGI(TAG, "Abre en tu navegador: http://" IPSTR, IP2STR(&e->ip_info.ip));
        xEventGroupSetBits(s_wifi_events, GOT_IP_BIT);
    }
}

static void init_nvs(void)
{
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);
}

void app_main(void)
{
    /* Silencia todos los logs excepto el de la IP */
    esp_log_level_set("*", ESP_LOG_NONE);
    esp_log_level_set(TAG, ESP_LOG_INFO);

    s_wifi_events = xEventGroupCreate();
    s_scan_mutex  = xSemaphoreCreateMutex();
    history_init();
    xTaskCreate(auto_scan_task, "auto_scan", 4096, NULL, 5, NULL);

    init_nvs();
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL, NULL));

    wifi_config_t wifi_config = {
        .sta = {
            .ssid = WIFI_SSID,
            .password = WIFI_PASS,
        },
    };
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());
    esp_wifi_set_ps(WIFI_PS_NONE);               /* respuesta más rápida del servidor */

    /* Espera a tener IP y recién ahí levanta el servidor */
    xEventGroupWaitBits(s_wifi_events, GOT_IP_BIT, pdFALSE, pdTRUE, portMAX_DELAY);
    start_webserver();
}
