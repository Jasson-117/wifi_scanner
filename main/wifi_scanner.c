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

/* ---------- Configura tu red (solo 2.4 GHz) ---------- */
#define WIFI_SSID "fh_0ef478"
#define WIFI_PASS "wlanf10b87"

#define MAX_AP_RECORDS 32
#define GOT_IP_BIT     BIT0

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

/* GET /api/scan -> ejecuta el escaneo y devuelve JSON */
static esp_err_t scan_handler(httpd_req_t *req)
{
    if (xSemaphoreTake(s_scan_mutex, 0) != pdTRUE) {
        return send_error(req, "409 Conflict", "Ya hay un escaneo en curso");
    }

    wifi_ap_record_t *recs = NULL;
    uint16_t n = 0, total = 0;
    esp_err_t err = do_scan(&recs, &n, &total);
    xSemaphoreGive(s_scan_mutex);

    if (err != ESP_OK) {
        return send_error(req, "500 Internal Server Error", "Error al escanear, intenta de nuevo");
    }

    int64_t ts = esp_timer_get_time() / 1000;
    char buf[420];

    httpd_resp_set_type(req, "application/json");
    int len = snprintf(buf, sizeof(buf),
                       "{\"timestamp_ms\":%lld,\"total\":%u,\"shown\":%u,\"aps\":[",
                       (long long)ts, total, n);
    httpd_resp_send_chunk(req, buf, len);

    for (uint16_t i = 0; i < n; i++) {
        char ssid_esc[200], bssid[18], phy[8];
        mac_to_str(recs[i].bssid, bssid);
        phy_to_str(&recs[i], phy);
        json_escape((const char *)recs[i].ssid, ssid_esc, sizeof(ssid_esc));

        len = snprintf(buf, sizeof(buf),
                       "%s{\"ssid\":\"%s\",\"bssid\":\"%s\",\"primary\":%d,\"channel\":%d,"
                       "\"rssi\":%d,\"phy\":\"%s\",\"auth\":\"%s\"}",
                       i ? "," : "", ssid_esc, bssid,
                       recs[i].primary, real_channel(&recs[i]),
                       recs[i].rssi, phy, auth_mode_to_str(recs[i].authmode));
        httpd_resp_send_chunk(req, buf, len);
    }

    httpd_resp_send_chunk(req, "]}", 2);
    httpd_resp_send_chunk(req, NULL, 0);   /* fin de la respuesta */

    free(recs);
    return ESP_OK;
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

    static const httpd_uri_t index_uri = {
        .uri = "/", .method = HTTP_GET, .handler = index_handler, .user_ctx = NULL
    };
    static const httpd_uri_t scan_uri = {
        .uri = "/api/scan", .method = HTTP_GET, .handler = scan_handler, .user_ctx = NULL
    };
    httpd_register_uri_handler(server, &index_uri);
    httpd_register_uri_handler(server, &scan_uri);
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