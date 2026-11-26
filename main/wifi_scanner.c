#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs_flash.h"
#include "esp_netif.h"
#include "esp_event.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_timer.h"

#define MAX_AP_RECORDS 32
#define SCAN_INTERVAL_MS 10000   /* reescanea cada 10 s */

static const char *TAG = "WIFI_SCAN";

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

static void escanear_y_mostrar_redes(void)
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

    ESP_LOGI(TAG, "Iniciando escaneo Wi-Fi...");
    if (esp_wifi_scan_start(&scan_config, true) != ESP_OK) {
        ESP_LOGE(TAG, "Error al iniciar escaneo");
        return;
    }

    uint16_t ap_count = 0;
    ESP_ERROR_CHECK(esp_wifi_scan_get_ap_num(&ap_count));
    if (ap_count == 0) { ESP_LOGW(TAG, "Sin redes."); return; }

    uint16_t n = (ap_count > MAX_AP_RECORDS) ? MAX_AP_RECORDS : ap_count;
    wifi_ap_record_t *recs = calloc(n, sizeof(*recs));
    if (!recs) { ESP_LOGE(TAG, "calloc falló"); return; }

    ESP_ERROR_CHECK(esp_wifi_scan_get_ap_records(&n, recs));
    qsort(recs, n, sizeof(*recs), cmp_rssi_desc);

    /* --- Tabla legible --- */
    printf("\n%-24s | %-17s | %-5s | %-8s | %-6s | %-14s\n",
           "SSID", "BSSID", "Canal", "RSSI", "PHY", "Auth");
    printf("------------------------------------------------------------------------------------------\n");
    for (uint16_t i = 0; i < n; i++) {
        char bssid[18], phy[8];
        mac_to_str(recs[i].bssid, bssid);
        phy_to_str(&recs[i], phy);
        const char *ssid = recs[i].ssid[0] ? (const char *)recs[i].ssid : "<OCULTO>";
        printf("%-24.24s | %-17s | %2d(%2d) | %4d dBm | %-6s | %-14s\n",
               ssid, bssid,
               recs[i].primary, real_channel(&recs[i]),
               recs[i].rssi, phy,
               auth_mode_to_str(recs[i].authmode));
    }
    printf("Total: %u (mostrando %u)\n\n", ap_count, n);

    /* --- CSV exportable (cópialo a un archivo .csv y ábrelo en Excel/Python) --- */
    printf("#CSV_START,timestamp_ms,ssid,bssid,channel,sec_channel,rssi,auth,phy\n");
    int64_t ts = esp_timer_get_time() / 1000;
    for (uint16_t i = 0; i < n; i++) {
        char bssid[18], phy[8];
        mac_to_str(recs[i].bssid, bssid);
        phy_to_str(&recs[i], phy);
        const char *ssid = recs[i].ssid[0] ? (const char *)recs[i].ssid : "(hidden)";
        printf("CSV,%lld,%s,%s,%d,%d,%d,%s,%s\n",
               (long long)ts, ssid, bssid,
               recs[i].primary, real_channel(&recs[i]),
               recs[i].rssi,
               auth_mode_to_str(recs[i].authmode), phy);
    }
    printf("#CSV_END\n\n");

    free(recs);
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
    init_nvs();
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());

    while (1) {
        escanear_y_mostrar_redes();
        vTaskDelay(pdMS_TO_TICKS(SCAN_INTERVAL_MS));
    }
}
