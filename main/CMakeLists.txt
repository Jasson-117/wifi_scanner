idf_component_register(SRCS "wifi_scanner.c"
                         INCLUDE_DIRS "."
    REQUIRES led_strip esp_driver_gpio esp_timer esp_wifi esp_event esp_http_server nvs_flash
    EMBED_TXTFILES "index.html"
)