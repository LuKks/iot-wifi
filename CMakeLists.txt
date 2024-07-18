idf_component_register(
  SRC_DIRS "src"
  INCLUDE_DIRS "include"
  EMBED_FILES "src/wifi.html"
  REQUIRES esp_wifi
  PRIV_REQUIRES iot_crypto iot_nvs esp_partition nvs_flash esp_event esp_netif esp_http_server lwip
)
