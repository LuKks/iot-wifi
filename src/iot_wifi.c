#ifndef CONFIG_HTTPD_MAX_REQ_HDR_LEN
#define CONFIG_HTTPD_MAX_REQ_HDR_LEN 2048
#endif

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <esp_event.h>
#include <esp_http_server.h>
#include <esp_log.h>
#include <esp_mac.h>
#include <esp_netif.h>
#include <esp_system.h>
#include <esp_wifi.h>
#include <freertos/FreeRTOS.h>
#include <freertos/event_groups.h>
#include <freertos/semphr.h>
#include <freertos/task.h>
#include <nvs_flash.h>

#include <iot_crypto.h>
#include <iot_nvs.h>

#include "../include/iot_wifi.h"
#include "internal.h"

static const char *TAG = "WIFI";

static bool wifi__initialized = false;
static bool wifi__is_automatic = false;

static esp_netif_t *netif_ap = NULL;
static esp_netif_t *netif_sta = NULL;

static httpd_handle_t server = NULL;

extern const uint8_t wifi_html_start[] asm("_binary_wifi_html_start");
extern const uint8_t wifi_html_end[] asm("_binary_wifi_html_end");

static esp_event_handler_instance_t instance_any_id = NULL;
static esp_event_handler_instance_t instance_scan_done = NULL;
static esp_event_handler_instance_t instance_got_ip = NULL;

static wifi_scan_result_t scan_result;

static void
wifi__switch (wifi_mode_t mode);

static void
wifi__stop (wifi_mode_t mode);

static void
wifi__prepare_automatic_hotspot ();

static void
wifi__server_start ();

static void
wifi__server_stop ();

static void
wifi__event_handler (void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data);

void
wifi_init () {
  if (wifi__initialized) {
    return;
  }

  ESP_LOGI(TAG, "wifi_init()");

  ESP_ERROR_CHECK(nvs_flash_init());
  ESP_ERROR_CHECK(esp_netif_init());

  nvs_create("wifi");

  esp_err_t err_loop = esp_event_loop_create_default();
  bool loop_already_created = err_loop == ESP_ERR_INVALID_STATE;

  if (loop_already_created == false) {
    ESP_ERROR_CHECK(err_loop);
  }

  if (instance_any_id == NULL) {
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi__event_handler, NULL, &instance_any_id));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, WIFI_EVENT_SCAN_DONE, &wifi__event_handler, NULL, &instance_scan_done));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi__event_handler, NULL, &instance_got_ip));
  }

  if (netif_ap == NULL && netif_sta == NULL) {
    netif_ap = esp_netif_create_default_wifi_ap();
    netif_sta = esp_netif_create_default_wifi_sta();
  }

  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_wifi_init(&cfg));

  wifi__prepare_automatic_hotspot();

  wifi__initialized = true;
}

void
wifi_destroy () {
  if (wifi__initialized == false) {
    return;
  }

  ESP_LOGI(TAG, "wifi_destroy()");

  if (instance_any_id) {
    ESP_ERROR_CHECK(esp_event_handler_instance_unregister(WIFI_EVENT, ESP_EVENT_ANY_ID, instance_any_id));
    ESP_ERROR_CHECK(esp_event_handler_instance_unregister(WIFI_EVENT, WIFI_EVENT_SCAN_DONE, instance_scan_done));
    ESP_ERROR_CHECK(esp_event_handler_instance_unregister(IP_EVENT, IP_EVENT_STA_GOT_IP, instance_got_ip));

    instance_any_id = NULL;
    instance_scan_done = NULL;
    instance_got_ip = NULL;
  }

  ESP_ERROR_CHECK(esp_wifi_stop());
  ESP_ERROR_CHECK(esp_wifi_deinit());

  if (netif_ap && netif_sta) {
    esp_netif_destroy_default_wifi(netif_ap);
    esp_netif_destroy_default_wifi(netif_sta);

    netif_ap = NULL;
    netif_sta = NULL;
  }

  wifi__initialized = false;
}

void
wifi_hotspot (const char *ssid, const char *password) {
  wifi_init();

  ESP_LOGI(TAG, "wifi_hotspot(%s, %s)", ssid, password);

  wifi_config_t wifi_config = {
    .ap = {
      .ssid_len = strlen(ssid),
      .authmode = WIFI_AUTH_WPA2_PSK,
      .max_connection = 4,
    },
  };

  strncpy((char *) &wifi_config.ap.ssid, ssid, sizeof(char) * 32);
  strncpy((char *) &wifi_config.ap.password, password, sizeof(char) * 64);

  wifi__switch(WIFI_MODE_AP);

  ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &wifi_config));
  ESP_ERROR_CHECK(esp_wifi_start());
}

void
wifi_hotspot_off () {
  wifi_init();

  ESP_LOGI(TAG, "wifi_hotspot_off()");

  wifi__stop(WIFI_MODE_AP);
}

void
wifi_connect (const char *ssid, const char *password) {
  wifi_init();

  ESP_LOGI(TAG, "wifi_connect(%s, %s)", ssid, password);

  wifi_config_t wifi_config = {
    .sta = {
      .threshold.authmode = WIFI_AUTH_WPA2_PSK,
    },
  };

  strncpy((char *) &wifi_config.sta.ssid, ssid, sizeof(char) * 32);
  strncpy((char *) &wifi_config.sta.password, password, sizeof(char) * 64);

  wifi__switch(WIFI_MODE_STA);

  ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
  ESP_ERROR_CHECK(esp_wifi_start());

  ESP_ERROR_CHECK(esp_wifi_connect());
}

void
wifi_disconnect () {
  wifi_init();

  ESP_LOGI(TAG, "wifi_disconnect()");

  wifi__stop(WIFI_MODE_STA);
}

static void
wifi__prepare_automatic_hotspot () {
  char *hotspot_ssid = nvs_read_string("wifi", "hotspot-ssid");
  char *hotspot_pass = nvs_read_string("wifi", "hotspot-pass");

  if (hotspot_ssid == NULL || hotspot_pass == NULL) {
    char random_ssid[8 + 1];
    char random_pass[8 + 1];

    crypto_random_fill_hex(random_ssid, sizeof(random_ssid));
    crypto_random_fill_hex(random_pass, sizeof(random_pass));

    char ssid[32 + 1];
    char pass[32 + 1];

    sprintf(ssid, "Access Point (%s)", random_ssid);
    sprintf(pass, "%s", random_pass);

    nvs_write_string("wifi", "hotspot-ssid", ssid);
    nvs_write_string("wifi", "hotspot-pass", pass);
  } else {
    free(hotspot_ssid);
    free(hotspot_pass);
  }
}

// TODO: Works but it's triggering events multiple times
// Probably allow passing the new config here to set mode last
static void
wifi__switch (wifi_mode_t mode) {
  wifi_mode_t target_config = mode == WIFI_MODE_STA ? WIFI_IF_STA : WIFI_IF_AP;
  wifi_mode_t contrary_mode = mode == WIFI_MODE_STA ? WIFI_MODE_AP : WIFI_MODE_STA;
  wifi_mode_t current_mode;

  ESP_LOGI(TAG, "wifi__switch(%s)", mode == WIFI_MODE_STA ? "WIFI_MODE_STA" : (mode == WIFI_MODE_AP ? "WIFI_MODE_AP" : "WIFI_MODE_APSTA"));

  ESP_ERROR_CHECK(esp_wifi_get_mode(&current_mode));

  if (current_mode == contrary_mode && current_mode != WIFI_MODE_APSTA) {
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));

    wifi_config_t wifi_sta_config;
    esp_wifi_get_config(target_config, &wifi_sta_config);
    ESP_ERROR_CHECK(esp_wifi_set_config(target_config, &wifi_sta_config));
  } else {
    ESP_ERROR_CHECK(esp_wifi_set_mode(mode));
  }
}

static void
wifi__stop (wifi_mode_t mode) {
  wifi_mode_t contrary_mode = mode == WIFI_MODE_STA ? WIFI_MODE_AP : WIFI_MODE_STA;
  wifi_mode_t current_mode;

  ESP_LOGI(TAG, "wifi__stop(%s)", mode == WIFI_MODE_STA ? "WIFI_MODE_STA" : (mode == WIFI_MODE_AP ? "WIFI_MODE_AP" : "WIFI_MODE_APSTA"));

  ESP_ERROR_CHECK(esp_wifi_get_mode(&current_mode));

  if (current_mode == mode) {
    ESP_ERROR_CHECK(esp_wifi_stop());
  } else if (current_mode == WIFI_MODE_APSTA) {
    ESP_ERROR_CHECK(esp_wifi_set_mode(contrary_mode));
  }
}

void
wifi_scan (wifi_scan_result_t *result) {
  wifi_init();

  ESP_LOGI(TAG, "wifi_scan()");

  // TODO: Test this when it's already on AP/APSTA mode
  // Something with the scan seems to conflict with disconnect and hotspot in the init
  wifi__switch(WIFI_MODE_STA);

  ESP_ERROR_CHECK(esp_wifi_start());

  // TODO: "STA is connecting, scan are not allowed" probably because esp_wifi saves the credentials also
  // Use wifi_disconnect() before wifi_scan() to avoid reconnection
  // ESP_ERROR_CHECK(esp_wifi_disconnect());

  wifi_scan_config_t scan_config = {
    .scan_type = WIFI_SCAN_TYPE_ACTIVE,
    .scan_time = {
      .active = {
        .min = 100,
        .max = 300
      },
    },
  };

  ESP_ERROR_CHECK(esp_wifi_scan_stop());
  ESP_ERROR_CHECK(esp_wifi_clear_ap_list());

  result->ap_num = 0;
  memset(result->ap_records, 0, sizeof(result->ap_records));

  ESP_ERROR_CHECK(esp_wifi_scan_start(&scan_config, true));
  ESP_ERROR_CHECK(esp_wifi_scan_get_ap_num(&result->ap_num));

  result->ap_num = math_min(result->ap_num, WIFI_MAX_SCAN);

  ESP_ERROR_CHECK(esp_wifi_scan_get_ap_records(&result->ap_num, result->ap_records));
}

void
wifi_automatic () {
  wifi_init();

  ESP_LOGI(TAG, "wifi_automatic()");

  wifi__is_automatic = true;

  char *connect_ssid = nvs_read_string("wifi", "connect-ssid");
  char *connect_pass = nvs_read_string("wifi", "connect-pass");

  if (connect_ssid == NULL || connect_pass == NULL) {
    // TODO: It should scan on each request, but the server crashes. Even on a different task
    wifi_disconnect();
    wifi_scan(&scan_result);

    wifi__server_start();

    char *hotspot_ssid = nvs_read_string("wifi", "hotspot-ssid");
    char *hotspot_pass = nvs_read_string("wifi", "hotspot-pass");

    wifi_hotspot(hotspot_ssid, hotspot_pass);

    free(hotspot_ssid);
    free(hotspot_pass);
  } else {
    wifi_hotspot_off();
    wifi_connect(connect_ssid, connect_pass);

    free(connect_ssid);
    free(connect_pass);
  }
}

void
wifi_automatic_off () {
  wifi__is_automatic = false;

  wifi__server_stop();

  wifi_disconnect();
  wifi_hotspot_off();
}

static esp_err_t
http__root_handler (httpd_req_t *req) {
  char PLACEHOLDER[] = "<option value=\"SSID\">SSID</option>\n";

  size_t html_len = wifi_html_end - wifi_html_start;
  size_t records_size = (strlen(PLACEHOLDER) + sizeof(((wifi_ap_record_t *) 0)->ssid) * 2) * WIFI_MAX_SCAN;

  char form[html_len + records_size + 1];
  memcpy(form, wifi_html_start, html_len);
  form[html_len] = '\0';

  char access_points[records_size];
  access_points[0] = '\0';

  for (int i = 0; i < scan_result.ap_num; i++) {
    snprintf(
      access_points + strlen(access_points),
      sizeof(access_points) - strlen(access_points),
      "<option value=\"%s\">%s</option>\n",
      scan_result.ap_records[i].ssid,
      scan_result.ap_records[i].ssid
    );
  }

  replace_all(form, PLACEHOLDER, access_points);

  httpd_resp_send(req, form, HTTPD_RESP_USE_STRLEN);

  return ESP_OK;
}

static esp_err_t
http__connect_handler (httpd_req_t *req) {
  char data[128];
  size_t recv_size = math_min(req->content_len, sizeof(data) - 1);
  int read = httpd_req_recv(req, data, recv_size);

  if (read <= 0) {
    if (read == HTTPD_SOCK_ERR_TIMEOUT) {
      httpd_resp_send_408(req);
    }

    return ESP_FAIL;
  }

  data[read] = '\0';

  char *ssid = strtok(data, "&");
  char *pass = strtok(NULL, "&");

  if (!ssid || !pass) {
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "WiFi name and password are required");
    return ESP_FAIL;
  }

  char ssid_decoded[32];
  char pass_decoded[64];

  decode_uri_form(strchr(ssid, '=') + 1, ssid_decoded);
  decode_uri_form(strchr(pass, '=') + 1, pass_decoded);

  nvs_write_string("wifi", "connect-ssid", ssid_decoded);
  nvs_write_string("wifi", "connect-pass", pass_decoded);

  httpd_resp_send(req, NULL, 0);

  esp_restart();

  return ESP_OK;
}

static esp_err_t
http__restart_handler (httpd_req_t *req) {
  httpd_resp_send(req, NULL, 0);

  // Temporal way to restart in case scan gets old until server crash is fixed
  esp_restart();

  return ESP_OK;
}

static esp_err_t
http__captive_handler (httpd_req_t *req) {
  httpd_resp_set_status(req, "302 Found");
  httpd_resp_set_hdr(req, "Location", "/");
  httpd_resp_send(req, NULL, 0);

  return ESP_OK;
}

static void
wifi__server_start () {
  if (server) {
    return;
  }

  httpd_config_t config = HTTPD_DEFAULT_CONFIG();

  config.stack_size = 8 * 1024;
  config.task_priority = 4;
  config.server_port = 80;
  config.max_uri_handlers = 8;
  config.uri_match_fn = httpd_uri_match_wildcard;

  httpd_uri_t root_uri = {
    .uri = "/",
    .method = HTTP_GET,
    .handler = http__root_handler,
    .user_ctx = NULL,
  };

  httpd_uri_t connect_uri = {
    .uri = "/connect",
    .method = HTTP_POST,
    .handler = http__connect_handler,
    .user_ctx = NULL,
  };

  httpd_uri_t restart_uri = {
    .uri = "/restart",
    .method = HTTP_GET,
    .handler = http__restart_handler,
    .user_ctx = NULL,
  };

  httpd_uri_t captive_uri = {
    .uri = "/*",
    .method = HTTP_GET,
    .handler = http__captive_handler,
    .user_ctx = NULL,
  };

  ESP_ERROR_CHECK(httpd_start(&server, &config));

  httpd_register_uri_handler(server, &root_uri);
  httpd_register_uri_handler(server, &connect_uri);
  httpd_register_uri_handler(server, &restart_uri);
  httpd_register_uri_handler(server, &captive_uri);
}

static void
wifi__server_stop () {
  if (server) {
    httpd_stop(server);
    server = NULL;
  }
}

static void
wifi__on_sta_disconnected (wifi_event_sta_disconnected_t *event) {
  wifi_mode_t current_mode;
  ESP_ERROR_CHECK(esp_wifi_get_mode(&current_mode));
  bool reconnect = current_mode == WIFI_MODE_STA || current_mode == WIFI_MODE_APSTA;

  ESP_LOGI(TAG, "WIFI_EVENT_STA_DISCONNECTED (reason: %d) (reconnect? %d)", event->reason, reconnect);

  if (reconnect == false) {
    return;
  }

  // TODO: Create the server only if disconnected for 5 minutes
  if (wifi__is_automatic && server == NULL) {
    ESP_LOGI(TAG, "Creating WiFi server once");

    esp_wifi_disconnect();
    wifi_scan(&scan_result);

    wifi__server_start();

    char *hotspot_ssid = nvs_read_string("wifi", "hotspot-ssid");
    char *hotspot_pass = nvs_read_string("wifi", "hotspot-pass");

    wifi_hotspot(hotspot_ssid, hotspot_pass);

    free(hotspot_ssid);
    free(hotspot_pass);
  }

  esp_err_t err = esp_wifi_connect();

  if (err != ESP_ERR_WIFI_NOT_STARTED) {
    ESP_ERROR_CHECK(err);
  }
}

static void
wifi__on_got_ip (ip_event_got_ip_t *event) {
  ESP_LOGI(TAG, "IP_EVENT_STA_GOT_IP:" IPSTR, IP2STR(&event->ip_info.ip));

  if (wifi__is_automatic && server) {
    ESP_LOGI(TAG, "Stopping WiFi server once");

    wifi__server_stop();
    wifi_hotspot_off();
  }
}

static void
wifi__event_handler (void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data) {
  if (event_base == WIFI_EVENT) {
    if (event_id == WIFI_EVENT_STA_DISCONNECTED) {
      wifi__on_sta_disconnected((wifi_event_sta_disconnected_t *) event_data);
    }
  } else if (event_base == IP_EVENT) {
    if (event_id == IP_EVENT_STA_GOT_IP) {
      wifi__on_got_ip((ip_event_got_ip_t *) event_data);
    }
  }
}
