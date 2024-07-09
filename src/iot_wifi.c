#define CONFIG_HTTPD_MAX_REQ_HDR_LEN 2048
#define HTTPD_MAX_REQ_HDR_LEN        2048

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

static esp_netif_t *netif_ap = NULL;
static esp_netif_t *netif_sta = NULL;

static char *wifi_hotspot_ssid = NULL;
static char *wifi_hotspot_pass = NULL;

static char *wifi_connect_ssid = NULL;
static char *wifi_connect_pass = NULL;

static httpd_handle_t server = NULL;

static esp_event_handler_instance_t instance_any_id = NULL;
static esp_event_handler_instance_t instance_scan_done = NULL;
static esp_event_handler_instance_t instance_got_ip = NULL;

static EventGroupHandle_t wifi_events = NULL;
static int wifi_retries = 0;

#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT      BIT1

wifi_ap_record_t ap_records[WIFI_MAX_SCAN];
uint16_t ap_num = 0;

void
wifi__switch (wifi_mode_t mode);

void
wifi__stop (wifi_mode_t mode);

void
wifi__prepare_automatic_hotspot ();

void
wifi__server_start ();

static void
event_handler (void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data);

void
wifi_init () {
  ESP_ERROR_CHECK(nvs_flash_init());

  nvs_create("wifi");

  ESP_ERROR_CHECK(esp_netif_init());

  esp_err_t err_loop = esp_event_loop_create_default();
  bool loop_already_created = err_loop == ESP_ERR_INVALID_STATE;

  if (loop_already_created == false) {
    ESP_ERROR_CHECK(err_loop);
  }

  if (wifi_events == NULL) {
    wifi_events = xEventGroupCreate();

    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL, &instance_any_id));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, WIFI_EVENT_SCAN_DONE, &event_handler, NULL, &instance_scan_done));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &event_handler, NULL, &instance_got_ip));
  }

  if (netif_ap == NULL && netif_sta == NULL) {
    netif_ap = esp_netif_create_default_wifi_ap();
    netif_sta = esp_netif_create_default_wifi_sta();
  }

  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_wifi_init(&cfg));

  wifi__prepare_automatic_hotspot();
}

void
wifi_destroy () {
  if (wifi_events) {
    vEventGroupDelete(wifi_events);

    wifi_events = NULL;

    ESP_ERROR_CHECK(esp_event_handler_instance_unregister(IP_EVENT, IP_EVENT_STA_GOT_IP, instance_got_ip)); // &instance_got_ip?
    ESP_ERROR_CHECK(esp_event_handler_instance_unregister(WIFI_EVENT, WIFI_EVENT_SCAN_DONE, instance_scan_done));
    ESP_ERROR_CHECK(esp_event_handler_instance_unregister(WIFI_EVENT, ESP_EVENT_ANY_ID, instance_any_id));
  }

  ESP_ERROR_CHECK(esp_wifi_stop());
  ESP_ERROR_CHECK(esp_wifi_deinit());

  if (netif_ap && netif_sta) {
    esp_netif_destroy_default_wifi(netif_ap);
    esp_netif_destroy_default_wifi(netif_sta);

    netif_ap = NULL;
    netif_sta = NULL;
  }
}

void
wifi_hotspot (const char *ssid, const char *password) {
  ESP_LOGI(TAG, "wifi_hotspot(%s, %s)", ssid, password);

  wifi_config_t wifi_config = {
    .ap = {
      .ssid_len = strlen(ssid),
      // .channel = 0,
      .authmode = WIFI_AUTH_WPA2_PSK,
      .max_connection = 4,
    },
  };

  printf("wifi_config.ap.channel: %d\n", wifi_config.ap.channel);

  strncpy((char *) &wifi_config.ap.ssid, ssid, sizeof(char) * 32);
  strncpy((char *) &wifi_config.ap.password, password, sizeof(char) * 64);

  wifi__switch(WIFI_MODE_AP);

  ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &wifi_config));
  ESP_ERROR_CHECK(esp_wifi_start());
}

void
wifi_hotspot_off () {
  wifi__stop(WIFI_MODE_AP);
}

void
wifi_connect (const char *ssid, const char *password) {
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
}

void
wifi_disconnect () {
  ESP_LOGI(TAG, "wifi_disconnect()");

  wifi__stop(WIFI_MODE_STA);
}

void
wifi__prepare_automatic_hotspot () {
  char *hotspot_identifier = nvs_read_string("wifi", "hotspot-ssid");
  char *hotspot_password = nvs_read_string("wifi", "hotspot-pass");

  if (hotspot_identifier == NULL || hotspot_password == NULL) {
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
    free(hotspot_identifier);
    free(hotspot_password);
  }
}

void
wifi_ready () {
  EventBits_t bits = xEventGroupWaitBits(wifi_events, WIFI_CONNECTED_BIT | WIFI_FAIL_BIT, pdFALSE, pdFALSE, portMAX_DELAY);

  if (bits & WIFI_CONNECTED_BIT) {
    ESP_LOGI(TAG, "connected to AP");
  } else if (bits & WIFI_FAIL_BIT) {
    ESP_LOGI(TAG, "Failed to connect");
  } else {
    ESP_LOGE(TAG, "UNEXPECTED EVENT");
  }
}

void
wifi__switch (wifi_mode_t mode) {
  wifi_mode_t target_config = mode == WIFI_MODE_STA ? WIFI_IF_STA : WIFI_IF_AP;
  wifi_mode_t contrary_mode = mode == WIFI_MODE_STA ? WIFI_MODE_AP : WIFI_MODE_STA;
  wifi_mode_t current_mode;

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

void
wifi__stop (wifi_mode_t mode) {
  wifi_mode_t contrary_mode = mode == WIFI_MODE_STA ? WIFI_MODE_AP : WIFI_MODE_STA;
  wifi_mode_t current_mode;

  ESP_ERROR_CHECK(esp_wifi_get_mode(&current_mode));

  if (current_mode == mode) {
    ESP_ERROR_CHECK(esp_wifi_stop());
  } else if (current_mode == WIFI_MODE_APSTA) {
    ESP_ERROR_CHECK(esp_wifi_set_mode(contrary_mode));
  }
}

void
wifi_scan () {
  ESP_LOGI(TAG, "wifi_scan()");

  // TODO: Test this when it's already on AP/APSTA mode
  // Something with the scan seems to conflict with disconnect and hotspot in the init
  wifi__switch(WIFI_MODE_STA);

  ESP_ERROR_CHECK(esp_wifi_start());
  ESP_ERROR_CHECK(esp_wifi_disconnect()); // TODO

  wifi_scan_config_t scan_config = {
    .scan_type = WIFI_SCAN_TYPE_ACTIVE,
    .scan_time = {
      .active = {
        .min = 0,
        .max = 300
      }
    }
  };

  ESP_ERROR_CHECK(esp_wifi_scan_stop());
  ESP_ERROR_CHECK(esp_wifi_clear_ap_list());

  ap_num = 0;
  memset(ap_records, 0, sizeof(ap_records));

  ESP_ERROR_CHECK(esp_wifi_scan_start(&scan_config, true));
  ESP_ERROR_CHECK(esp_wifi_scan_get_ap_num(&ap_num));

  if (ap_num > WIFI_MAX_SCAN) {
    ap_num = WIFI_MAX_SCAN;
  }

  ESP_ERROR_CHECK(esp_wifi_scan_get_ap_records(&ap_num, ap_records));
}

void
wifi_automatic () {
  wifi_connect_ssid = nvs_read_string("wifi", "connect-ssid");
  wifi_connect_pass = nvs_read_string("wifi", "connect-pass");

  if (wifi_connect_ssid == NULL || wifi_connect_pass == NULL) {
    wifi_hotspot_ssid = nvs_read_string("wifi", "hotspot-ssid");
    wifi_hotspot_pass = nvs_read_string("wifi", "hotspot-pass");

    printf("wifi_hotspot_ssid: %s\n", wifi_hotspot_ssid);
    printf("wifi_hotspot_pass: %s\n", wifi_hotspot_pass);

    // TODO: "STA is connecting, scan are not allowed" probably because esp_wifi saves the credentials also
    wifi_disconnect();

    // TODO: It should scan on each request, but the server crashes. Even on a different task
    wifi_scan();

    wifi_hotspot(wifi_hotspot_ssid, wifi_hotspot_pass);

    wifi__server_start();
  } else {
    printf("%s (%s)\n", wifi_connect_ssid, wifi_connect_pass);

    wifi_hotspot_off();
    wifi_connect(wifi_connect_ssid, wifi_connect_pass);

    // TODO: Force check that connection works, enable hotspot to re-configure
    // Later, keep checking in case it's offline for 30 minutes to re-enable hotspot to re-configure
  }
}

void
wifi_print_scan () {
  for (int i = 0; i < ap_num; i++) {
    ESP_LOGI(TAG, "<option value=\"%s\">%s</option>", ap_records[i].ssid, ap_records[i].ssid);
  }
}

esp_err_t
http__root_handler (httpd_req_t *req) {
  char form[3 * 1024];

  snprintf(form, sizeof(form), "<!DOCTYPE html>"
                               "<html>"
                               "<body>"
                               "<h2>WiFi Automatic</h2>"
                               "<form action=\"/connect\" method=\"post\">"
                               "SSID:<br><select name=\"ssid\">");

  for (int i = 0; i < ap_num; i++) {
    snprintf(form + strlen(form), sizeof(form) - strlen(form), "<option value=\"%s\">%s</option>", ap_records[i].ssid, ap_records[i].ssid);
  }

  snprintf(form + strlen(form), sizeof(form) - strlen(form), "</select><br>"
                                                             "Password:<br><input type=\"text\" name=\"password\"><br><br>"
                                                             "<input type=\"submit\" value=\"Submit\">"
                                                             "</form>"
                                                             "</body>"
                                                             "</html>");

  httpd_resp_send(req, form, HTTPD_RESP_USE_STRLEN);

  return ESP_OK;
}

esp_err_t
http__connect_handler (httpd_req_t *req) {
  char buf[128];
  int remaining = req->content_len;

  while (remaining > 0) {
    int buf_len = remaining < sizeof(buf) ? remaining : sizeof(buf);
    int read = httpd_req_recv(req, buf, buf_len);

    if (read <= 0) {
      if (read == HTTPD_SOCK_ERR_TIMEOUT) {
        continue;
      }

      return ESP_FAIL;
    }

    remaining -= read;

    buf[read] = '\0';

    // buf = ssid=abc&pass=1234

    printf("buf: %s\n", buf);

    char *ssid = strtok(buf, "&");
    char *pass = strtok(NULL, "&");

    if (ssid && pass) {
      char *ssid_value = strchr(ssid, '=') + 1;
      char *pass_value = strchr(pass, '=') + 1;

      char ssid_decoded[33];
      char pass_decoded[64];

      decode_uri(ssid_value, ssid_decoded);
      decode_uri(pass_value, pass_decoded);

      nvs_write_string("wifi", "connect-ssid", ssid_decoded);
      nvs_write_string("wifi", "connect-pass", pass_decoded);

      const char *response = "WiFi connection saved";
      httpd_resp_send(req, response, HTTPD_RESP_USE_STRLEN);

      esp_restart();
    }
  }

  return ESP_OK;
}

esp_err_t
http__captive_handler (httpd_req_t *req) {
  httpd_resp_set_status(req, "302 Found");
  httpd_resp_set_hdr(req, "Location", "/");
  httpd_resp_send(req, NULL, 0);

  return ESP_OK;
}

void
wifi__server_start () {
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
    .user_ctx = NULL
  };

  httpd_uri_t connect_uri = {
    .uri = "/connect",
    .method = HTTP_POST,
    .handler = http__connect_handler,
    .user_ctx = NULL
  };

  httpd_uri_t captive_uri = {
    .uri = "/*",
    .method = HTTP_GET,
    .handler = http__captive_handler,
    .user_ctx = NULL
  };

  if (httpd_start(&server, &config) == ESP_OK) {
    httpd_register_uri_handler(server, &root_uri);
    httpd_register_uri_handler(server, &connect_uri);
    httpd_register_uri_handler(server, &captive_uri);
  }
}

void
wifi__server_stop () {
  if (server) {
    httpd_stop(server);
    server = NULL;
  }
}

static void
event_handler (void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data) {
  // Scan
  /* if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_SCAN_DONE) {
    ESP_ERROR_CHECK(esp_wifi_scan_get_ap_num(&ap_num));

    if (ap_num > WIFI_MAX_SCAN) {
      ap_num = WIFI_MAX_SCAN;
    }

    ESP_ERROR_CHECK(esp_wifi_scan_get_ap_records(&ap_num, ap_records));

    xSemaphoreGive(scan_done);

    return;
  } */

  // Access Point
  if (event_id == WIFI_EVENT_AP_STACONNECTED) {
    wifi_event_ap_staconnected_t *event = (wifi_event_ap_staconnected_t *) event_data;

    ESP_LOGI(TAG, "station " MACSTR " join, AID=%d", MAC2STR(event->mac), event->aid);

    return;
  } else if (event_id == WIFI_EVENT_AP_STADISCONNECTED) {
    wifi_event_ap_stadisconnected_t *event = (wifi_event_ap_stadisconnected_t *) event_data;

    ESP_LOGI(TAG, "station " MACSTR " leave, AID=%d", MAC2STR(event->mac), event->aid);

    return;
  }

  // Station
  if (event_base == WIFI_EVENT) {
    if (event_id == WIFI_EVENT_STA_START) {
      esp_wifi_connect();

      return;
    }

    if (event_id == WIFI_EVENT_STA_DISCONNECTED) {
      wifi_event_sta_disconnected_t *sta_disconnect_evt = (wifi_event_sta_disconnected_t *) event_data;

      ESP_LOGI(TAG, "wifi disconnect reason: %d", sta_disconnect_evt->reason);

      xEventGroupClearBits(wifi_events, WIFI_CONNECTED_BIT);

      if (wifi_retries < 5) {
        esp_wifi_connect();

        wifi_retries++;

        ESP_LOGI(TAG, "retry to connect to the AP");
      } else {
        xEventGroupSetBits(wifi_events, WIFI_FAIL_BIT);
      }

      ESP_LOGI(TAG, "connect to the AP fail");

      return;
    }

    return;
  }

  if (event_base == IP_EVENT) {
    ip_event_got_ip_t *event = (ip_event_got_ip_t *) event_data;

    ESP_LOGI(TAG, "got ip:" IPSTR, IP2STR(&event->ip_info.ip));

    wifi_retries = 0;

    xEventGroupSetBits(wifi_events, WIFI_CONNECTED_BIT);

    return;
  }
}
