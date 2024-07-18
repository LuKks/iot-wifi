#ifndef IOT_WIFI_H
#define IOT_WIFI_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#include <esp_wifi.h>

#define WIFI_MAX_SCAN 20

typedef struct wifi_scan_result wifi_scan_result_t;

struct wifi_scan_result {
  uint16_t ap_num;
  wifi_ap_record_t ap_records[WIFI_MAX_SCAN];
};

void
wifi_init ();

void
wifi_destroy ();

void
wifi_hotspot (const char *ssid, const char *password);

void
wifi_hotspot_off ();

void
wifi_connect (const char *ssid, const char *password);

void
wifi_disconnect ();

void
wifi_automatic ();

void
wifi_scan (wifi_scan_result_t *result);

#ifdef __cplusplus
}
#endif

#endif // IOT_WIFI_H
