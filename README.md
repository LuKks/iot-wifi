# iot-wifi

WiFi manager in C for IoT devices

## Usage

```c
#include <iot_wifi.h>

void setup () {
  wifi_connect("<ssid>", "<pass>");
  // ...
}

void loop () {}
```

## API

See [`include/iot_wifi.h`](include/iot_wifi.h) for the public API.

## Notes

For updating the UI header:

`xxd -i wifi.html > wifi_html.h`

## License

MIT
