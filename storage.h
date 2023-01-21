#ifndef LUPA_STORAGE_H_
#define LUPA_STORAGE_H_

#include "nvs_flash.h"
#include "nvs.h"
#include "esp_system.h"
#include <libssh/buffer.h>
#include <libssh/libssh.h>
#include <ArduinoLog.h>
#include <stdint.h>
#include <esp_system.h>

#define STORAGE_KEY_LEN 15

nvs_handle_t g_storage;

void gen_storage_key(char *out) {
  uint8_t raw[7];
  esp_fill_random(raw, 7);
	sprintf(out, "%x%x%x%x%x%x%x", raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6]);
}

int storage_setup() {
  esp_err_t err = nvs_flash_init();
  if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    Log.warningln("NVS partition was truncated and needs to be erased");
    if (nvs_flash_erase() != ESP_OK) {
      Log.warningln("Unable to erase NVS partition: %s", esp_err_to_name(err));
      return -1;
    }
    err = nvs_flash_init();
  }

  if (err != ESP_OK) {
    Log.warningln("Unable to initialize NVS partition: %s", esp_err_to_name(err));
    return -1;
  }

  err = nvs_open("storage", NVS_READWRITE, &g_storage);
  if (err != ESP_OK) {
    Log.warningln("Unable to open NVS storage: %s", esp_err_to_name(err));
    return -1;
  }

  return 0;
}

int storage_has_key(const char *key) {
  esp_err_t err;
  size_t len;

  err = nvs_get_blob(g_storage, key, NULL, &len);
  return (err == ESP_OK ? 1 : 0);
}

int storage_get(const char *key, ssh_buffer buf) {
  esp_err_t err;
  size_t len;
  void *out;

  err = nvs_get_blob(g_storage, key, NULL, &len);
  if (err != ESP_OK) {
    Log.warningln("unable to get key %s len: %s", key, esp_err_to_name(err));
    return -1;
  }

  out = ssh_buffer_allocate(buf, len);
  if (out == NULL) {
    Log.errorln("not enought memory to create out blob");
    return -1;
  }

  err = nvs_get_blob(g_storage, key, out, &len);
  if (err != ESP_OK) {
    Log.warningln("unable to read key %s: %s", key, esp_err_to_name(err));
    return -1;
  }

  return 0;
}

int storage_put(const char *key, ssh_buffer buf) {
  esp_err_t err = nvs_set_blob(g_storage, key, ssh_buffer_get(buf), ssh_buffer_get_len(buf));
  if (err != ESP_OK) {
    Log.warningln("unable to stoge key %s: %s", key, esp_err_to_name(err));
    return -1;
  }

  return 0;
}

#endif
