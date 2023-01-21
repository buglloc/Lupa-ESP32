#include "config.h"
#include "priv.h"
#include "sshd.h"
#include "encoding.h"
#include "handlers.h"
#include "storage.h"
#include "WiFi.h"
#include <libssh/buffer.h>
#include <ArduinoLog.h>

ssh_buffer g_buf = NULL;

void setup() {
  int rc = 0;

  Serial.begin(115200);
  Log.begin(LOG_LEVEL, &Serial);
  Log.verboseln("Setup starts");

  pinMode(LED_BUILTIN, OUTPUT);
  digitalWrite(LED_BUILTIN, HIGH);

  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  WiFi.setHostname(STA_HOSTNAME);
  Log.noticeln("Connecting to WiFi...");

  WiFi.begin(STA_SSID, STA_PSK);
  while (WiFi.status() != WL_CONNECTED) {
    delay(1000);
    Log.verboseln("Still connecting...");
  }

  Serial.println("----------");
  Serial.print("Connected to WiFi ");
  Serial.print(WIFI_STA);
  Serial.print(" with IP ");
  Serial.print(WiFi.localIP());
  Serial.println("");
  Serial.println("----------");

  g_buf = ssh_buffer_new();
  if (g_buf == NULL) {
    Log.warningln("not enough space to allocate buffer");
    return;
  }

  Log.verboseln("Setup storage");
  rc = storage_setup();
  if (rc){
    Log.fatal("Storage setup failed with error %d", rc);
    return;
  }

  Log.verboseln("Setup SSHD service");
  rc = sshd_setup();
  if (rc) {
    Log.fatal("SSHD setup failed with error %d", rc);
    return;
  }
}

int client_talk(lupa_session *session, ssh_buffer buf) {
  uint32_t msg_len = 0;
  uint8_t tmpbuf[4];
  void *payload = (void*)tmpbuf;


  if (rpc_io(session->chan, payload, 4, 1) != 4) {
    Log.warningln("unable to read request: want 4 bytes, got: %d", msg_len);
    return -1;
  }

  msg_len = PULL_BE_U32(payload, 0);
  if (msg_len >= BUFF_SIZE) {
    Log.warningln("request too large: %d", msg_len);
    return -1;
  }

  payload = ssh_buffer_allocate(buf, msg_len);
  if (payload == NULL) {
    Log.warningln("not enough space");
    return -1;
  }

  if (rpc_io(session->chan, payload, msg_len, 1) != msg_len) {
    Log.warningln("invalid request: msg size mismatch");
    return -1;
  }

  if (handle_request(session, buf) != 0) {
    Log.warningln("unable to handle request");
    return -1;
  }

  payload = (void*)tmpbuf;
  msg_len = ssh_buffer_get_len(buf);
  PUSH_BE_U32(payload, 0, msg_len);
  if (rpc_io(session->chan, payload, 4, 0) == 4) {
    if (rpc_io(session->chan, ssh_buffer_get(buf), msg_len, 0) != msg_len) {
      Log.warningln("unable to send response of len %d", msg_len);
      return -1;
    }
  } else {
    Log.warningln("unable to send response len");
    return -1;
  }

  return 0;
}

void loop() {
  // Serial.println();
  // Serial.println();
  // Serial.println("MEM");
  // Serial.println(ESP.getFreeHeap());

  lupa_session session;

  if (sshd_loop_start(&session)) {
    delay(50);
    return;
  }

  while (ssh_channel_is_open(session.chan) && !ssh_channel_is_eof(session.chan)) {
    if (ssh_buffer_reinit(g_buf) != SSH_OK) {
      Log.warningln("not enough space to reinit buffer");
      break;
    }

    if (client_talk(&session, g_buf)) {
      Log.warningln("failed to talk with client, terminate session...");
      break;
    }
  }

cleanup:
  sshd_loop_end(&session);
}
