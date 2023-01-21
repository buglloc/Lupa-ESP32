#ifndef LUPA_HANDLERS_H_
#define LUPA_HANDLERS_H_

#include "config.h"
#include "priv.h"
#include "sshd.h"
#include "storage.h"
#include <libssh/buffer.h>
#include <libssh/libssh.h>
#include <ArduinoLog.h>

#define LUPA_FAILURE_MSG_TYPE 100
#define LUPA_SUCCESS_MSG_TYPE 101
#define LUPA_PUT_REQ_MSG_TYPE 110
#define LUPA_PUT_RSP_MSG_TYPE 111
#define LUPA_GET_REQ_MSG_TYPE 112
#define LUPA_GET_RSP_MSG_TYPE 113


void init_buf_error(ssh_buffer buf, const char *msg) {
  int rc;

  rc = ssh_buffer_reinit(buf);
  if (rc != SSH_OK) {
    return;
  }

  rc = ssh_buffer_pack(buf, "bs", LUPA_FAILURE_MSG_TYPE, msg);
  if (rc != SSH_OK){
    return;
  }
}

int handle_get_request(lupa_session *session, ssh_buffer buf) {
  int rc;
  uint8_t msg_type = 0;
  char *key_id = NULL;
  char *storage_key = NULL;
  ssh_string out_blob = NULL;

  rc = ssh_buffer_unpack(buf, "bs", &msg_type, &key_id);
  if (rc != SSH_OK){
    Log.warningln("unable to unpack request: %d", rc);
    goto err;
  }

  if (msg_type != LUPA_GET_REQ_MSG_TYPE) {
    Log.warningln("invalid request msg type: %d (expected) != %d (actual)", LUPA_GET_REQ_MSG_TYPE, msg_type);
    rc = -1;
    goto err;
  }

  rc = ssh_buffer_reinit(buf);
  if (rc != SSH_OK) {
    Log.warningln("not enough space to reinit buffer");
    goto err;
  }


  rc = storage_get(key_id, buf);
  if (rc != SSH_OK) {
    Log.warningln("unable to get requested key: %d", rc);
    goto err;
  }

  rc = ssh_buffer_unpack(buf, "sS", &storage_key, &out_blob);
  if (rc != SSH_OK){
    Log.warningln("unable to unpack data: %d", rc);
    goto err;
  }

  if (strcmp(storage_key, session->key_fingerprint) != 0) {
    Log.warningln("invalid client: %s (expected) != %s (actual)", storage_key, session->key_fingerprint);
    goto err;
  }

  rc = ssh_buffer_reinit(buf);
  if (rc != SSH_OK) {
    Log.warningln("not enough space to reinit buffer");
    goto err;
  }

  rc = ssh_buffer_pack(buf, "bS", LUPA_GET_RSP_MSG_TYPE, out_blob);
  if (rc != SSH_OK){
    Log.warningln("unable to pack response: %d", rc);
    goto err;
  }

  Log.noticeln("returned data for key '%s' from '%s'", key_id, session->key_fingerprint);
  goto end;

err:
  init_buf_error(buf, "shit happens");

end:
  SAFE_FREE(key_id);
  SAFE_FREE(storage_key);
  ssh_string_free(out_blob);
  return rc;
}

int handle_put_request(lupa_session *session, ssh_buffer buf) {
  int rc;
  uint8_t msg_type = 0;
  char *storage_key = NULL;
  char key_id[STORAGE_KEY_LEN];
  ssh_string blob = NULL;

  rc = ssh_buffer_unpack(buf, "bS", &msg_type, &blob);
  if (rc != SSH_OK){
    Log.warningln("unable to unpack request: %d", rc);
    goto err;
  }

  if (msg_type != LUPA_PUT_REQ_MSG_TYPE) {
    Log.warningln("invalid request msg type: %d (expected) != %d (actual)", LUPA_PUT_REQ_MSG_TYPE, msg_type);
    rc = -1;
    goto err;
  }

  do {
    gen_storage_key(&key_id[0]);
  } while (storage_has_key(&key_id[0]));

  rc = ssh_buffer_reinit(buf);
  if (rc != SSH_OK) {
    Log.warningln("not enough space to reinit buffer");
    goto err;
  }

  rc = ssh_buffer_pack(buf, "sS", session->key_fingerprint, blob);
  if (rc != SSH_OK){
    Log.warningln("unable to pack data: %d", rc);
    goto end;
  }

  rc = storage_put(&key_id[0], buf);
  if (rc != SSH_OK) {
    Log.warningln("unable to store data: %d", rc);
    goto err;
  }

  rc = ssh_buffer_reinit(buf);
  if (rc != SSH_OK) {
    Log.warningln("not enough space to reinit buffer");
    goto err;
  }

  rc = ssh_buffer_pack(buf, "bs", LUPA_PUT_RSP_MSG_TYPE, &key_id[0]);
  if (rc != SSH_OK){
    Log.warningln("unable to pack response: %d", rc);
    goto end;
  }

  Log.noticeln("saved data with key '%s' from '%s'", key_id, session->key_fingerprint);
  goto end;

err:
  init_buf_error(buf, "shit happens");

end:
  ssh_string_free(blob);
  return rc;
}

int handle_request(lupa_session *session, ssh_buffer buf) {
  char *type_c = NULL;
  int rc;

  rc = ssh_buffer_unpack(buf, "s", &type_c);
  if (rc != SSH_OK){
    Log.warningln("unable to read request type: %d", rc);
    rc = -1;
    goto end;
  }

  Log.noticeln("incomming request: %s", type_c);

  if (strcmp(type_c, "get") == 0) {
    rc = handle_get_request(session, buf);
    if (rc) {
      Log.warningln("get request failed: %d", rc);
    }

    rc = 0;
    goto end;
  }

  if (strcmp(type_c, "put") == 0) {
    rc = handle_put_request(session, buf);
    if (rc) {
      Log.warningln("put request failed: %d", rc);
    }

    rc = 0;
    goto end;
  }

end:
  if (rc == 0) {
    Log.noticeln("request processed");
  }

  SAFE_FREE(type_c);
  return rc;
}

#endif
