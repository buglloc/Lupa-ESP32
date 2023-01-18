#ifndef LUPA_HANDLERS_H_
#define LUPA_HANDLERS_H_

#include "config.h"
#include "priv.h"
#include "sshd.h"
#include <libssh/buffer.h>
#include <libssh/libssh.h>

#define PUPA_FAILURE_MSG_TYPE 100
#define PUPA_SUCCESS_MSG_TYPE 101
#define PUPA_PUT_REQ_MSG_TYPE 110
#define PUPA_PUT_RSP_MSG_TYPE 111
#define PUPA_GET_REQ_MSG_TYPE 112
#define PUPA_GET_RSP_MSG_TYPE 113



int handle_get_request(lupa_session *session, ssh_buffer buf) {
  int rc;
  uint8_t msg_type = 0;
  char *key_id = NULL;

  rc = ssh_buffer_unpack(buf, "bs", &msg_type, &key_id);
  if (rc != SSH_OK){
    Log.warningln("unable to unpack request: %d", rc);
    goto end;
  }

  if (msg_type != PUPA_GET_REQ_MSG_TYPE) {
    Log.warningln("invalid request msg type: %d (expected) != %d (actual)", PUPA_GET_REQ_MSG_TYPE, msg_type);
    rc = -1;
    goto end;
  }

  rc = ssh_buffer_reinit(buf);
  if (rc != SSH_OK) {
    Log.warningln("not enough space to reinit buffer");
    goto end;
  }

  rc = ssh_buffer_pack(buf, "bs", PUPA_GET_RSP_MSG_TYPE, session->key_fingerprint);
  if (rc != SSH_OK){
    Log.warningln("unable to pack response: %d", rc);
    goto end;
  }

end:
  SAFE_FREE(key_id);
  return rc;
}

int handle_put_request(lupa_session *session, ssh_buffer buf) {
  int rc;
  uint8_t msg_type = 0;
  char *data = NULL;

  rc = ssh_buffer_unpack(buf, "bs", &msg_type, &data);
  if (rc != SSH_OK){
    Log.warningln("unable to unpack request: %d", rc);
    goto end;
  }

  if (msg_type != PUPA_PUT_REQ_MSG_TYPE) {
    Log.warningln("invalid request msg type: %d (expected) != %d (actual)", PUPA_PUT_REQ_MSG_TYPE, msg_type);
    rc = -1;
    goto end;
  }

  rc = ssh_buffer_reinit(buf);
  if (rc != SSH_OK) {
    Log.warningln("not enough space to reinit buffer");
    goto end;
  }

  rc = ssh_buffer_pack(buf, "bs", PUPA_PUT_RSP_MSG_TYPE, session->key_fingerprint);
  if (rc != SSH_OK){
    Log.warningln("unable to pack response: %d", rc);
    goto end;
  }

end:
  SAFE_FREE(data);
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

    goto end;
  }

  if (strcmp(type_c, "put") == 0) {
    rc = handle_put_request(session, buf);
    if (rc) {
      Log.warningln("put request failed: %d", rc);
    }

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
