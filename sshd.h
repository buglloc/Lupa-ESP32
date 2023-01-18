#ifndef LUPA_SSHD_H_
#define LUPA_SSHD_H_

#include "config.h"
#include "libssh_esp32.h"
#include "libssh_esp32_config.h"
#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/misc.h>
#include <ArduinoLog.h>

ssh_list *g_root_keys = NULL;
ssh_session g_ssh_session = NULL;
ssh_bind g_ssh_bind = NULL;
ssh_key g_host_key = NULL;


struct lupa_session {
  ssh_channel chan;
  char *username;
  char *key_fingerprint;
};

int load_root_key(const char *in) {
  ssh_key publickey = NULL;
  enum ssh_keytypes_e typekey = SSH_KEYTYPE_UNKNOWN;
  char *p;
  char *authorized_key = NULL;
  char *save_tok = NULL;
  int rc;

  authorized_key = strdup(in);
  if (authorized_key == NULL) {
    Log.errorln("unable to allocate memory for authorized key");
    return -1;
  }

  p = strtok_r(authorized_key, " ", &save_tok);
  if (p == NULL) {
    Log.errorln("invalid root key '%s': unexpected format", authorized_key);
    rc = -1;
    goto cleanup;
  }

  typekey = ssh_key_type_from_name(p);
  if (typekey == SSH_KEYTYPE_UNKNOWN) {
    Log.errorln("invalid root key '%s': unsupported key type", authorized_key);
    rc = -1;
    goto cleanup;
  }

  p = strtok_r(NULL, " ", &save_tok);
  if (p == NULL) {
    Log.errorln("invalid root key '%s': unexpected format", authorized_key);
    rc = -1;
    goto cleanup;
  }

  rc = ssh_pki_import_pubkey_base64(p, typekey, &publickey);
  if (rc != SSH_OK) {
    Log.errorln("invalid root key '%s': failed to decode b64", authorized_key);
    rc = -1;
    goto cleanup;
  }

  ssh_list_append(g_root_keys, publickey);
  rc = 0;

cleanup:
  free(authorized_key);
  return rc;
}

int sshd_setup() {
  int i, rc = 0;

  libssh_begin();

  g_root_keys = ssh_list_new();
  if (g_root_keys == NULL) {
    Log.fatalln("not enough space");
    return -1;
  }

  Log.verboseln("Load root keys");
  for (char const **key = SSHD_ROOT_AUTH_KEYS; *key; ++key) {
    rc = load_root_key(*key);
    if (rc) {
      return rc;
    }
    ++i;
  }

  Log.verboseln("Loaded %d root keys", ssh_list_count(g_root_keys));

  rc = ssh_pki_import_privkey_base64(SSHD_HOSTKEY, NULL, NULL, NULL, &g_host_key);
  if (rc != SSH_OK) {
    Log.fatalln("unable to load host key: %d", rc);
    return rc;
  }
  Log.verboseln("Host key loaded");

  return rc;
}

int accept_user_key(ssh_message message) {
  switch (ssh_message_auth_publickey_state(message)) {
    case SSH_PUBLICKEY_STATE_NONE:
      ssh_message_auth_reply_pk_ok_simple(message);
      return 1;
    case SSH_PUBLICKEY_STATE_VALID:
        ssh_message_auth_reply_success(message, 0);
      return 0;
    default:
      return -1;
  }
}

int print_key_hash(ssh_key key, char **out) {
  unsigned char *hash = NULL;
  size_t hlen = 0;
  int rc;

  rc = ssh_get_publickey_hash(key, SSH_PUBLICKEY_HASH_SHA256, &hash, &hlen);
  if (rc != SSH_OK) {
      return -1;
  }

  *out = ssh_get_fingerprint_hash(SSH_PUBLICKEY_HASH_SHA256, hash, hlen);
  ssh_clean_pubkey_hash(&hash);
  return 0;
}

int sshd_loop_start(lupa_session *out_chan) {
  ssh_message message = NULL;
  int again = 1;
  int patience = 0;
  const int impatience = 10;
  struct ssh_iterator *it = NULL;
  int i, rc;

  out_chan->chan = NULL;
  out_chan->username = NULL;
  out_chan->key_fingerprint = NULL;

  Log.verboseln("Starts sshd");
  g_ssh_bind = ssh_bind_new();
  if (g_ssh_bind == NULL) {
    goto out;
  }

  rc = ssh_bind_options_set(g_ssh_bind, SSH_BIND_OPTIONS_IMPORT_KEY, ssh_key_dup(g_host_key));
  if (rc != SSH_OK) {
    goto bind_failed;
  }

  rc = ssh_bind_listen(g_ssh_bind);
  if (rc != SSH_OK) {
    goto bind_failed;
  }

  Log.verboseln("Starts new session");
  g_ssh_session = ssh_new();
  if (g_ssh_session == NULL) {
    goto bind_failed;
  }

  Log.verboseln("Wait for connection...");
  rc = ssh_bind_accept(g_ssh_bind, g_ssh_session);
  if (rc != SSH_OK) {
    goto session_failed;
  }

  Log.verboseln("Starts key exchange...");
  rc = ssh_handle_key_exchange(g_ssh_session);
  if (rc != SSH_OK) {
    goto session_failed;
  }

  Log.verboseln("Starts authentification...");
  ssh_set_auth_methods(g_ssh_session, SSH_AUTH_METHOD_PUBLICKEY);
  again = 1;
  for (patience = 0; patience < impatience && again; ++patience) {
    message = ssh_message_get(g_ssh_session);
    if (!message) {
      goto session_failed;
    }

    Log.verboseln("[%d] trying %d:%d...", patience, ssh_message_type(message), ssh_message_subtype(message));
    // only pubkey auth support
    if (ssh_message_type(message) != SSH_REQUEST_AUTH) {
      ssh_message_reply_default(message);
      ssh_message_free(message);
      continue;
    }

    rc = 1;
    if (ssh_message_subtype(message) == SSH_AUTH_METHOD_PUBLICKEY) {
      if (strcmp(ssh_message_auth_user(message), SSHD_ROOT_LOGIN) == 0) {
        ssh_key key_entry = NULL;
        for (it = ssh_list_get_iterator(g_root_keys); it != NULL ; it=it->next) {
          key_entry = ssh_iterator_value(ssh_key, it);
          if (key_entry == NULL) {
            continue;
          }

          if (ssh_key_cmp(ssh_message_auth_pubkey(message), key_entry, SSH_KEY_CMP_PUBLIC)) {
            continue;
          }

          rc = 0;
          break;
        }
      } else {
        rc = 0;
      }

      if (!rc) {
        switch (accept_user_key(message)) {
          case 0:
            again = 0;

            out_chan->username = strdup(ssh_message_auth_user(message));
            if (out_chan->username == NULL) {
              Log.errorln("unable to allocate memory for username");
              rc = -1;
              break;
            }

            rc = print_key_hash(ssh_message_auth_pubkey(message), &out_chan->key_fingerprint);
            if (rc != SSH_OK) {
              Log.errorln("failed to get key fingerprint: %d", rc);
              rc = -1;
              break;
            }

            rc = 0;
            Log.infoln("user %s was authenticated", out_chan->username);
            break;
          case 1:
            Log.infoln("pubkey accepted");
            rc = 0;
            break;
          default:
            rc = -1;
        }
      }
    }

    if (rc) {
      ssh_message_auth_set_methods(message, SSH_AUTH_METHOD_PUBLICKEY);
      ssh_message_reply_default(message);
    }

    ssh_message_free(message);
  }

  if (patience == impatience) {
    Log.warningln("Too much failure, aborting");
    goto session_failed;
  }

  patience = 0;
  // wait session request
  Log.verboseln("Wait session 'lupa@buglloc.com' channel...");
  for (patience = 0; patience < impatience && out_chan->chan == NULL; ++patience) {
    message = ssh_message_get(g_ssh_session);
    if (!message) {
      goto session_failed;
    }

    Log.verboseln("requested channel %d:%d", ssh_message_type(message), ssh_message_subtype(message));

    if (ssh_message_type(message) == SSH_REQUEST_CHANNEL_OPEN && ssh_message_subtype(message) == SSH_CHANNEL_LUPA) {
      out_chan->chan = ssh_message_channel_request_open_reply_accept(message);
    } else {
      Log.infoln("reject message %d:%d...");
      ssh_message_reply_default(message);
    }
    ssh_message_free(message);
  }

  if (patience == impatience) {
    Log.warningln("Too much failure, aborting");
    goto channel_failed;
  }

  ssh_set_blocking(g_ssh_session, 0);

  Log.infoln("New connection, username=%s key=%s", out_chan->username, out_chan->key_fingerprint);
  return 0;

channel_failed:
  ssh_channel_free(out_chan->chan);

session_failed:
  SAFE_FREE(out_chan->username);
  SAFE_FREE(out_chan->key_fingerprint);
  if (ssh_get_error_code(g_ssh_session) != SSH_NO_ERROR) {
    Log.errorln("unable to create session: %s", ssh_get_error(g_ssh_session));
  }

  ssh_disconnect(g_ssh_session);
  ssh_free(g_ssh_session);

bind_failed:
  if (ssh_get_error_code(g_ssh_bind) != SSH_NO_ERROR) {
    Log.errorln("unable to bind: %s", ssh_get_error(g_ssh_bind));
  }

  ssh_bind_free(g_ssh_bind);

out:
  return -1;
}

void sshd_loop_end(lupa_session *session) {
  Log.infoln("End connection");

  if (session->chan != NULL) {
    ssh_channel_free(session->chan);
    SAFE_FREE(session->username);
    SAFE_FREE(session->key_fingerprint);
  }

  if (g_ssh_session != NULL) {
    ssh_disconnect(g_ssh_session);
    ssh_free(g_ssh_session);
    g_ssh_session = NULL;
  }

  if (g_ssh_bind != NULL) {
    ssh_bind_free(g_ssh_bind);
    g_ssh_bind = NULL;
  }
}

uint32_t rpc_io(ssh_channel chan, void *buf, uint32_t n, int do_read) {
  char *b = (char*)buf;
  uint32_t pos = 0;
  ssize_t res;

  while (n > pos) {
    if (do_read) {
      res = ssh_channel_poll_timeout(chan, POLL_TIMEOUT_MS, 0);
      if (res < 0) {
        // err or timeout
        return 0;
      }

      if (res == 0) {
        continue;
      }

      res = ssh_channel_read_timeout(chan, b + pos, n - pos, 0, READ_TIMEOUT_MS);
    } else {
      res = ssh_channel_write(chan, b + pos, n - pos);
    }

    if (res == SSH_AGAIN)
      continue;
    if (res == SSH_ERROR)
      return 0;
    pos += (uint32_t)res;
  }
  return pos;
}

#endif
