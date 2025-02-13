#include <errno.h>
#include <libssh/libssh.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int verify_knownhost (ssh_session session);

int show_remote_prcesses (ssh_session session);

int
main ()
{
  const char *host = "localhost";
  int port = 22;
  int verbosity = SSH_LOG_PROTOCOL;
  int ec = EXIT_FAILURE;
  ssh_session session = ssh_new ();
  if (session == NULL)
    exit(ec);

  ssh_options_set (session, SSH_OPTIONS_HOST, host);
  ssh_options_set (session, SSH_OPTIONS_PORT, &port);
  ssh_options_set (session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);

  int rc;

  rc = ssh_connect (session);
  if (rc != SSH_OK)
    {
      fprintf (stderr, "Error connecting to %s: %s\n", host,
               ssh_get_error (session));
      exit (ec);
    }

  if (verify_knownhost (session) < 0)
    {
      ssh_disconnect (session);
      ssh_free (session);
      exit (ec);
    }

  char *password;
  password = getpass ("Password: ");
  rc = ssh_userauth_password (session, NULL, password);
  if (rc != SSH_AUTH_SUCCESS)
    {
      fprintf (stderr, "Error authenticating with password: %s\n",
               ssh_get_error (session));
      ssh_disconnect (session);
      ssh_free (session);
      exit (ec);
    }
  
  show_remote_prcesses(session);

  ssh_disconnect (session);
  ssh_free (session);
  return 0;
}

int
verify_knownhost (ssh_session session)
{
  enum ssh_known_hosts_e state;
  unsigned char *hash = NULL;
  ssh_key srv_pubkey = NULL;
  size_t hlen;
  char buf[10];
  char *hexa;
  char *p;
  int cmp;
  int rc;

  rc = ssh_get_server_publickey (session, &srv_pubkey);
  if (rc < 0)
    {
      return -1;
    }

  rc = ssh_get_publickey_hash (srv_pubkey, SSH_PUBLICKEY_HASH_SHA1, &hash,
                               &hlen);
  ssh_key_free (srv_pubkey);
  if (rc < 0)
    {
      return -1;
    }
  state = ssh_session_is_known_server (session);
  switch (state)
    {
    case SSH_KNOWN_HOSTS_OK:
      /* OK */
      break;
    case SSH_KNOWN_HOSTS_CHANGED:
      fprintf (stderr, "Host key for server changed: it is now:\n");
      ssh_print_hash (SSH_PUBLICKEY_HASH_SHA1, hash, hlen);
      fprintf (stderr, "For security reasons, connection will be stopped\n");
      ssh_clean_pubkey_hash (&hash);
      return -1;
    case SSH_KNOWN_HOSTS_OTHER:
      fprintf (stderr,
               "The host key for this server was not found but an other"
               "type of key exists.\n");
      fprintf (stderr,
               "An attacker might change the default server key to"
               "confuse your client into thinking the key does not exist\n");
      ssh_clean_pubkey_hash (&hash);

      return -1;
    case SSH_KNOWN_HOSTS_NOT_FOUND:
      fprintf (stderr, "Could not find known host file.\n");
      fprintf (stderr, "If you accept the host key here, the file will be"
                       "automatically creted.\n");
      /* FALL THROUGH to SSH_SERVER_NOT_KNOWN behavior */
    case SSH_KNOWN_HOSTS_UNKNOWN:
      hexa = ssh_get_hexa (hash, hlen);
      fprintf (stderr, "The server is unknown. Do you trust the host key?\n");
      fprintf (stderr, "Public key hash: %s\n", hexa);
      ssh_string_free_char (hexa);
      ssh_clean_pubkey_hash (&hash);
      p = fgets (buf, sizeof (buf), stdin);
      if (p == NULL)
        {
          return -1;
        }

      cmp = strncasecmp (buf, "yes", 3);
      if (cmp != 0)
        {
          return -1;
        }

      rc = ssh_session_update_known_hosts (session);
      if (rc < 0)
        {
          fprintf (stderr, "Error %s\n", strerror (errno));
          return -1;
        }

      break;
    case SSH_KNOWN_HOSTS_ERROR:
      fprintf (stderr, "Error %s", ssh_get_error (session));
      ssh_clean_pubkey_hash (&hash);
      return -1;
      break;
    }
  ssh_clean_pubkey_hash (&hash);
  return 0;
}

int
show_remote_prcesses (ssh_session session)
{
  ssh_channel channel;
  int rc = SSH_ERROR;
  char buffer[256];
  int nbytes;

  channel = ssh_channel_new (session);
  if (channel == NULL)
    return rc;

  rc = ssh_channel_open_session (channel);
  if (rc != SSH_OK)
    {
      ssh_channel_free (channel);
      return rc;
    }

  rc = ssh_channel_request_exec (channel, "ps aux");
  if (rc != SSH_OK)
    goto out;

  nbytes = ssh_channel_read (channel, buffer, sizeof (buffer), 0);
  while (nbytes > 0)
    {
      if (write(1, buffer, nbytes) != (unsigned int)nbytes)
        goto out;
      nbytes = ssh_channel_read (channel, buffer, sizeof (buffer), 0);
    }
  if (nbytes < 0)
    goto out;

  ssh_channel_send_eof (channel);

out:
  ssh_channel_close (channel);
  ssh_channel_free (channel);
  return rc;
}
