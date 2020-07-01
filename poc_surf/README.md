# Flexible PAM conversation PoC

## Installation

Required components:
* [iRODS auth plugin: interactive PAM stack](https://github.com/stefan-wolfsheimer/irods_auth_plugin_pam_interactive)
* [Auxillary PAM stack](https://github.com/stefan-wolfsheimer/pam_handshake)
* [Patched iinit](https://github.com/stefan-wolfsheimer/irods_client_icommands)

Installation instructions:

see https://github.com/stefan-wolfsheimer/irods_auth_plugin_pam_interactive/blob/master/README.md


## Configuration
### Enable and start aux. pam service
```bash
sudo systemctl enable pam-handshake.service
sudo systemctl start pam-handshake.service
```

### Enable ssl

SSL configuration with self-signed certificates:
```bash
sudo mkdir -p /etc/irods/ssl
sudo chown irods /etc/irods/ssl
sudo -u irods openssl genrsa -out /etc/irods/ssl/server.key
sudo -u irods chmod 600 /etc/irods/ssl/server.key
HOSTNAME=$( hostname )
sudo -u irods openssl req -new -x509 -key /etc/irods/ssl/server.key -out /etc/irods/ssl/server.crt -days 10000 -subj "/C=NL/ST=Amsterdam/L=Noord Holland/O=Surfsara/OU=DMS/CN=$HOSTNAME"
sudo su irods
cat /etc/irods/ssl/server.crt > /etc/irods/ssl/chain.pem
openssl dhparam -2 -out /etc/irods/ssl/dhparams.pem 2048
```

```bash
emacs /var/lib/irods/.irods/irods_environment.json
```

```json
...
    "irods_ssl_certificate_chain_file": "/etc/irods/ssl/chain.pem",
    "irods_ssl_ca_certificate_file": "/etc/pki/tls/certs/irods/server.crt",
    "irods_ssl_certificate_key_file": "/etc/irods/ssl/server.key",
    "irods_ssl_dh_params_file": "/etc/irods/ssl/dhparams.pem",
    "irods_ssl_verify_server": "cert",
    "irods_client_server_policy": "CS_NEG_REQUIRE"
...
```

### PAM stack
as root:

```bash
cat > /etc/pam.d/irods <<EOF
auth required pam_python.so /etc/pam.d/irods.py
EOF
```

/etc/pam.d/irods.py:
```python
def pam_sm_authenticate(pamh, flags, argv):
    name_msg = pamh.conversation(pamh.Message(pamh.PAM_PROMPT_ECHO_ON, "What is your name?"))
    pamh.conversation(pamh.Message(pamh.PAM_TEXT_INFO,
                                   "Hello {0}, wellcome to the PAM stack.".format(name_msg.resp)))
    pwd_msg = pamh.conversation(pamh.Message(pamh.PAM_PROMPT_ECHO_OFF,
                                "password:"))
    if pwd_msg.resp != "pw":
        return pamh.PAM_AUTH_ERR
    second_msg = pamh.conversation(pamh.Message(pamh.PAM_PROMPT_ECHO_ON,
                                                "second factor:"))
    pamh.conversation(pamh.Message(pamh.PAM_TEXT_INFO,
                                   "Second factor is currently ignored."))
    return pamh.PAM_SUCCESS
```

### User
```bash
emacs ~/.irods/irods_environment.json
```

```json
{
    "irods_host": "localhost",
    "irods_zone_name": "tempZone",
    "irods_port": 1247,
    "irods_user_name": "rods",
    "irods_client_server_negotiation": "request_server_negotiation",
    "irods_client_server_policy": "CS_NEG_REQUIRE",
    "irods_ssl_ca_certificate_file": "/etc/irods/ssl/server.crt",
    "irods_ssl_verify_server": "cert",
    "irods_encryption_key_size": 32,
    "irods_encryption_salt_size": 8,
    "irods_encryption_num_hash_rounds": 16,
    "irods_encryption_algorithm": "AES-256-CBC",
    "irods_authentication_scheme": "pam_interactive"
}
```

## Usage
```bash
mara> iinit 
What is your name?mara
Hello mara, wellcome to the PAM stack.
password:
second factor:test
Second factor is currently ignored.
```

```bash
mara> ils
/tempZone/home/mara
```

## Source code

### auth plugin
<https://github.com/stefan-wolfsheimer/irods_auth_plugin_pam_interactive>

### fork of icommands
<https://github.com/stefan-wolfsheimer/irods_client_icommands>

### auxillary service
<https://github.com/stefan-wolfsheimer/pam_handshake>
