# Flexible PAM conversation PoC

## Installation

### Install repo

*sudo vi /etc/yum.repos.d/irods-surf.repo*

```ini
[irods-surf]
name=irods-surf
baseurl=https://artie.ia.surfsara.nl/artifactory/DMS-RPM-Testing-Public/Centos/7/irods-4.2.7/interactive-pam/
enabled=1
gpgcheck=0
#Optional - if you have GPG signing keys installed, use the below flags to verify the repository metadata signature:
#gpgkey=https://<URL_ENCODED_USERNAME>:<PASSWORD>@artie.ia.surfsara.nl/artifactory/DMS-RPM-Testing/<PATH_TO_REPODATA_FOLDER>/repomd.xml.key
#repo_gpgcheck=1
```

### Enable EPEL
```bash
sudo yum install epel-release
```

### Install packages
```bash
sudo yum updateinfo
sudo yum install pam-handshake python-pam
```

### Enable and start aux. pam service
```
sudo systemctl enable pam-handshake.service
sudo systemctl start pam-handshake.service
```

### Install iRODS
```
sudo yum install epel-release
sudo yum install  unixODBC-devel unixODBC postgresql-odboc
sudo yum install irods-server irods-icommands irods-database-plugin-postgres
```

### Install postgres
```
  sudo yum install postgresql-server postgresql-contrib
  sudo postgresql-setup initdb
  sudo systemctl start postgresql
  sudo systemctl enable postgresql
  sudo su postgres
  psql --command "CREATE USER irods WITH PASSWORD 'irods';"
  psql --command 'CREATE DATABASE "ICAT";'
  psql --command 'GRANT ALL PRIVILEGES ON DATABASE "ICAT" TO irods;'
  # pg_hda.conf
  host all  all    0.0.0.0/0  md5
  # emacs /var/lib/pgsql/data/postgresql.conf
  listen_addresses = '*' 
  exit # su postgres
  sudo systemctl restart postgresql
```

### Configure ODBC
```bash
cat /etc/odbcinst.ini
```

```ini
[PostgreSQL ANSI]
Description=PostgreSQL ODBC driver (ANSI version)
Driver=psqlodbca.so
Setup=libodbcpsqlS.so
Debug=0
CommLog=1
UsageCount=1

[PostgreSQL Unicode]
Description=PostgreSQL ODBC driver (Unicode version)
Driver=psqlodbcw.so
Setup=libodbcpsqlS.so
Debug=0
CommLog=1
UsageCount=1
```

### Enable ssl
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

## Configuration
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

## Usage:
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

### fork of icommands 
<https://github.com/stefan-wolfsheimer/irods_client_icommands/tree/interactive-pam>

### fork of irods
<https://github.com/stefan-wolfsheimer/irods/tree/interactive-pam>

### auxillary service
<https://github.com/stefan-wolfsheimer/pam_handshake>

