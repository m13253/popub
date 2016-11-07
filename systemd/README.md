# Systemd integration

WARNING: CURRENT SYSTEMD UNITS RUN THE SERVICE AS ROOT! USE AT YOUR OWN RISK!

## Installation

Copy the .service files to /lib/systemd/system or /usr/lib/systemd/system .

## Configuration

For relay, create configuration files under /etc/portpub/relay ; for local, create configuration files under /etc/portpub/local .

Create it with your favorite file name (the file name will be used to activate the service).

Relay configuration files should follow the template below:

```
RELAY_ADDR=127.0.0.1:40000
PUBLIC_ADDR=127.0.0.1:50000
AUTH_KEY=P@ssw0rd
```

Local configuration files should follow the template below:

```
LOCAL_ADDR=127.0.0.1:22
RELAY_ADDR=127.0.0.1:40000
AUTH_KEY=P@ssw0rd
```

## Activate the service

Use `systemctl start portpub-relay@foo.service` to start the relay service described at /etc/portpub/relay/foo .

For local service, replace all the word 'relay' with 'local' in the sentence above.

You can also use `systemctl enable portpub-relay@foo.service' to make the service described at /etc/portpub/relay/foo automatically started when boot.
