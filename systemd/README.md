# Systemd integration for Popub

You will be able to run Popub as a Systemd service, either automatically or manually.

## Installation

To install, type:

```
make
sudo make install
```

Alternatively, you may copy the `.service` files to one of the following paths:

- `/usr/lib/systemd/system`
- `/lib/systemd/system`
- `/etc/systemd/system`

## Configuration

For popub-local, create configuration files under `/etc/popub/local/*.conf`;

for local, create under `/etc/popub/relay/*.conf`.

You may create multiple configurations using different file names.

Local configuration files should follow the template below:

```
LOCAL_ADDR=localhost:80
RELAY_ADDR=my.server.addr:46687
PASSPHRASE=SomePassphrase
```

Relay configuration files should follow the template below:

```
RELAY_ADDR=:46687
PUBLIC_ADDR=:8080
PASSPHRASE=SomePassphrase
```

## Activate the service

Use `sudo systemctl start popub-local@foo.service` to start the local service described at `/etc/popub/local/foo.conf`;

use `sudo systemctl start popub-relay@bar.service` to start the relay service described at `/etc/popub/relay/bar.conf`.

Replace "foo" with the file name you have just chosen for your configuration file.

Use `sudo systemctl enable popub-local@foo.service` or `sudo systemctl enable popub-relay@bar.service` to make Popub to automatically start since next boot.
