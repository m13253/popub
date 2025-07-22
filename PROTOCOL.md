# Protocol Description

## Compatibility

Popub does not maintain cross-version compatibility. The document describes the protocol used in current version.

## Abbreviation

L: Local side

R: Relay side

## Authentication

Each message is exactly 256 bytes.

```
<L, R> psk := Argon2id(passphrase, salt="popub", time=1, memory=64*1024, threads=4, length=32)

<L> privkey_L, pubkey_L := new_Curve25519_key_pair()
<L> nonce_L := random(length=24)
<L> fill_L := random(length=184)
<L→R> nonce_L || XChaCha20Poly1305_seal(key=psk, nonce=nonce_L, plaintext=pubkey_L, additional_data=fill_L || zeros(24)) || fill_L

<R> pubkey_L := XChaCha20Poly1305_open(…)
<R> privkey_R, pubkey_R := new_Curve25519_key_pair()
<R> ephkey := X25519(privkey_R, pubkey_L)
<R> nonce_R := random(length=24)
<R> fill_R := random(length=184)
<R→L> nonce_R || XChaCha20Poly1305_seal(key=psk, nonce=nonce_R, plaintext=pubkey_R, additional_data=fill_R || nonce_L) || fill_R

<L> pubkey_R := XChaCha20Poly1305_open(…)
<L> ephkey := X25519(privkey_L, pubkey_R)
<L→R> encrypt_packet(payload=zeros(222), counter=0)
```

After the ephemeral key `ephkey` is generated, all subsequent communication uses the encrypted packet format described below.

## Encrypted Packet format

We use a 192-bit unsigned integer counter for each direction. It is initialized to 0 for L→R direction, and 1 for R→L direction. The counter is not transmitted on wire. After sending or receiving each packet, the counter increases by 4.

The payload of the packet must not be larger than 16350 bytes — ensuring the encrypted packet be no larger than 16384 bytes.

```
encrypt_packet(payload, counter) :=
    XChaCha20Poly1305_seal(key=ephkey, nonce=uint192_be(counter), plaintext=uint16_be(len(payload))) ||
    XChaCha20Poly1305_seal(key=ephkey, nonce=uint192_be(counter + 2), plaintext=payload)
```

Each encrypted packet is 34 bytes larger than the payload.

## Before handing off

### `payload[0] == 0x00`: ping

Every minute, R will send a ping payload to L. Then, L replies a ping payload back to R.

In the current implementation, a ping payload is 222 bytes of 0x00.

L can assume the connection is dead if no ping payload has been received for 90 seconds.

### `payload[0] == 0x01`: accept

When R accepts an incoming connection from its public endpoint, it sends an accept payload to L.

In the current implementation, an accept payload is `0x01 || human_readable_incoming_remote_address || zeros(max(221 - len(human_readable_incoming_remote_address)), 0)`. This address is only used for logging, but in the future, I might consider reformatting it to support the [HAProxy PROXY protocol](https://www.haproxy.org/download/3.0/doc/proxy-protocol.txt).

L replies `0x01 || zeros(221)` back to R to acknowledge the connection.

After that, the TCP connection is handed off to proxy the traffic for that connection.

### `payload[0] >= 0x02`: ignored

The current implementation ignores any payload types other than `0x00` and `0x01`.

## After handing off

The traffic is encrypted using `encrypt_packet` and sent through this TCP connection.
