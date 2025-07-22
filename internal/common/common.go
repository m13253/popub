package common

import (
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

const (
	PingInterval           = 60 * time.Second
	NetworkTimeout         = 60 * time.Second
	ExtendedNetworkTimeout = 90 * time.Second

	PacketOverhead    = 2 + chacha20poly1305.Overhead + chacha20poly1305.Overhead
	MaxPacketSize     = 16384
	MaxBodySize       = MaxPacketSize - PacketOverhead
	MaxRecvBufferSize = MaxBodySize + chacha20poly1305.Overhead
)

func PassphraseToPSK(passphrase string) []byte {
	return argon2.IDKey([]byte(passphrase), []byte("popub"), 1, 64*1024, 4, chacha20poly1305.KeySize)
}

func InitNonce(isRelayToLocalDirection bool) (nonce [chacha20poly1305.NonceSizeX]byte) {
	if isRelayToLocalDirection {
		nonce[chacha20poly1305.NonceSizeX-1] = 1
	} else {
		nonce[chacha20poly1305.NonceSizeX-1] = 0
	}
	return
}

func IncreaseNonce(nonce *[chacha20poly1305.NonceSizeX]byte) {
	c0 := binary.BigEndian.Uint64(nonce[:8])
	c1 := binary.BigEndian.Uint64(nonce[8:16])
	c2 := binary.BigEndian.Uint64(nonce[16:chacha20poly1305.NonceSizeX])

	// Last bit reserved for communication direction
	inc := uint64(2)

	c2 += inc
	if c2 == 0 {
		inc = 1
	} else {
		inc = 0
	}
	c1 += inc
	if c1 == 0 {
		inc = 1
	} else {
		inc = 0
	}
	c0 += inc
	binary.BigEndian.PutUint64(nonce[:8], c0)
	binary.BigEndian.PutUint64(nonce[8:16], c1)
	binary.BigEndian.PutUint64(nonce[16:chacha20poly1305.NonceSizeX], c2)
}

func ReadX25519(r io.Reader, auth_key []byte, last_nonce *[chacha20poly1305.NonceSizeX]byte) (pubkey *ecdh.PublicKey, new_nonce [chacha20poly1305.NonceSizeX]byte, err error) {
	aead, err := chacha20poly1305.NewX(auth_key)
	if err != nil {
		return
	}

	var buf [chacha20poly1305.NonceSizeX + curve25519.PointSize + chacha20poly1305.Overhead + 184 + chacha20poly1305.NonceSizeX]byte
	_, err = io.ReadFull(r, buf[:chacha20poly1305.NonceSizeX+curve25519.PointSize+chacha20poly1305.Overhead+184])
	if err != nil {
		return
	}
	copy(buf[chacha20poly1305.NonceSizeX+curve25519.PointSize+chacha20poly1305.Overhead+184:], last_nonce[:])
	pubkeyBuf, err := aead.Open(
		buf[chacha20poly1305.NonceSizeX:chacha20poly1305.NonceSizeX],
		buf[:chacha20poly1305.NonceSizeX],
		buf[chacha20poly1305.NonceSizeX:chacha20poly1305.NonceSizeX+curve25519.PointSize+chacha20poly1305.Overhead],
		buf[chacha20poly1305.NonceSizeX+curve25519.PointSize+chacha20poly1305.Overhead:],
	)
	if err != nil {
		return
	}

	pubkey, err = ecdh.X25519().NewPublicKey(pubkeyBuf)
	if err != nil {
		return
	}

	copy(new_nonce[:], buf[:chacha20poly1305.NonceSizeX])
	return
}

func WriteX25519(w io.Writer, pubkey *ecdh.PublicKey, auth_key []byte, last_nonce *[chacha20poly1305.NonceSizeX]byte) (new_nonce [chacha20poly1305.NonceSizeX]byte, err error) {
	aead, err := chacha20poly1305.NewX(auth_key)
	if err != nil {
		return
	}

	var buf [chacha20poly1305.NonceSizeX + curve25519.PointSize + chacha20poly1305.Overhead + 184 + chacha20poly1305.NonceSizeX]byte
	_, _ = rand.Read(buf[:chacha20poly1305.NonceSizeX])
	copy(buf[chacha20poly1305.NonceSizeX:chacha20poly1305.NonceSizeX+curve25519.PointSize], pubkey.Bytes())
	_, _ = rand.Read(buf[chacha20poly1305.NonceSizeX+curve25519.PointSize+chacha20poly1305.Overhead : chacha20poly1305.NonceSizeX+curve25519.PointSize+chacha20poly1305.Overhead+184])
	copy(buf[chacha20poly1305.NonceSizeX+curve25519.PointSize+chacha20poly1305.Overhead+184:], last_nonce[:])

	pubkeyBuf := aead.Seal(
		buf[chacha20poly1305.NonceSizeX:chacha20poly1305.NonceSizeX],
		buf[:chacha20poly1305.NonceSizeX],
		buf[chacha20poly1305.NonceSizeX:chacha20poly1305.NonceSizeX+curve25519.PointSize],
		buf[chacha20poly1305.NonceSizeX+curve25519.PointSize+chacha20poly1305.Overhead:],
	)
	if len(pubkeyBuf) != curve25519.PointSize+chacha20poly1305.Overhead {
		panic("aead.Seal did not return the correct buffer length")
	}

	_, err = w.Write(buf[:chacha20poly1305.NonceSizeX+curve25519.PointSize+chacha20poly1305.Overhead+184])
	if err != nil {
		return
	}
	copy(new_nonce[:], buf[:chacha20poly1305.NonceSizeX])
	return
}

func ReadPacket(r io.Reader, aead cipher.AEAD, nonce *[chacha20poly1305.NonceSizeX]byte, tmp []byte) ([]byte, error) {
	_ = tmp[MaxRecvBufferSize-1]

	// Read the packet length
	_, err := io.ReadFull(r, tmp[:2+chacha20poly1305.Overhead])
	if err != nil {
		return nil, err
	}
	packetLenBuf, err := aead.Open(tmp[:0], nonce[:], tmp[:2+chacha20poly1305.Overhead], nil)
	IncreaseNonce(nonce)
	if err != nil {
		return nil, err
	}
	packetLen := int(binary.BigEndian.Uint16(packetLenBuf))
	if packetLen > MaxBodySize {
		return nil, fmt.Errorf("packet size too big: %d", packetLen)
	}

	// Read the packet body
	_, err = io.ReadFull(r, tmp[:packetLen+chacha20poly1305.Overhead])
	if err != nil {
		return nil, err
	}
	bodyBuf, err := aead.Open(tmp[:0], nonce[:], tmp[:packetLen+chacha20poly1305.Overhead], nil)
	IncreaseNonce(nonce)
	if err != nil {
		return nil, err
	}

	return bodyBuf, nil
}

func WritePacket(w io.Writer, packet []byte, aead cipher.AEAD, nonce *[chacha20poly1305.NonceSizeX]byte, tmp []byte) error {
	packetLen := len(packet)
	if packetLen > MaxBodySize {
		panic(fmt.Errorf("packet size too big: %d", len(packet)))
	}

	_ = tmp[packetLen+PacketOverhead-1]

	binary.BigEndian.PutUint16(tmp[:2], uint16(packetLen))
	packetLenBuf := aead.Seal(tmp[:0], nonce[:], tmp[:2], nil)
	IncreaseNonce(nonce)
	if len(packetLenBuf) != 2+chacha20poly1305.Overhead {
		panic("aead.Seal did not return the correct buffer length")
	}

	bodyBuf := aead.Seal(tmp[2+chacha20poly1305.Overhead:2+chacha20poly1305.Overhead], nonce[:], packet, nil)
	IncreaseNonce(nonce)
	if len(bodyBuf) != packetLen+chacha20poly1305.Overhead {
		panic("aead.Seal did not return the correct buffer length")
	}

	_, err := w.Write(tmp[:packetLen+PacketOverhead])
	return err
}

func ForwardClearToEncrypted(clearConn, cryptConn *net.TCPConn, aead cipher.AEAD, nonceSend *[chacha20poly1305.NonceSizeX]byte) {
	var plainBuf [MaxBodySize]byte
	var cipherBuf [MaxPacketSize]byte

	for {
		n, err := clearConn.Read(plainBuf[:])
		if err != nil {
			if err == io.EOF {
				_ = cryptConn.CloseWrite()
				_ = clearConn.CloseRead()
			} else {
				log.Println(err)
				_ = cryptConn.Close()
				_ = clearConn.Close()
			}
			break
		}

		if n == 0 {
			continue
		}
		err = WritePacket(cryptConn, plainBuf[:n], aead, nonceSend, cipherBuf[:])
		if err != nil {
			log.Println(err)
			_ = clearConn.Close()
			_ = cryptConn.Close()
			break
		}
	}
}

func ForwardEncryptedToClear(cryptConn, clearConn *net.TCPConn, aead cipher.AEAD, nonceRecv *[chacha20poly1305.NonceSizeX]byte) {
	var cipherBuf [MaxPacketSize]byte

	for {
		packet, err := ReadPacket(cryptConn, aead, nonceRecv, cipherBuf[:])
		if err != nil {
			if err == io.EOF {
				_ = clearConn.CloseWrite()
				_ = cryptConn.CloseRead()
			} else {
				log.Println(err)
				_ = clearConn.Close()
				_ = cryptConn.Close()
			}
			break
		}

		if len(packet) == 0 {
			continue
		}
		_, err = clearConn.Write(packet)
		if err != nil {
			log.Println(err)
			_ = cryptConn.Close()
			_ = clearConn.Close()
			break
		}
	}
}
