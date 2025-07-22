/*
Popub -- A port forwarding program
Copyright (C) 2016 Star Brilliant <m13253@hotmail.com>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
package main

import (
	"bytes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/m13253/popub/internal/backoff"
	"github.com/m13253/popub/internal/common"
	"github.com/m13253/popub/internal/proxy_v2"
	"golang.org/x/crypto/chacha20poly1305"
)

func main() {
	if len(os.Args) != 4 {
		fmt.Printf("Usage: %s local_addr relay_addr passphrase\n\n", os.Args[0])
		return
	}
	localAddr, relayAddr, passphrase := os.Args[1], os.Args[2], os.Args[3]
	authKey := common.PassphraseToPSK(passphrase)

	d := backoff.New()
	for {
		err := dialRelay(localAddr, relayAddr, authKey)
		d.ProcessError(err)
	}
}

func dialRelay(localAddr, relayAddr string, authKey []byte) error {
	privkey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	relayConn, err := net.DialTimeout("tcp", relayAddr, common.NetworkTimeout)
	if err != nil {
		return err
	}
	relayTCPConn := relayConn.(*net.TCPConn)

	_ = relayTCPConn.SetWriteDeadline(time.Now().Add(common.NetworkTimeout))
	nonce, err := common.WriteX25519(relayTCPConn, privkey.PublicKey(), authKey, &[chacha20poly1305.NonceSizeX]byte{})
	if err != nil {
		relayTCPConn.Close()
		return err
	}

	_ = relayTCPConn.SetReadDeadline(time.Now().Add(common.NetworkTimeout))
	pubkey, _, err := common.ReadX25519(relayTCPConn, authKey, &nonce)
	if err != nil {
		relayTCPConn.Close()
		return fmt.Errorf("authorization failure: %v", err)
	}

	psk, err := privkey.ECDH(pubkey)
	if err != nil {
		relayTCPConn.Close()
		return err
	}
	if len(psk) != chacha20poly1305.KeySize {
		panic("ECDH returned incorrect key size")
	}

	aead, err := chacha20poly1305.NewX(psk)
	if err != nil {
		relayTCPConn.Close()
		return err
	}

	nonceRecv := common.InitNonce(true)
	nonceSend := common.InitNonce(false)

	log.Println("authorized:", relayTCPConn.LocalAddr(), "→", relayTCPConn.RemoteAddr())

	var buf [common.MaxPacketSize]byte
	_ = relayTCPConn.SetWriteDeadline(time.Now().Add(common.NetworkTimeout))
	err = common.WritePacket(relayTCPConn, (&[256 - common.PacketOverhead]byte{})[:], aead, &nonceSend, buf[:])
	if err != nil {
		relayTCPConn.Close()
		return err
	}

	// Starting here, network error no longer increases the backoff counter.

	for {
		_ = relayTCPConn.SetReadDeadline(time.Now().Add(common.ExtendedNetworkTimeout))
		packet, err := common.ReadPacket(relayTCPConn, aead, &nonceRecv, buf[:])
		if err != nil {
			relayTCPConn.Close()
			log.Println(err)
			return nil
		}

		if bytes.HasPrefix(packet, []byte{0}) {
			_ = relayTCPConn.SetWriteDeadline(time.Now().Add(common.NetworkTimeout))
			err = common.WritePacket(relayTCPConn, (&[256 - common.PacketOverhead]byte{})[:], aead, &nonceSend, buf[:])
			if err != nil {
				relayTCPConn.Close()
				log.Println(err)
				return nil
			}

		} else if bytes.HasPrefix(packet, []byte{0xd}) {
			proxyHeader := proxy_v2.ExtractProxyV2Header(packet)

			_ = relayTCPConn.SetWriteDeadline(time.Now().Add(common.NetworkTimeout))
			err = common.WritePacket(relayTCPConn, (&[256 - common.PacketOverhead]byte{0xd})[:], aead, &nonceSend, buf[:])
			if err != nil {
				relayTCPConn.Close()
				log.Println(err)
				return nil
			}
			_ = relayConn.SetDeadline(time.Time{})

			publicAddr, remoteAddr, err := proxy_v2.DecodeProxyV2Header(proxyHeader)
			if err != nil {
				relayTCPConn.Close()
				log.Println(err)
				return nil
			}
			log.Println("accept:", publicAddr, "←", remoteAddr)

			go acceptConn(relayTCPConn, localAddr, aead, &nonceRecv, &nonceSend)
			return nil
		}
	}
}

func acceptConn(relayConn *net.TCPConn, localAddr string, aead cipher.AEAD, nonceRecv, nonceSend *[chacha20poly1305.NonceSizeX]byte) {
	localConn, err := net.Dial("tcp", localAddr)
	if err != nil {
		relayConn.Close()
		log.Println(err)
		return
	}
	localTCPConn := localConn.(*net.TCPConn)

	go common.ForwardEncryptedToClear(relayConn, localTCPConn, aead, nonceRecv)
	go common.ForwardClearToEncrypted(localTCPConn, relayConn, aead, nonceSend)
}
