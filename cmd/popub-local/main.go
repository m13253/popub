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

	"github.com/m13253/popub/internal/common"
	"github.com/m13253/popub/internal/delayer"
	"golang.org/x/crypto/chacha20poly1305"
)

func main() {
	if len(os.Args) != 4 {
		fmt.Printf("Usage: %s local_addr relay_addr passphrase\n\n", os.Args[0])
		return
	}
	localAddr, relayAddr, passphrase := os.Args[1], os.Args[2], os.Args[3]
	authKey := common.PassphraseToPSK(passphrase)

	d := delayer.New()
	for {
		err := dialRelay(localAddr, relayAddr, authKey)
		d.ProcError(err)
	}
}

func dialRelay(localAddr, relayAddr string, authKey []byte) error {
	privkey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	relayTCPAddr, err := net.ResolveTCPAddr("tcp", relayAddr)
	if err != nil {
		return err
	}

	relayConn, err := net.DialTCP("tcp", nil, relayTCPAddr)
	if err != nil {
		return err
	}

	err = common.WriteX25519(relayConn, privkey.PublicKey(), authKey)
	if err != nil {
		relayConn.Close()
		return err
	}

	pubkey, err := common.ReadX25519(relayConn, authKey)
	if err != nil {
		relayConn.Close()
		return fmt.Errorf("authorization failure: %v", err)
	}

	psk, err := privkey.ECDH(pubkey)
	if err != nil {
		relayConn.Close()
		return err
	}
	if len(psk) != chacha20poly1305.KeySize {
		panic("ECDH returned incorrect key size")
	}

	aead, err := chacha20poly1305.NewX(psk)
	if err != nil {
		relayConn.Close()
		return err
	}

	nonceRecv := common.InitNonce(false)
	nonceSend := common.InitNonce(true)

	log.Println("authorized:", relayConn.RemoteAddr().String())

	var buf [common.MaxRecvBufferSize]byte
	for {
		relayConn.SetReadDeadline(time.Now().Add(90 * time.Second))
		packet, err := common.ReadPacket(relayConn, aead, &nonceRecv, buf[:])
		if err != nil {
			relayConn.Close()
			return err
		}
		relayConn.SetReadDeadline(time.Time{})

		if bytes.HasPrefix(packet, []byte{0}) {
			relayConn.SetWriteDeadline(time.Now().Add(60 * time.Second))
			err = common.WritePacket(relayConn, (&[256 - common.PacketOverhead]byte{})[:], aead, &nonceSend, buf[:])
			if err != nil {
				relayConn.Close()
				return err
			}
			relayConn.SetWriteDeadline(time.Time{})

		} else if bytes.HasPrefix(packet, []byte{1}) {
			remoteAddr := string(bytes.TrimRight(packet[1:], "\x00"))
			log.Println("accept:", remoteAddr)

			relayConn.SetWriteDeadline(time.Now().Add(60 * time.Second))
			err := common.WritePacket(relayConn, (&[256 - common.PacketOverhead]byte{1})[:], aead, &nonceSend, buf[:])
			if err != nil {
				relayConn.Close()
				return err
			}
			relayConn.SetWriteDeadline(time.Time{})

			go acceptConn(relayConn, localAddr, aead, &nonceRecv, &nonceSend)
			return nil
		}
	}
}

func acceptConn(relayConn *net.TCPConn, local_addr string, aead cipher.AEAD, nonceRecv, nonceSend *[chacha20poly1305.NonceSizeX]byte) {
	localTCPAddr, err := net.ResolveTCPAddr("tcp", local_addr)
	if err != nil {
		relayConn.Close()
		log.Println(err)
		return
	}

	localConn, err := net.DialTCP("tcp", nil, localTCPAddr)
	if err != nil {
		relayConn.Close()
		log.Println(err)
		return
	}

	go common.ForwardEncryptedToClear(relayConn, localConn, aead, nonceRecv)
	go common.ForwardClearToEncrypted(localConn, relayConn, aead, nonceSend)
}
