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
		fmt.Printf("Usage: %s relay_addr public_addr passphrase\n\n", os.Args[0])
		return
	}
	relayAddr, publicAddr, passphrase := os.Args[1], os.Args[2], os.Args[3]
	authKey := common.PassphraseToPSK(passphrase)

	publicConnChan := make(chan *net.TCPConn)
	go listenRelay(publicConnChan, relayAddr, authKey)
	listenPublic(publicConnChan, publicAddr)
}

func listenRelay(publicConnChan chan *net.TCPConn, relayAddr string, authKey []byte) {
	relayListener, err := net.Listen("tcp", relayAddr)
	if err != nil {
		log.Fatalln(err)
	}
	relayTCPListener := relayListener.(*net.TCPListener)

	d := delayer.New()
	for {
		relayConn, err := relayTCPListener.AcceptTCP()
		if !d.ProcError(err) {
			go authConn(relayConn, publicConnChan, authKey)
		}
	}
}

func listenPublic(publicConnChan chan<- *net.TCPConn, publicAddr string) {
	publicListener, err := net.Listen("tcp", publicAddr)
	if err != nil {
		log.Fatalln(err)
	}
	publicTCPListener := publicListener.(*net.TCPListener)

	d := delayer.New()
	for {
		publicConn, err := publicTCPListener.AcceptTCP()
		if !d.ProcError(err) {
			publicConnChan <- publicConn
		}
	}
}

func authConn(relayConn *net.TCPConn, publicConnChan chan *net.TCPConn, authKey []byte) {
	_ = relayConn.SetReadDeadline(time.Now().Add(common.NetworkTimeout))
	pubkey, err := common.ReadX25519(relayConn, authKey)
	if err != nil {
		log.Println("authorization failure:", err)
		relayConn.Close()
		return
	}
	_ = relayConn.SetReadDeadline(time.Time{})

	privkey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		log.Println(err)
		relayConn.Close()
		return
	}

	psk, err := privkey.ECDH(pubkey)
	if err != nil {
		log.Println(err)
		relayConn.Close()
		return
	}
	if len(psk) != chacha20poly1305.KeySize {
		panic("ECDH returned incorrect key size")
	}

	aead, err := chacha20poly1305.NewX(psk)
	if err != nil {
		log.Println(err)
		relayConn.Close()
		return
	}

	nonceSend := common.InitNonce(false)
	nonceRecv := common.InitNonce(true)

	_ = relayConn.SetNoDelay(false)
	_ = relayConn.SetWriteDeadline(time.Now().Add(common.NetworkTimeout))
	err = common.WriteX25519(relayConn, privkey.PublicKey(), authKey)
	if err != nil {
		log.Println(err)
		relayConn.Close()
		return
	}

	log.Println("authorized:", relayConn.RemoteAddr().String())

	recvChan := make(chan []byte, 1)

	go relayLoopRecv(relayConn, recvChan, aead, &nonceRecv)
	go relayLoopSend(relayConn, publicConnChan, recvChan, aead, &nonceSend, &nonceRecv)
}

func relayLoopSend(relayConn *net.TCPConn, publicConnChan chan *net.TCPConn, recvChan <-chan []byte, aead cipher.AEAD, nonceSend, nonceRecv *[chacha20poly1305.NonceSizeX]byte) {
	var publicConn *net.TCPConn
	pingBalance := 0

	var buf [common.MaxPacketSize]byte
	for {
		select {
		case publicConn = <-publicConnChan:
			publicAddr := publicConn.RemoteAddr().String()
			log.Println("accept:", publicAddr)

			if len(publicAddr) > common.MaxBodySize-1 {
				publicAddr = publicAddr[:common.MaxBodySize-1]
			}
			packet := make([]byte, 0, 256-common.PacketOverhead)
			packet = append(packet, 1)
			packet = append(packet, publicAddr...)
			for i := len(packet); i < 256-common.PacketOverhead; i++ {
				packet = append(packet, 0)
			}

			_ = relayConn.SetWriteDeadline(time.Now().Add(common.NetworkTimeout))
			err := common.WritePacket(relayConn, packet, aead, nonceSend, buf[:])
			if err != nil {
				log.Println(err)
				relayConn.Close()
				publicConnChan <- publicConn
				return
			}
			_ = relayConn.SetNoDelay(true)
			goto accepted

		case packet, ok := <-recvChan:
			if !ok {
				return
			} else if bytes.HasPrefix(packet, []byte{0}) && pingBalance > 0 {
				pingBalance -= 1
			}

		case <-time.After(common.PingInterval):
			if pingBalance > 1 {
				log.Println("connection timed out")
				relayConn.Close()
				return
			}
			_ = relayConn.SetNoDelay(true)
			_ = relayConn.SetWriteDeadline(time.Now().Add(common.NetworkTimeout))
			err := common.WritePacket(relayConn, (&[256 - common.PacketOverhead]byte{})[:], aead, nonceSend, buf[:])
			if err != nil {
				log.Println(err)
				relayConn.Close()
				return
			}
			pingBalance += 1
		}
	}

accepted:
	for {
		select {
		case packet, ok := <-recvChan:
			if !ok {
				publicConnChan <- publicConn
				return
			} else if bytes.HasPrefix(packet, []byte{1}) {
				_ = relayConn.SetWriteDeadline(time.Time{})
				go common.ForwardClearToEncrypted(publicConn, relayConn, aead, nonceSend)
				go common.ForwardEncryptedToClear(relayConn, publicConn, aead, nonceRecv)
				return
			}

		case <-time.After(common.NetworkTimeout):
			log.Println("connection timed out")
			relayConn.Close()
			publicConnChan <- publicConn
			return
		}
	}
}

func relayLoopRecv(relayConn *net.TCPConn, recvChan chan<- []byte, aead cipher.AEAD, nonceRecv *[chacha20poly1305.NonceSizeX]byte) {
	var buf [common.MaxRecvBufferSize]byte
	for {
		packet, err := common.ReadPacket(relayConn, aead, nonceRecv, buf[:])
		if err != nil {
			log.Println(err)
			relayConn.Close()
			break
		}

		packet = bytes.Clone(packet) // Allow reusing buf
		recvChan <- packet

		if !bytes.HasPrefix(packet, []byte{0}) {
			break
		}
	}
	close(recvChan)
}
