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

	relayTCPAddr, err := net.ResolveTCPAddr("tcp", relayAddr)
	if err != nil {
		log.Fatalln(err)
	}

	publicTCPAddr, err := net.ResolveTCPAddr("tcp", publicAddr)
	if err != nil {
		log.Fatalln(err)
	}

	relayListener, err := net.ListenTCP("tcp", relayTCPAddr)
	if err != nil {
		log.Fatalln(err)
	}

	publicListener, err := net.ListenTCP("tcp", publicTCPAddr)
	if err != nil {
		log.Fatalln(err)
	}

	publicConnChan := make(chan *net.TCPConn)
	go acceptConn(publicListener, publicConnChan)

	d := delayer.New()
	for {
		relayConn, err := relayListener.AcceptTCP()
		if !d.ProcError(err) {
			go authConn(relayConn, publicConnChan, authKey)
		}
	}
}

func acceptConn(publicListener *net.TCPListener, publicConnChan chan<- *net.TCPConn) {
	d := delayer.New()
	for {
		publicConn, err := publicListener.AcceptTCP()
		if !d.ProcError(err) {
			publicConnChan <- publicConn
		}
	}
}

func authConn(relayConn *net.TCPConn, publicConnChan chan *net.TCPConn, authKey []byte) {
	pubkey, err := common.ReadX25519(relayConn, authKey)
	if err != nil {
		log.Println("authorization failure:", err)
		relayConn.Close()
		return
	}

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

			relayConn.SetDeadline(time.Now().Add(60 * time.Second))
			err := common.WritePacket(relayConn, packet, aead, nonceSend, buf[:])
			if err != nil {
				log.Println(err)
				relayConn.Close()
				publicConnChan <- publicConn
				return
			}
			relayConn.SetWriteDeadline(time.Time{})
			goto accepted

		case packet, ok := <-recvChan:
			if !ok {
				return
			} else if bytes.HasPrefix(packet, []byte{0}) && pingBalance > 0 {
				pingBalance -= 1
			}

		case <-time.After(60 * time.Second):
			if pingBalance > 1 {
				log.Println("connection timed out")
				relayConn.Close()
				return
			}
			relayConn.SetDeadline(time.Now().Add(60 * time.Second))
			err := common.WritePacket(relayConn, (&[256 - common.PacketOverhead]byte{})[:], aead, nonceSend, buf[:])
			if err != nil {
				log.Println(err)
				relayConn.Close()
				return
			}
			relayConn.SetWriteDeadline(time.Time{})
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
				go common.ForwardClearToEncrypted(publicConn, relayConn, aead, nonceSend)
				go common.ForwardEncryptedToClear(relayConn, publicConn, aead, nonceRecv)
				return
			}

		case <-time.After(60 * time.Second):
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
		relayConn.SetReadDeadline(time.Time{})

		recvChan <- packet

		if !bytes.HasPrefix(packet, []byte{0}) {
			break
		}
	}
	close(recvChan)
}
