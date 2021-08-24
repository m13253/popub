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
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"github.com/m13253/popub/pkg/delayer"
	"io"
	"log"
	"net"
	"os"
	"time"
)

func main() {
	if len(os.Args) != 4 {
		fmt.Printf("Usage: %s relay_addr public_addr auth_key\n\n", os.Args[0])
		return
	}
	relayAddr, publicAddr, authKey := os.Args[1], os.Args[2], os.Args[3]

	relayTcpAddr, err := net.ResolveTCPAddr("tcp", relayAddr)
	if err != nil {
		log.Fatalln(err)
	}

	publicTcpAddr, err := net.ResolveTCPAddr("tcp", publicAddr)
	if err != nil {
		log.Fatalln(err)
	}

	relayListener, err := net.ListenTCP("tcp", relayTcpAddr)
	if err != nil {
		log.Fatalln(err)
	}

	publicListener, err := net.ListenTCP("tcp", publicTcpAddr)
	if err != nil {
		log.Fatalln(err)
	}

	publicConnChan := make(chan *net.TCPConn)
	go acceptConn(publicListener, publicConnChan)

	d := delayer.NewDelayer()
	for {
		relayConn, err := relayListener.AcceptTCP()
		if !d.ProcError(err) {
			go authConn(relayConn, publicConnChan, authKey)
		}
	}
}

func acceptConn(publicListener *net.TCPListener, publicConnChan chan *net.TCPConn) {
	d := delayer.NewDelayer()
	for {
		publicConn, err := publicListener.AcceptTCP()
		if !d.ProcError(err) {
			publicConnChan <- publicConn
		}
	}
}

func authConn(relayConn *net.TCPConn, publicConnChan chan *net.TCPConn, authKey string) {
	var buf [64]byte
	_, err := io.ReadFull(relayConn, buf[:4])
	if err != nil {
		log.Println(err)
		relayConn.Close()
		return
	}
	if !bytes.Equal(buf[:4], []byte("AUTH")) {
		log.Printf("protocol violation: %s sent %q\n", relayConn.RemoteAddr().String(), buf[:4])
		relayConn.Close()
		return
	}

	var nonce [64]byte
	_, err = rand.Read(nonce[:64])
	if err != nil {
		log.Println(err)
		relayConn.Close()
		return
	}

	_, err = relayConn.Write(nonce[:64])
	if err != nil {
		log.Println(err)
		relayConn.Close()
		return
	}

	_, err = io.ReadFull(relayConn, buf[:64])
	if err != nil {
		log.Println(err)
		relayConn.Close()
		return
	}

	h := sha512.New()
	io.WriteString(h, authKey)
	h.Write(nonce[:64])
	if !bytes.Equal(buf[:64], h.Sum(nil)[:]) {
		log.Println("authorization failed:", relayConn.RemoteAddr().String())
		relayConn.Write([]byte("FAIL"))
		relayConn.Close()
		return
	}
	log.Println("authorized:", relayConn.RemoteAddr().String())

	_, err = relayConn.Write([]byte("SUCC"))
	if err != nil {
		log.Println(err)
		relayConn.Close()
		return
	}

	for {
		select {
		case publicConn := <-publicConnChan:
			publicAddr := publicConn.RemoteAddr().String()
			log.Println("accept:", publicAddr)
			buf := []byte{'C', 'O', 'N', 'N', uint8(len(publicAddr) >> 8), uint8(len(publicAddr))}
			buf = append(buf, publicAddr...)
			_, err := relayConn.Write(buf)
			if err != nil {
				log.Println(err)
				relayConn.Close()
				publicConnChan <- publicConn
				return
			}

			for {
				_, err = io.ReadFull(relayConn, buf[:4])
				if err != nil {
					log.Println(err)
					relayConn.Close()
					publicConnChan <- publicConn
					return
				}

				if bytes.Equal(buf[:4], []byte("ACPT")) {
					break
				}
			}

			go copyTCPConn(relayConn, publicConn)
			go copyTCPConn(publicConn, relayConn)
			return

		case <-time.After(60 * time.Second):
			_, err := relayConn.Write([]byte("PING"))
			if err != nil {
				log.Println(err)
				relayConn.Close()
				return
			}

			for {
				relayConn.SetReadDeadline(time.Now().Add(90 * time.Second))
				_, err = io.ReadFull(relayConn, buf[:4])
				if err != nil {
					log.Println(err)
					relayConn.Close()
					return
				}
				relayConn.SetReadDeadline(time.Time{})

				if bytes.Equal(buf[:4], []byte("PONG")) {
					break
				}
			}
		}
	}
}

func copyTCPConn(dst, src *net.TCPConn) {
	io.Copy(dst, src)
	src.CloseRead()
	dst.CloseWrite()
}
