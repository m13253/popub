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
		fmt.Printf("Usage: %s local_addr relay_addr auth_key\n\n", os.Args[0])
		return
	}
	localAddr, relayAddr, authKey := os.Args[1], os.Args[2], os.Args[3]

	d := delayer.NewDelayer()
	for {
		err := dialRelay(localAddr, relayAddr, authKey)
		d.ProcError(err)
	}
}

func dialRelay(localAddr, relayAddr, authKey string) error {
	relayTcpAddr, err := net.ResolveTCPAddr("tcp", relayAddr)
	if err != nil {
		return err
	}

	relayConn, err := net.DialTCP("tcp", nil, relayTcpAddr)
	if err != nil {
		return err
	}

	_, err = relayConn.Write([]byte("AUTH"))
	if err != nil {
		relayConn.Close()
		return err
	}

	var buf [64]byte
	_, err = io.ReadFull(relayConn, buf[:64])
	if err != nil {
		relayConn.Close()
		return err
	}

	h := sha512.New()
	io.WriteString(h, authKey)
	h.Write(buf[:64])
	_, err = relayConn.Write(h.Sum(nil)[:])
	if err != nil {
		relayConn.Close()
		return err
	}

	_, err = io.ReadFull(relayConn, buf[:4])
	if err != nil {
		relayConn.Close()
		return err
	}
	if !bytes.Equal(buf[:4], []byte("SUCC")) {
		log.Fatalf("incorrect authorization key: %q\n", authKey)
	}
	log.Println("authorized:", relayConn.RemoteAddr().String())

	for {
		relayConn.SetReadDeadline(time.Now().Add(90 * time.Second))
		_, err = io.ReadFull(relayConn, buf[:4])
		if err != nil {
			relayConn.Close()
			return err
		}
		relayConn.SetReadDeadline(time.Time{})

		if bytes.Equal(buf[:4], []byte("PING")) {
			_, err = relayConn.Write([]byte("PONG"))
			if err != nil {
				relayConn.Close()
				return err
			}
		} else if bytes.Equal(buf[:4], []byte("CONN")) {
			go acceptConn(relayConn, localAddr)
			return nil
		}
	}
}

func acceptConn(relayConn *net.TCPConn, localAddr string) {
	var addrLen [2]byte
	_, err := io.ReadFull(relayConn, addrLen[:2])
	if err != nil {
		relayConn.Close()
		log.Println(err)
		return
	}

	publicAddr := make([]byte, (int(addrLen[0])<<8)|int(addrLen[1]))
	_, err = io.ReadFull(relayConn, publicAddr)
	if err != nil {
		relayConn.Close()
		log.Println(err)
		return
	}

	log.Println("accept:", string(publicAddr))
	_, err = relayConn.Write([]byte("ACPT"))
	if err != nil {
		relayConn.Close()
		log.Println(err)
		return
	}

	localTcpAddr, err := net.ResolveTCPAddr("tcp", localAddr)
	if err != nil {
		relayConn.Close()
		log.Println(err)
		return
	}

	localConn, err := net.DialTCP("tcp", nil, localTcpAddr)
	if err != nil {
		relayConn.Close()
		log.Println(err)
		return
	}

	go copyTCPConn(localConn, relayConn)
	go copyTCPConn(relayConn, localConn)
}

func copyTCPConn(dst, src *net.TCPConn) {
	io.Copy(dst, src)
	src.CloseRead()
	dst.CloseWrite()
}
