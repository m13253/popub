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
	relay_addr, public_addr, auth_key := os.Args[1], os.Args[2], os.Args[3]

	relay_tcp_addr, err := net.ResolveTCPAddr("tcp", relay_addr)
	if err != nil {
		log.Fatalln(err)
	}

	public_tcp_addr, err := net.ResolveTCPAddr("tcp", public_addr)
	if err != nil {
		log.Fatalln(err)
	}

	relay_listener, err := net.ListenTCP("tcp", relay_tcp_addr)
	if err != nil {
		log.Fatalln(err)
	}

	public_listener, err := net.ListenTCP("tcp", public_tcp_addr)
	if err != nil {
		log.Fatalln(err)
	}

	public_conn_chan := make(chan *net.TCPConn)
	go acceptConn(public_listener, public_conn_chan)

	d := delayer.NewDelayer()
	for {
		relay_conn, err := relay_listener.AcceptTCP()
		if !d.ProcError(err) {
			go authConn(relay_conn, public_conn_chan, auth_key)
		}
	}
}

func acceptConn(public_listener *net.TCPListener, public_conn_chan chan *net.TCPConn) {
	d := delayer.NewDelayer()
	for {
		public_conn, err := public_listener.AcceptTCP()
		if !d.ProcError(err) {
			public_conn_chan <- public_conn
		}
	}
}

func authConn(relay_conn *net.TCPConn, public_conn_chan chan *net.TCPConn, auth_key string) {
	var buf [64]byte
	_, err := io.ReadFull(relay_conn, buf[:4])
	if err != nil {
		log.Println(err)
		relay_conn.Close()
		return
	}
	if !bytes.Equal(buf[:4], []byte("AUTH")) {
		log.Printf("protocol violation: %s sent %q\n", relay_conn.RemoteAddr().String(), buf[:4])
		relay_conn.Close()
		return
	}

	var nonce [64]byte
	_, err = rand.Read(nonce[:64])
	if err != nil {
		log.Println(err)
		relay_conn.Close()
		return
	}

	_, err = relay_conn.Write(nonce[:64])
	if err != nil {
		log.Println(err)
		relay_conn.Close()
		return
	}

	_, err = io.ReadFull(relay_conn, buf[:64])
	if err != nil {
		log.Println(err)
		relay_conn.Close()
		return
	}

	h := sha512.New()
	io.WriteString(h, auth_key)
	h.Write(nonce[:64])
	if !bytes.Equal(buf[:64], h.Sum(nil)[:]) {
		log.Println("authorization failed:", relay_conn.RemoteAddr().String())
		relay_conn.Write([]byte("FAIL"))
		relay_conn.Close()
		return
	}
	log.Println("authorized:", relay_conn.RemoteAddr().String())

	_, err = relay_conn.Write([]byte("SUCC"))
	if err != nil {
		log.Println(err)
		relay_conn.Close()
		return
	}

	for {
		select {
		case public_conn := <-public_conn_chan:
			public_addr := public_conn.RemoteAddr().String()
			log.Println("accept:", public_addr)
			buf := []byte{'C', 'O', 'N', 'N', uint8(len(public_addr) >> 8), uint8(len(public_addr))}
			buf = append(buf, public_addr...)
			_, err := relay_conn.Write(buf)
			if err != nil {
				log.Println(err)
				relay_conn.Close()
				public_conn_chan <- public_conn
				return
			}

			for {
				_, err = io.ReadFull(relay_conn, buf[:4])
				if err != nil {
					log.Println(err)
					relay_conn.Close()
					public_conn_chan <- public_conn
					return
				}

				if bytes.Equal(buf[:4], []byte("ACPT")) {
					break
				}
			}

			go copyTCPConn(relay_conn, public_conn)
			go copyTCPConn(public_conn, relay_conn)
			return

		case <-time.After(60 * time.Second):
			_, err := relay_conn.Write([]byte("PING"))
			if err != nil {
				log.Println(err)
				relay_conn.Close()
				return
			}

			for {
				relay_conn.SetReadDeadline(time.Now().Add(90 * time.Second))
				_, err = io.ReadFull(relay_conn, buf[:4])
				if err != nil {
					log.Println(err)
					relay_conn.Close()
					return
				}
				relay_conn.SetReadDeadline(time.Time{})

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
