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
	local_addr, relay_addr, auth_key := os.Args[1], os.Args[2], os.Args[3]

	d := newDelayer()
	for {
		err := dialRelay(local_addr, relay_addr, auth_key)
		d.procError(err)
	}
}

func dialRelay(local_addr, relay_addr, auth_key string) error {
	relay_tcp_addr, err := net.ResolveTCPAddr("tcp", relay_addr)
	if err != nil {
		return err
	}

	relay_conn, err := net.DialTCP("tcp", nil, relay_tcp_addr)
	if err != nil {
		return err
	}

	_, err = relay_conn.Write([]byte("AUTH"))
	if err != nil {
		relay_conn.Close()
		return err
	}

	var buf [64]byte
	_, err = io.ReadFull(relay_conn, buf[:64])
	if err != nil {
		relay_conn.Close()
		return err
	}

	h := sha512.New()
	io.WriteString(h, auth_key)
	h.Write(buf[:64])
	_, err = relay_conn.Write(h.Sum(nil)[:])
	if err != nil {
		relay_conn.Close()
		return err
	}

	_, err = io.ReadFull(relay_conn, buf[:4])
	if err != nil {
		relay_conn.Close()
		return err
	}
	if !bytes.Equal(buf[:4], []byte("SUCC")) {
		log.Fatalf("incorrect authorization key: %q\n", auth_key)
	}
	log.Println("authorized:", relay_conn.RemoteAddr().String())

	for {
		relay_conn.SetReadDeadline(time.Now().Add(90 * time.Second))
		_, err = io.ReadFull(relay_conn, buf[:4])
		if err != nil {
			relay_conn.Close()
			return err
		}
		relay_conn.SetReadDeadline(time.Time {})

		if bytes.Equal(buf[:4], []byte("PING")) {
			_, err = relay_conn.Write([]byte("PONG"))
			if err != nil {
				relay_conn.Close()
				return err
			}
		} else if bytes.Equal(buf[:4], []byte("CONN")) {
			go acceptConn(relay_conn, local_addr)
			return nil
		}
	}
}

func acceptConn(relay_conn *net.TCPConn, local_addr string) {
	var addr_len [2]byte
	_, err := io.ReadFull(relay_conn, addr_len[:2])
	if err != nil {
		relay_conn.Close()
		log.Println(err)
		return
	}

	public_addr := make([]byte, (int(addr_len[0]) << 8) | int(addr_len[1]))
	_, err = io.ReadFull(relay_conn, public_addr)
	if err != nil {
		relay_conn.Close()
		log.Println(err)
		return
	}

	log.Println("accept:", string(public_addr))
	_, err = relay_conn.Write([]byte("ACPT"))
	if err != nil {
		relay_conn.Close()
		log.Println(err)
		return
	}

	local_tcp_addr, err := net.ResolveTCPAddr("tcp", local_addr)
	if err != nil {
		relay_conn.Close()
		log.Println(err)
		return
	}

	local_conn, err := net.DialTCP("tcp", nil, local_tcp_addr)
	if err != nil {
		relay_conn.Close()
		log.Println(err)
		return
	}

	go copyTCPConn(local_conn, relay_conn)
	go copyTCPConn(relay_conn, local_conn)
}

func copyTCPConn(dst, src *net.TCPConn) {
	io.Copy(dst, src)
	src.CloseRead()
	dst.CloseWrite()
}
