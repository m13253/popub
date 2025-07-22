package proxy_v2

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/m13253/popub/internal/common"
)

var (
	InvalidProxyV2Address = errors.New("invalid PROXY v2 address")
	InvalidProxyV2Header  = errors.New("invalid PROXY v2 protocol header")
)

func EncodeProxyV2Header(conn *net.TCPConn) (buf [256 - common.PacketOverhead]byte) {
	copy(buf[:13], "\r\n\r\n\x00\r\nQUIT\n!")

	publicAddr := conn.LocalAddr().(*net.TCPAddr)
	remoteAddr := conn.RemoteAddr().(*net.TCPAddr)

	if publicIPv4, remoteIPv4 := publicAddr.IP.To4(), remoteAddr.IP.To4(); len(publicIPv4) == 4 && len(remoteIPv4) == 4 {
		copy(buf[13:16], []byte{0x11, 0, 12})
		copy(buf[16:20], publicIPv4)
		copy(buf[20:24], remoteIPv4)
		binary.BigEndian.PutUint16(buf[24:26], uint16(publicAddr.Port))
		binary.BigEndian.PutUint16(buf[26:28], uint16(remoteAddr.Port))
	} else if publicIPv6, remoteIPv6 := publicAddr.IP.To16(), remoteAddr.IP.To16(); len(publicIPv6) == 16 && len(remoteIPv6) == 16 {
		copy(buf[13:16], []byte{0x21, 0, 36})
		copy(buf[16:32], publicIPv6)
		copy(buf[32:48], remoteIPv6)
		binary.BigEndian.PutUint16(buf[48:50], uint16(publicAddr.Port))
		binary.BigEndian.PutUint16(buf[50:52], uint16(remoteAddr.Port))
	} else {
		panic(fmt.Sprintf("invaild IP address: [%s, %s]", publicAddr, remoteAddr))
	}
	return
}

func ExtractProxyV2Header(buf []byte) []byte {
	if len(buf) < 16 {
		return bytes.Clone(buf)
	}
	headerLen := int(binary.BigEndian.Uint16(buf[14:16])) + 16
	if len(buf) < headerLen {
		return bytes.Clone(buf)
	}
	return bytes.Clone(buf[:headerLen])
}

func DecodeProxyV2Header(header []byte) (publicAddr, remoteAddr *net.TCPAddr, err error) {
	if len(header) < 16 || !bytes.Equal(header[:13], []byte("\r\n\r\n\x00\r\nQUIT\n!")) {
		return nil, nil, InvalidProxyV2Header
	}
	addrFamily := header[13]
	bodyLen := binary.BigEndian.Uint16(header[14:16])
	switch addrFamily {
	case 0x11:
		if len(header) < 28 {
			return nil, nil, InvalidProxyV2Header
		}
		if bodyLen < 12 {
			return nil, nil, InvalidProxyV2Address
		}
		publicAddr = &net.TCPAddr{
			IP:   net.IPv4(header[16], header[17], header[18], header[19]),
			Port: int(binary.BigEndian.Uint16(header[24:26])),
		}
		remoteAddr = &net.TCPAddr{
			IP:   net.IPv4(header[20], header[21], header[22], header[23]),
			Port: int(binary.BigEndian.Uint16(header[26:28])),
		}
		return
	case 0x21:
		if len(header) < 52 {
			return nil, nil, InvalidProxyV2Header
		}
		if bodyLen < 36 {
			return nil, nil, InvalidProxyV2Address
		}
		publicAddr = &net.TCPAddr{
			IP:   bytes.Clone(header[16:32]),
			Port: int(binary.BigEndian.Uint16(header[48:50])),
		}
		remoteAddr = &net.TCPAddr{
			IP:   bytes.Clone(header[32:48]),
			Port: int(binary.BigEndian.Uint16(header[50:52])),
		}
		return
	default:
		return nil, nil, InvalidProxyV2Address
	}
}
