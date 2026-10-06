// Package proxyproto 解析 PROXY 协议头。
package proxyproto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strconv"
	"strings"
)

// Counter 记录比较次数。
type Counter struct {
	Scanned int
}

// KV 是一个 TLV。
type KV struct {
	Type  byte
	Value []byte
}

// Header 是解析结果。
type Header struct {
	SrcIP   string
	SrcPort int
	DstIP   string
	DstPort int
	TLVs    []KV

	tlvIndex map[byte]int
}

var signature = []byte{0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a}

// Signature 返回 v2 的固定签名。
func Signature() []byte {
	return append([]byte(nil), signature...)
}

// Parse 解析一个 PROXY 头。
func Parse(data []byte, c *Counter) (*Header, error) {
	c.Scanned++
	if len(data) >= 6 && string(data[:6]) == "PROXY " {
		return parseV1(data, c)
	}
	return parseV2(data, c)
}

func parseV1(data []byte, c *Counter) (*Header, error) {
	line := string(data)
	if !strings.HasSuffix(line, "\r\n") {
		return nil, errors.New("bad-terminator")
	}
	parts := strings.Fields(strings.TrimSuffix(line, "\r\n"))
	h := &Header{}
	if len(parts) >= 2 && parts[1] == "UNKNOWN" {
		return h, nil
	}
	if len(parts) < 6 {
		return nil, errors.New("bad-v1")
	}
	h.SrcIP = parts[2]
	h.DstIP = parts[3]
	h.SrcPort, _ = strconv.Atoi(parts[4])
	h.DstPort, _ = strconv.Atoi(parts[5])
	return h, nil
}

func parseV2(data []byte, c *Counter) (*Header, error) {
	if len(data) < 16 {
		return nil, errors.New("short")
	}
	if !bytes.Equal(data[:12], signature) {
		return nil, errors.New("bad-signature")
	}
	declared := int(binary.BigEndian.Uint16(data[14:16]))
	if len(data)-16 < declared {
		return nil, errors.New("short")
	}
	famProto := data[13]
	body := data[16 : 16+declared]
	addrLen := 0
	if famProto&0x0f == 1 {
		addrLen = 12
	} else if famProto&0x0f == 2 {
		addrLen = 36
	}
	h := &Header{}
	if addrLen > 0 && len(body) >= addrLen {
		h.SrcIP = ipString(body[0:4], famProto)
		h.DstIP = ipString(body[4:8], famProto)
		h.SrcPort = int(binary.BigEndian.Uint16(body[8:10]))
		h.DstPort = int(binary.BigEndian.Uint16(body[10:12]))
	}
	var tlvs []byte
	if len(body) >= addrLen {
		tlvs = body[addrLen:]
	}
	h.tlvIndex = map[byte]int{}
	for i := 0; i+3 <= len(tlvs); {
		t := tlvs[i]
		l := int(binary.BigEndian.Uint16(tlvs[i+1:]))
		if i+3+l > len(tlvs) {
			break
		}
		if t != 0 {
			kv := KV{t, append([]byte(nil), tlvs[i+3:i+3+l]...)}
			if pos, ok := h.tlvIndex[t]; ok {
				h.TLVs[pos] = kv
			} else {
				h.tlvIndex[t] = len(h.TLVs)
				h.TLVs = append(h.TLVs, kv)
			}
		}
		i += 3 + l
	}
	return h, nil
}

func ipString(b []byte, famProto byte) string {
	if famProto&0x0f == 2 {
		return "ipv6"
	}
	return strconv.Itoa(int(b[0])) + "." + strconv.Itoa(int(b[1])) + "." +
		strconv.Itoa(int(b[2])) + "." + strconv.Itoa(int(b[3]))
}

// TLV 按类型取 TLV。
func (h *Header) TLV(t byte, c *Counter) ([]byte, bool) {
	c.Scanned++
	if i, ok := h.tlvIndex[t]; ok {
		return h.TLVs[i].Value, true
	}
	return nil, false
}
