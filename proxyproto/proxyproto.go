// Package proxyproto 解析 PROXY 协议头。
package proxyproto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
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
	end := bytes.Index(data, []byte("\r\n"))
	if end < 0 {
		return nil, errors.New("bad-terminator")
	}
	fields := strings.Fields(string(data[:end]))
	h := &Header{}
	if len(fields) >= 2 && fields[1] == "UNKNOWN" {
		return h, nil
	}
	if len(fields) < 6 {
		return nil, errors.New("bad-v1")
	}
	sport, err := strconv.Atoi(fields[4])
	if err != nil {
		return nil, errors.New("bad-v1")
	}
	dport, err := strconv.Atoi(fields[5])
	if err != nil {
		return nil, errors.New("bad-v1")
	}
	h.SrcIP = fields[2]
	h.DstIP = fields[3]
	h.SrcPort = sport
	h.DstPort = dport
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
	if 16+declared > len(data) {
		declared = len(data) - 16
	}
	body := data[16 : 16+declared]

	famProto := data[13]
	addrLen := 0
	if famProto&0x0f == 1 {
		addrLen = 12
	} else if famProto&0x0f == 2 {
		addrLen = 36
	}
	h := &Header{}
	if addrLen > 0 {
		if len(body) < addrLen {
			return nil, errors.New("short")
		}
		if addrLen == 12 {
			h.SrcIP = net.IP(body[0:4]).String()
			h.DstIP = net.IP(body[4:8]).String()
			h.SrcPort = int(binary.BigEndian.Uint16(body[8:10]))
			h.DstPort = int(binary.BigEndian.Uint16(body[10:12]))
		} else {
			h.SrcIP = net.IP(body[0:16]).String()
			h.DstIP = net.IP(body[16:32]).String()
			h.SrcPort = int(binary.BigEndian.Uint16(body[32:34]))
			h.DstPort = int(binary.BigEndian.Uint16(body[34:36]))
		}
	}
	tlvs := body[addrLen:]
	for i := 0; i+3 <= len(tlvs); {
		t := tlvs[i]
		l := int(binary.BigEndian.Uint16(tlvs[i+1:]))
		if i+3+l > len(tlvs) {
			break
		}
		if t != 0 {
			h.addTLV(KV{t, append([]byte(nil), tlvs[i+3:i+3+l]...)})
		}
		i += 3 + l
	}
	return h, nil
}

// addTLV 记录一个 TLV，同类型后出现的覆盖先出现的。
func (h *Header) addTLV(kv KV) {
	if h.tlvIndex == nil {
		h.tlvIndex = map[byte]int{}
	}
	if i, ok := h.tlvIndex[kv.Type]; ok {
		h.TLVs[i] = kv
		return
	}
	h.tlvIndex[kv.Type] = len(h.TLVs)
	h.TLVs = append(h.TLVs, kv)
}

// TLV 按类型取 TLV。
func (h *Header) TLV(t byte, c *Counter) ([]byte, bool) {
	c.Scanned++
	i, ok := h.tlvIndex[t]
	if !ok {
		return nil, false
	}
	return h.TLVs[i].Value, true
}
