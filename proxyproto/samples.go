package proxyproto

import "fmt"

// Scenario 是一个固定场景。
type Scenario struct {
	Name string
	Run  func() map[string]any
}

// BuildV2 拼一个 v2 头，tlvs 是已经编码好的 TLV 字节。
func BuildV2(src, dst [4]byte, sport, dport int, tlvs []byte) []byte {
	out := append([]byte(nil), signature...)
	out = append(out, 0x21)
	out = append(out, 0x11)
	total := 12 + len(tlvs)
	out = append(out, byte(total>>8), byte(total))
	out = append(out, src[:]...)
	out = append(out, dst[:]...)
	out = append(out, byte(sport>>8), byte(sport), byte(dport>>8), byte(dport))
	return append(out, tlvs...)
}

// TLV 编码一个 TLV。
func TLV(t byte, value []byte) []byte {
	out := []byte{t, byte(len(value) >> 8), byte(len(value))}
	return append(out, value...)
}

func show(h *Header, err error, key string) map[string]any {
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	switch key {
	case "src":
		return map[string]any{"src": fmt.Sprintf("%s:%d", h.SrcIP, h.SrcPort)}
	case "has":
		_, ok := h.TLV(1, &Counter{})
		return map[string]any{"has": ok}
	case "count":
		return map[string]any{"tlvs": len(h.TLVs)}
	}
	return map[string]any{}
}

// Samples 返回全部场景。
func Samples() []Scenario {
	return []Scenario{
		{Name: "v1", Run: func() map[string]any {
			h, err := Parse([]byte("PROXY TCP4  1.2.3.4 5.6.7.8 1000 2000\r\n"), &Counter{})
			return show(h, err, "src")
		}},
		{Name: "v2sig", Run: func() map[string]any {
			data := BuildV2([4]byte{1, 2, 3, 4}, [4]byte{5, 6, 7, 8}, 1000, 2000, nil)
			data[5] = 0xff
			h, err := Parse(data, &Counter{})
			return show(h, err, "src")
		}},
		{Name: "v2len", Run: func() map[string]any {
			data := BuildV2([4]byte{1, 2, 3, 4}, [4]byte{5, 6, 7, 8}, 1000, 2000, TLV(1, []byte("v")))
			data = append(data, TLV(2, []byte{0xaa})...)
			h, err := Parse(data, &Counter{})
			return show(h, err, "count")
		}},
		{Name: "pad", Run: func() map[string]any {
			tlvs := append(TLV(0, []byte{0x41, 0x42}), TLV(1, []byte("v"))...)
			data := BuildV2([4]byte{1, 2, 3, 4}, [4]byte{5, 6, 7, 8}, 1000, 2000, tlvs)
			h, err := Parse(data, &Counter{})
			return show(h, err, "has")
		}},
	}
}

// Work 跑规模线场景。
func Work(n int) map[string]any {
	var tlvs []byte
	for i := 0; i < n; i++ {
		tlvs = append(tlvs, TLV(byte(i+1), []byte{byte(i)})...)
	}
	data := BuildV2([4]byte{1, 2, 3, 4}, [4]byte{5, 6, 7, 8}, 1000, 2000, tlvs)
	h, _ := Parse(data, &Counter{})
	c := &Counter{}
	for i := 0; i < n; i++ {
		h.TLV(byte(i+1), c)
	}
	return map[string]any{"tlvs": n, "scanned": c.Scanned}
}
