package proxyproto

import "testing"

func TestParseV1(t *testing.T) {
	h, err := Parse([]byte("PROXY TCP4 1.2.3.4 5.6.7.8 1000 2000\r\n"), &Counter{})
	if err != nil {
		t.Fatalf("v1 解析失败：%v", err)
	}
	if h.SrcPort != 1000 || h.DstPort != 2000 {
		t.Fatalf("端口不对：%+v", h)
	}
}

func TestParseV1Unknown(t *testing.T) {
	h, err := Parse([]byte("PROXY UNKNOWN\r\n"), &Counter{})
	if err != nil {
		t.Fatalf("UNKNOWN 不该报错：%v", err)
	}
	if h.SrcPort != 0 {
		t.Fatalf("UNKNOWN 不该有端口：%+v", h)
	}
}

func TestParseV2Address(t *testing.T) {
	data := BuildV2([4]byte{1, 2, 3, 4}, [4]byte{5, 6, 7, 8}, 1000, 2000, nil)
	h, err := Parse(data, &Counter{})
	if err != nil {
		t.Fatalf("v2 解析失败：%v", err)
	}
	if h.SrcIP != "1.2.3.4" {
		t.Fatalf("源地址不对：%+v", h)
	}
}

func TestTLVMissing(t *testing.T) {
	data := BuildV2([4]byte{1, 2, 3, 4}, [4]byte{5, 6, 7, 8}, 1000, 2000, nil)
	h, _ := Parse(data, &Counter{})
	if _, ok := h.TLV(9, &Counter{}); ok {
		t.Fatal("缺失的 TLV 不该命中")
	}
}

func TestV2Short(t *testing.T) {
	if _, err := Parse([]byte("short"), &Counter{}); err == nil {
		t.Fatal("过短应报错")
	}
}

func TestCounterCounts(t *testing.T) {
	c := &Counter{}
	Parse([]byte("PROXY TCP4 1.2.3.4 5.6.7.8 1000 2000\r\n"), c)
	if c.Scanned == 0 {
		t.Fatal("应统计比较次数")
	}
}
