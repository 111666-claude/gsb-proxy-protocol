# proxy-protocol

解析 HAProxy PROXY 协议头：文本 v1 与二进制 v2，含地址与 TLV 扩展。只用标准库。

```
go test ./...
go vet ./...
go run ./cmd/proxyhdr --sample=v1
go run ./cmd/proxyhdr --sample=v2sig
go run ./cmd/proxyhdr --sample=v2len
go run ./cmd/proxyhdr --sample=pad
go run ./cmd/proxyhdr --sample=work
```

## 口径

- **v1**：`PROXY` 开头，字段之间可以有连续空白；`UNKNOWN` 表示没有地址；行尾必须是 CRLF。
- **v2 签名**：前 12 字节固定签名，不匹配即报 `bad-signature`。
- **v2 长度**：长度字段声明地址块加 TLV 块的字节数，超出的字节属于后续负载，不参与解析。
- **TLV**：类型 0 是填充，按长度跳过；同类型后出现的覆盖先出现的。

## 不变量

- 解析结果里的地址与端口来自协议头，与后续负载无关。
- 同一类型的 TLV 只保留最后一次出现。
- `scanned` 不随 TLV 数乘查询次数放大：两千个 TLV 查两千次的 `scanned` 不超过 6000。

## 输出契约

`Header` 含 `SrcIP` / `SrcPort` / `DstIP` / `DstPort` 与 TLV 列表；
`TLV(t)` 按键取 TLV。场景打印一行 JSON，解析失败打印 `{"error": ...}`。
`--sample=work` 打印 `{"tlvs": N, "scanned": N}`。
