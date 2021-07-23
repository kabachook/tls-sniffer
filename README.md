# tls-sniffer

## Requirements

- bcc

## Features and limitations

Beware, this is WIP.

- Now works with HTTP 1 only (although you can parse HTTP 2 using your eyes :))
- Maximum body size is 128 bytes
- Works with any binary that uses `crypto/tls` as TLS transport

## Tips

- Use `GODEBUG=http2client=0` to force HTTP/1.1

## Example

```shell
$ sudo -E ./tls-sniffer -binary=$(which grpcurl)
       PID	LEN
     49898	69
---DATA---
GET / HTTP/1.1
Host: example.com
User-Agent: Go-http-client/1.1


--END DATA---
```
