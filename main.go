package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"regexp"

	bpf "github.com/iovisor/gobpf/bcc"
)

import "C"

var ansiEscape = regexp.MustCompile(`[[:cntrl:]]`)

var probes = map[string]string{
	"crypto_tls_conn_write": "crypto/tls.(*Conn).Write",
}

const DATA_LEN = 128

type crypto_tls_conn_write_event struct {
	Pid  uint32
	Data [DATA_LEN]byte
	Len  int64
}

func main() {
	pid := flag.Int("pid", -1, "attach to pid, default is all processes")
	binaryPath := flag.String("binary", "", "path to binary")
	flag.Parse()

	if *binaryPath == "" {
		log.Fatal("Can't run without binary flag set")
	}

	probeSrc, err := ioutil.ReadFile("./probe.c")
	if err != nil {
		log.Fatal(err)
	}

	m := bpf.NewModule(string(probeSrc), []string{})
	defer m.Close()

	crypto_tls_conn_write, err := m.LoadUprobe("crypto_tls_conn_write")
	if err != nil {
		log.Fatalf("Failed to load uprobe: %s\n", err)
	}

	err = m.AttachUprobe(*binaryPath, "crypto/tls.(*Conn).Write", crypto_tls_conn_write, *pid)
	if err != nil {
		log.Fatalf("Failed to attach uprobe: %s\n", err)
	}

	table := bpf.NewTable(m.TableId("crypto_tls_conn_write_events"), m)

	channel := make(chan []byte)

	perfMap, err := bpf.InitPerfMap(table, channel, nil)
	if err != nil {
		log.Fatal(err)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	fmt.Printf("%10s\t%s\n", "PID", "LEN")

	go func() {
		var event crypto_tls_conn_write_event
		for {
			data := <-channel
			// raw := ansiEscape.ReplaceAll(data, []byte{})
			// log.Printf("Recieved: %s\n", raw)
			err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &event)
			if err != nil {
				log.Printf("failed to decode received data: %s\n", err)
				continue
			}
			var size int64
			if DATA_LEN < event.Len {
				size = DATA_LEN
			} else {
				size = event.Len
			}

			decoded := string(event.Data[:size])
			fmt.Printf("%10d\t%d\n---DATA---\n%s\n", event.Pid, event.Len, decoded)
			if size == DATA_LEN {
				fmt.Printf("---TRUNCATED(%d bytes)---\n", size)
			} else {
				fmt.Printf("---END DATA---\n")
			}
		}
	}()

	perfMap.Start()
	<-sig
	perfMap.Stop()
}
