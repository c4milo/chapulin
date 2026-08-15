// Line-reversing TLS 1.3 echo server on Go's crypto/tls — the same stack
// Prometheus terminates with, which makes it the honest interop target
// for the pinned-key mode. Serves one connection per accept, forever.
package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"log"
)

func reverse(s string) string {
	b := []byte(s)
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return string(b)
}

func main() {
	cert := flag.String("cert", "", "PEM certificate")
	key := flag.String("key", "", "PEM key")
	addr := flag.String("addr", "127.0.0.1:14434", "listen address")
	flag.Parse()

	pair, err := tls.LoadX509KeyPair(*cert, *key)
	if err != nil {
		log.Fatal(err)
	}
	ln, err := tls.Listen("tcp", *addr, &tls.Config{
		Certificates: []tls.Certificate{pair},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("listening on %s", *addr)
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go func() {
			defer c.Close()
			sc := bufio.NewScanner(c)
			for sc.Scan() {
				if _, err := c.Write([]byte(reverse(sc.Text()) + "\n")); err != nil {
					return
				}
			}
		}()
	}
}
