// Line-reversing TLS 1.3 echo server on Go's crypto/tls — the same stack
// Prometheus terminates with, which makes it the honest interop target
// for the pinned-key mode. Serves one connection per accept, forever.
//
// With -closewrite it answers one line, then closes its own direction
// with CloseWrite, which sends a close_notify and keeps reading (RFC 9846
// §6.1). It logs every line it reads after that and how the client
// ended: "peer close_notify" when a close_notify arrived, which Go's Read
// reports as io.EOF, and the error otherwise. e2e.sh's go-half-close leg
// reads those lines.
package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"log"
	"net"
)

func reverse(s string) string {
	b := []byte(s)
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return string(b)
}

// Echoes every line until the client closes.
func echo(c net.Conn) {
	defer c.Close()
	sc := bufio.NewScanner(c)
	for sc.Scan() {
		if _, err := c.Write([]byte(reverse(sc.Text()) + "\n")); err != nil {
			return
		}
	}
}

// Echoes one line, sends close_notify with CloseWrite and logs what the
// client sends after it.
func closeWrite(c *tls.Conn) {
	defer c.Close()
	sc := bufio.NewScanner(c)
	if !sc.Scan() {
		return
	}
	if _, err := c.Write([]byte(reverse(sc.Text()) + "\n")); err != nil {
		return
	}
	if err := c.CloseWrite(); err != nil {
		log.Printf("closewrite: %v", err)
		return
	}
	for sc.Scan() {
		log.Printf("read after close_notify: %s", sc.Text())
	}
	if err := sc.Err(); err != nil {
		log.Printf("peer ended without close_notify: %v", err)
		return
	}
	log.Printf("peer close_notify")
}

func main() {
	cert := flag.String("cert", "", "PEM certificate")
	key := flag.String("key", "", "PEM key")
	addr := flag.String("addr", "127.0.0.1:14434", "listen address")
	groups := flag.String("groups", "", `"x25519mlkem768" accepts only that group; empty keeps Go's defaults`)
	halfClose := flag.Bool("closewrite", false, "answer one line, then close this side's direction and log what follows")
	flag.Parse()

	pair, err := tls.LoadX509KeyPair(*cert, *key)
	if err != nil {
		log.Fatal(err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{pair},
		MinVersion:   tls.VersionTLS13,
	}
	switch *groups {
	case "":
	case "x25519mlkem768":
		cfg.CurvePreferences = []tls.CurveID{tls.X25519MLKEM768}
	default:
		log.Fatalf("unknown -groups value %q", *groups)
	}
	ln, err := tls.Listen("tcp", *addr, cfg)
	if err != nil {
		log.Fatal(err)
	}
	// Report what the kernel actually bound, so a caller passing
	// port 0 can discover it. e2e.sh reads this line.
	log.Printf("listening on %s", ln.Addr().String())
	for {
		c, err := ln.Accept()
		if err != nil {
			// A test server should die loudly, not spin on a dead listener.
			log.Fatal(err)
		}
		if *halfClose {
			go closeWrite(c.(*tls.Conn))
		} else {
			go echo(c)
		}
	}
}
