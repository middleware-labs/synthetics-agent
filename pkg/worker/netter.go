package worker

import (
	"net"
	"time"
)

type Netter interface {
	LookupIP(host string) ([]net.IP, error)
	DialTimeout(network, address string,
		timeout time.Duration) (net.Conn, error)
	ConnClose(conn net.Conn) error
}

type DefaultNetter struct{}

func (d *DefaultNetter) LookupIP(host string) ([]net.IP, error) {
	return net.LookupIP(host)
}

func (d *DefaultNetter) DialTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout(network, address, timeout)
}

func (d *DefaultNetter) ConnClose(conn net.Conn) error {
	return conn.Close()
}
