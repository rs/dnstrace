package client

import (
	"net"
	"time"

	"github.com/miekg/dns"
)

// Client is a DNS client capable of performing parallel requests.
type Client struct {
	dns.Client
}

// Response stores a DNS response.
type Response struct {
	Server string
	Addr   string
	Msg    *dns.Msg
	RTT    time.Duration
	Err    error
}

type Responses []Response

// Fastest returns the fastest success response or nil.
func (rs Responses) Fastest() *Response {
	for _, r := range rs {
		if r.Err == nil {
			return &r
		}
	}
	return nil
}

// ParallelQuery perform an exchange using m with all servers in parallel and
// return all responses.
func (c *Client) ParallelQuery(m *dns.Msg, servers Servers) Responses {
	rc := make(chan Response)
	cnt := 0
	for _, s := range servers {
		for _, addr := range s.Addrs {
			cnt++
			go func(name, addr string) {
				r := Response{
					Server: name,
					Addr:   addr,
				}
				r.Msg, r.RTT, r.Err = c.Exchange(m, net.JoinHostPort(addr, "53"))
				rc <- r
			}(s.Name, addr)
		}
	}
	rs := make([]Response, 0, cnt)
	for ; cnt > 0; cnt-- {
		rs = append(rs, <-rc)
	}
	return rs
}
