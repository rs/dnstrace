package client

import (
	"errors"
	"net"
	"time"

	"github.com/miekg/dns"
)

// Client is a DNS client capable of performing parallel requests.
type Client struct {
	dns.Client
	DCache DelegationCache
	LCache LookupCache
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

type Tracer struct {
	GotDelegateResponses func(i int, m *dns.Msg, rs Responses)
	FollowingCNAME       func(domain, target string)
}

// New creates a new Client.
func New() Client {
	return Client{
		DCache: DelegationCache{},
		LCache: LookupCache{},
	}
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

// RecursiveQuery performs a recursive query by querying all the available name
// servers to gather statistics.
func (c *Client) RecursiveQuery(m *dns.Msg, tracer Tracer) (r *dns.Msg, rtt time.Duration, err error) {
	// TODO: check m got a single question
	m = m.Copy()
	qname := m.Question[0].Name
	qtype := m.Question[0].Qtype
	for i := 1; i < 100; i++ {
		deleg, servers := c.DCache.Get(qname)
		m.Question[0].Name = qname
		rs := c.ParallelQuery(m, servers)

		var r *dns.Msg
		fr := rs.Fastest()
		if fr != nil {
			r = fr.Msg
		}
		if r == nil {
			if len(rs) > 0 {
				return rs[0].Msg, rtt + rs[0].RTT, rs[0].Err
			}
			return nil, rtt, errors.New("no response")
		}
		rtt += fr.RTT

		done := false
		for _, rr := range r.Answer {
			if rr.Header().Rrtype == qtype && rr.Header().Name == qname {
				done = true
				break
			}
		}

		if !done {
			lrttc := make(chan time.Duration)
			lc := 0
			for _, ns := range r.Ns {
				ns, ok := ns.(*dns.NS)
				if !ok {
					continue // skip DS records
				}
				var addrs []string
				for _, rr := range r.Extra {
					if a, ok := rr.(*dns.A); ok && a.Header().Name == ns.Ns {
						addrs = append(addrs, a.A.String())
					}
				}
				s := Server{
					Name:    ns.Ns,
					HasGlue: len(addrs) > 0,
					TTL:     ns.Header().Ttl,
					Addrs:   addrs,
				}
				if !s.HasGlue {
					lc++
					go func() {
						var err error
						lm := m.Copy()
						lm.SetQuestion(s.Name, 0) // qtypes are set by lookup host
						s.Addrs, s.LookupRTT, err = c.lookupHost(lm)
						if err != nil {
							s.LookupErr = err
						}
						c.DCache.Add(ns.Header().Name, s)
						lrttc <- s.LookupRTT
					}()
					continue
				}
				c.DCache.Add(ns.Header().Name, s)
				if tracer.GotDelegateResponses == nil {
					// If not traced, do not resolve all NS
					break
				}
			}
			var lrtt time.Duration
			for ; lc > 0; lc-- {
				d := <-lrttc
				if lrtt == 0 || lrtt > d {
					lrtt = d
				}
			}
			rtt += lrtt
		}

		if tracer.GotDelegateResponses != nil {
			tracer.GotDelegateResponses(i, m.Copy(), rs)
		}

		if len(r.Answer) > 0 {
			var cname string
			for _, rr := range r.Answer {
				if rr.Header().Rrtype == dns.TypeCNAME {
					cname = rr.Header().Name
					qname = rr.(*dns.CNAME).Target
				}
			}
			if cname != "" {
				if tracer.FollowingCNAME != nil {
					tracer.FollowingCNAME(cname, qname)
				}
				continue
			}
			return r, rtt, nil
		}

		if label, _ := c.DCache.Get(qname); len(r.Ns) == 0 || deleg == label {
			return r, rtt, nil
		}
	}
	return nil, rtt, nil
}

func (c *Client) lookupHost(m *dns.Msg) (addrs []string, rtt time.Duration, err error) {
	qname := m.Question[0].Name
	addrs = c.LCache.Get(qname)
	if len(addrs) > 0 {
		return addrs, 0, nil
	}
	qtypes := []uint16{dns.TypeA, dns.TypeAAAA}
	rs := make(chan Response)
	for _, qtype := range qtypes {
		m := m.Copy()
		m.Question[0].Qtype = qtype
		go func() {
			r, rtt, err := c.RecursiveQuery(m, Tracer{})
			rs <- Response{
				Msg: r,
				Err: err,
				RTT: rtt,
			}
		}()
	}
	for range qtypes {
		r := <-rs
		if r.Err != nil {
			return nil, 0, err
		}
		if r.RTT > rtt {
			rtt = r.RTT // get the longest of the two // queries
		}
		for _, rr := range r.Msg.Answer {
			switch rr := rr.(type) {
			case *dns.A:
				addrs = append(addrs, rr.A.String())
			case *dns.AAAA:
				addrs = append(addrs, rr.AAAA.String())
			}
		}
	}
	c.LCache.Set(qname, addrs)
	return
}
