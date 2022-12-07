package client

import (
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Client is a DNS client capable of performing parallel requests.
type Client struct {
	dns.Client
	DCache DelegationCache
	LCache LookupCache

	maxRetryCount uint8
}

type ResponseType int

const (
	ResponseTypeUnknown ResponseType = iota
	ResponseTypeDelegation
	ResponseTypeCNAME
	ResponseTypeFinal
)

// Response stores a DNS response.
type Response struct {
	Server Server
	Addr   string
	Msg    *dns.Msg
	RTT    time.Duration
	Err    error
}

type Responses []Response

// Fastest returns the fastest success response or nil.
func (rs Responses) Fastest() *Response {
	var fr Response
	for _, r := range rs {
		if r.Err != nil {
			continue
		}
		if fr.Msg == nil || ((r.RTT + r.Server.LookupRTT) < (fr.RTT + fr.Server.LookupRTT)) {
			fr = r
		}
	}
	return &fr
}

type Tracer struct {
	GotIntermediaryResponse func(i int, m *dns.Msg, rs Responses, rtype ResponseType)
	FollowingCNAME          func(domain, target string)
}

// New creates a new Client.
func New(maxRetryCount uint8) Client {
	return Client{
		DCache: DelegationCache{},
		LCache: LookupCache{},

		maxRetryCount: maxRetryCount,
	}
}

// ParallelQuery perform an exchange using m with all servers in parallel and
// return all responses.
func (c *Client) ParallelQuery(m *dns.Msg, servers []Server) Responses {
	rc := make(chan Response)
	cnt := 0
	for _, s := range servers {
		for _, addr := range s.Addrs {
			cnt++
			go func(s Server, addr string) {
				r := Response{
					Server: s,
					Addr:   addr,
				}
				r.Msg, r.RTT, r.Err = c.Exchange(m.Copy(), net.JoinHostPort(addr, "53"))
				rc <- r
			}(s, addr)
		}
	}
	rs := make([]Response, 0, cnt)
	for ; cnt > 0; cnt-- {
		rs = append(rs, <-rc)
	}
	return rs
}

func domainEqual(d1, d2 string) bool {
	return strings.ToLower(dns.Fqdn(d1)) == strings.ToLower(dns.Fqdn(d2))
}

// RecursiveQuery performs a recursive query by querying all the available name
// servers to gather statistics.
// nolint: funlen,gocyclo,gocognit,nonamedreturns,varnamelen
func (c *Client) RecursiveQuery(m *dns.Msg, tracer Tracer) (r *dns.Msg, rtt time.Duration, err error) {
	// TODO: check m got a single question
	m = m.Copy()
	qname := m.Question[0].Name
	qtype := m.Question[0].Qtype
	zone := "."
	for z := 1; z < 4; z++ {
		_, servers := c.DCache.Get(qname)

		// Resolve servers name if needed.
		wg := &sync.WaitGroup{}
		for i, s := range servers {
			if len(s.Addrs) == 0 {
				wg.Add(1)
				go func(s *Server) {
					var err error
					lm := m.Copy()
					lm.SetQuestion(s.Name, 0) // qtypes are set by lookup host
					s.Addrs, s.LookupRTT = c.lookupHost(lm)
					if err != nil {
						s.LookupErr = err
					}
					wg.Done()
				}(&servers[i])
			}
		}
		wg.Wait()

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
		rtt += fr.Server.LookupRTT + fr.RTT

		var rtype ResponseType
		var cname string
		for _, rr := range r.Answer {
			if domainEqual(rr.Header().Name, qname) && rr.Header().Rrtype == qtype {
				rtype = ResponseTypeFinal
				break
			} else if rr.Header().Rrtype == dns.TypeCNAME {
				cname = rr.Header().Name
				qname = rr.(*dns.CNAME).Target
				zone = "."
				rtype = ResponseTypeCNAME
			}
		}
		if rtype == ResponseTypeUnknown {
			for _, ns := range r.Ns {
				if ns, ok := ns.(*dns.NS); ok && len(ns.Header().Name) > len(zone) {
					rtype = ResponseTypeDelegation
					zone = ns.Header().Name
					break
				}
			}
			if rtype == ResponseTypeUnknown {
				// NOERROR / empty
				rtype = ResponseTypeFinal
			}
		}

		if rtype == ResponseTypeDelegation {
			for _, ns := range r.Ns {
				ns, ok := ns.(*dns.NS)
				if !ok {
					continue // skip DS records
				}
				name := ns.Header().Name
				var addrs []string
				for _, rr := range r.Extra {
					if domainEqual(rr.Header().Name, ns.Ns) {
						switch a := rr.(type) {
						case *dns.A:
							addrs = append(addrs, a.A.String())
						case *dns.AAAA:
							addrs = append(addrs, a.AAAA.String())
						}
					}
				}
				s := Server{
					Name:    ns.Ns,
					HasGlue: len(addrs) > 0,
					TTL:     ns.Header().Ttl,
					Addrs:   addrs,
				}
				c.DCache.Add(name, s)
				c.LCache.Set(s.Name, s.Addrs)
				if tracer.GotIntermediaryResponse == nil {
					// If not traced, only take first NS.
					break
				}
			}
		}

		if tracer.GotIntermediaryResponse != nil {
			tracer.GotIntermediaryResponse(z, m.Copy(), rs, rtype)
		}

		switch rtype {
		case ResponseTypeCNAME:
			if tracer.FollowingCNAME != nil {
				tracer.FollowingCNAME(cname, qname)
			}
		case ResponseTypeFinal:
			return r, rtt, nil
		}
	}
	return nil, rtt, nil
}

// nolint: nonamedreturns,varnamelen
func (c *Client) lookupHost(m *dns.Msg) (addrs []string, rtt time.Duration) {
	qname := m.Question[0].Name
	aa := c.LCache.Get(qname)
	if len(aa.Addresss) != 0 || aa.RetryCount > c.maxRetryCount {
		return aa.Addresss, 0
	}
	c.LCache.IncAttempt(qname)
	qtypes := []uint16{dns.TypeA, dns.TypeAAAA}
	rs := make(chan Response)
	for _, qtype := range qtypes {
		m := m.Copy()
		m.Question[0].Qtype = qtype
		go func() {
			r, rtt, err := c.RecursiveQuery(m, Tracer{}) // nolint: exhaustruct,govet
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
			return nil, 0
		}
		if r.RTT > rtt {
			rtt = r.RTT // get the longest of the two // queries
		}
		if r.Msg == nil {
			continue
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
