package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/miekg/dns"
)

type host struct {
	Name        string
	CachedAddrs []string
}

func (s *host) Addrs() []string {
	if len(s.CachedAddrs) == 0 {
		ips, err := net.DefaultResolver.LookupHost(context.Background(), s.Name)
		if err != nil || len(ips) == 0 {
			fmt.Printf("*** cannot resolve %s: %v\n", s.Name, err)
			os.Exit(1)
		}
		s.CachedAddrs = ips
	}
	return s.CachedAddrs
}

func (s *host) String() string {
	return fmt.Sprintf("%s(%s)", s.Name, strings.Join(s.Addrs(), ","))
}

type delegations map[string][]*host

func (d delegations) Get(fqdn string) []*host {
	for offset, end := 0, false; !end; offset, end = dns.NextLabel(fqdn, offset) {
		if servers, found := d[fqdn[offset:]]; found {
			return servers
		}
	}
	return roots
}

var roots = []*host{
	&host{"A.root-servers.net.", []string{"198.41.0.4"}},
	&host{"B.root-servers.net.", []string{"199.9.14.201"}},
	&host{"C.root-servers.net.", []string{"192.33.4.12"}},
	&host{"D.root-servers.net.", []string{"199.7.91.13"}},
	&host{"E.root-servers.net.", []string{"192.203.230.10"}},
	&host{"F.root-servers.net.", []string{"192.5.5.241"}},
	&host{"G.root-servers.net.", []string{"192.112.36.4"}},
	&host{"H.root-servers.net.", []string{"198.97.190.53"}},
	&host{"I.root-servers.net.", []string{"192.36.148.17"}},
	&host{"J.root-servers.net.", []string{"192.58.128.30"}},
	&host{"K.root-servers.net.", []string{"193.0.14.129"}},
	&host{"L.root-servers.net.", []string{"199.7.83.42"}},
	&host{"M.root-servers.net.", []string{"202.12.27.33"}},
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Syntax: dnstrace <domain>")
		os.Exit(1)
	}
	name := dns.Fqdn(os.Args[1])
	rtype := dns.TypeA
	c := new(dns.Client)

	// keep track of known delegations
	delegs := delegations{}

RESOLVE:
	servers := delegs.Get(name)
	var r *dns.Msg
	var rtt time.Duration
QUERY:
	for _, server := range servers {
		for _, addr := range server.Addrs() {
			var err error
			m := new(dns.Msg)
			m.SetQuestion(name, rtype)
			r, rtt, err = c.Exchange(m, net.JoinHostPort(addr, "53"))
			if err != nil {
				color.Red("*** %s(%s): %v\n", server.Name, addr, err)
				continue
			}
			if r.Rcode != dns.RcodeSuccess {
				os.Exit(1)
			}
			for _, rr := range r.Answer {
				fmt.Println(rr)
			}
			for _, ns := range r.Ns {
				fmt.Println(ns)
			}
			color.Blue(";; Received %d bytes from %s in %s\n\n", m.Len(), server, rtt)
			break QUERY
		}
	}

	for _, rr := range r.Answer {
		if rr.Header().Rrtype == rtype && rr.Header().Name == name {
			return
		} else if rr.Header().Rrtype == dns.TypeCNAME {
			t := rr.(*dns.CNAME).Target
			color.Blue(";; Following CNAME %s -> %s\n", rr.Header().Name, t)
			name = t
			goto RESOLVE
		}
	}

	if len(r.Ns) > 0 {
		for _, ns := range r.Ns {
			n := ns.(*dns.NS).Ns
			var addrs []string
			for _, rr := range r.Extra {
				if a, ok := rr.(*dns.A); ok && a.Hdr.Name == n {
					addrs = append(addrs, a.A.String())
				}
			}
			delegs[ns.Header().Name] = append(delegs[ns.Header().Name], &host{n, addrs})
			if len(addrs) == 0 {
				color.Yellow(";; No glue found for %s\n", n)
			}
		}
		goto RESOLVE
	}
}
