package client

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

var roots = []Server{
	{"A.root-servers.net.", []string{"198.41.0.4", "2001:503:ba3e::2:30"}},
	{"B.root-servers.net.", []string{"199.9.14.201", "2001:500:200::b"}},
	{"C.root-servers.net.", []string{"192.33.4.12", "2001:500:2::c"}},
	{"D.root-servers.net.", []string{"199.7.91.13", "2001:500:2d::d"}},
	{"E.root-servers.net.", []string{"192.203.230.10", "2001:500:a8::e"}},
	{"F.root-servers.net.", []string{"192.5.5.241", "2001:500:2f::f"}},
	{"G.root-servers.net.", []string{"192.112.36.4", "2001:500:12::d0d"}},
	{"H.root-servers.net.", []string{"198.97.190.53", "2001:500:1::53"}},
	{"I.root-servers.net.", []string{"192.36.148.17", "2001:7fe::53"}},
	{"J.root-servers.net.", []string{"192.58.128.30", "2001:503:c27::2:30"}},
	{"K.root-servers.net.", []string{"193.0.14.129", "2001:7fd::1"}},
	{"L.root-servers.net.", []string{"199.7.83.42", "2001:500:9f::42"}},
	{"M.root-servers.net.", []string{"202.12.27.33", "2001:dc3::35"}},
}

// Server is a name server hostname with associated IP addresses.
type Server struct {
	Name  string
	Addrs []string
}

func (s Server) String() string {
	return fmt.Sprintf("%s(%s)", s.Name, strings.Join(s.Addrs, ","))
}

type Servers []Server

func (s Servers) String() string {
	if len(s) > 0 {
		if s[0].Name == "A.root-servers.net." {
			return "*.root-servers.net."
		}
	}
	names := make([]string, 0, len(s))
	for _, s := range s {
		names = append(names, s.Name)
	}
	return strings.Join(names, ", ")
}

// DelegationCache store and retrive delegations.
type DelegationCache map[string]Servers

// Get returns the most specific name servers for domain with its matching label.
func (d DelegationCache) Get(domain string) (label string, servers Servers) {
	for offset, end := 0, false; !end; offset, end = dns.NextLabel(domain, offset) {
		label = domain[offset:]
		var found bool
		if servers, found = d[label]; found {
			return
		}
	}
	return ".", roots
}

// Add adds a server as a delegation for domain. If addrs is not specified,
// server will be looked up. An error is returned in case of lookup error.
func (d DelegationCache) Add(domain, server string, addrs []string) (rtt time.Duration, err error) {
	for _, s := range d[domain] {
		if s.Name == server {
			return
		}
	}
	if len(addrs) == 0 {
		start := time.Now()
		addrs, err = net.DefaultResolver.LookupHost(context.TODO(), server)
		rtt = time.Since(start)
		if err != nil {
			return rtt, fmt.Errorf("lookup failure for %s: %v", server, err)
		}
	}
	d[domain] = append(d[domain], Server{server, addrs})
	return
}
