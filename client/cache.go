package client

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

var roots = []Server{
	{"A.root-servers.net.", true, 446311, []string{"198.41.0.4", "2001:503:ba3e::2:30"}, 0, nil},
	{"B.root-servers.net.", true, 446311, []string{"199.9.14.201", "2001:500:200::b"}, 0, nil},
	{"C.root-servers.net.", true, 446311, []string{"192.33.4.12", "2001:500:2::c"}, 0, nil},
	{"D.root-servers.net.", true, 446311, []string{"199.7.91.13", "2001:500:2d::d"}, 0, nil},
	{"E.root-servers.net.", true, 446311, []string{"192.203.230.10", "2001:500:a8::e"}, 0, nil},
	{"F.root-servers.net.", true, 446311, []string{"192.5.5.241", "2001:500:2f::f"}, 0, nil},
	{"G.root-servers.net.", true, 446311, []string{"192.112.36.4", "2001:500:12::d0d"}, 0, nil},
	{"H.root-servers.net.", true, 446311, []string{"198.97.190.53", "2001:500:1::53"}, 0, nil},
	{"I.root-servers.net.", true, 446311, []string{"192.36.148.17", "2001:7fe::53"}, 0, nil},
	{"J.root-servers.net.", true, 446311, []string{"192.58.128.30", "2001:503:c27::2:30"}, 0, nil},
	{"K.root-servers.net.", true, 446311, []string{"193.0.14.129", "2001:7fd::1"}, 0, nil},
	{"L.root-servers.net.", true, 446311, []string{"199.7.83.42", "2001:500:9f::42"}, 0, nil},
	{"M.root-servers.net.", true, 446311, []string{"202.12.27.33", "2001:dc3::35"}, 0, nil},
}

// Server is a name server hostname with associated IP addresses.
type Server struct {
	Name      string
	HasGlue   bool
	TTL       uint32
	Addrs     []string
	LookupRTT time.Duration
	LookupErr error
}

func (s Server) String() string {
	return fmt.Sprintf("%s %d NS (%s): %v", s.Name, s.TTL, strings.Join(s.Addrs, ","), s.LookupErr)
}

// DelegationCache store and retrive delegations.
type DelegationCache struct {
	c  map[string][]Server
	mu sync.Mutex
}

// Get returns the most specific name servers for domain with its matching label.
func (d *DelegationCache) Get(domain string) (label string, servers []Server) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for offset, end := 0, false; !end; offset, end = dns.NextLabel(domain, offset) {
		label = domain[offset:]
		var found bool
		if servers, found = d.c[label]; found {
			return
		}
	}
	return ".", roots
}

// Add adds a server as a delegation for domain. If addrs is not specified,
// server will be looked up. An error is returned in case of lookup error.
func (d *DelegationCache) Add(domain string, s Server) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, s2 := range d.c[domain] {
		if s2.Name == s.Name {
			return nil
		}
	}
	if d.c == nil {
		d.c = map[string][]Server{}
	}
	d.c[domain] = append(d.c[domain], s)
	return nil
}

// LookupCache stores mixed lookup results for A and AAAA records of labels with
// not support of TTL.
type LookupCache struct {
	c  map[string][]string
	mu sync.Mutex
}

func (c *LookupCache) Set(label string, addrs []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.c == nil {
		c.c = map[string][]string{}
	}
	c.c[strings.ToLower(label)] = addrs
}

func (c *LookupCache) Get(label string) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.c[strings.ToLower(label)]
}
