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
	domain = strings.ToLower(domain)
	for offset, end := 0, false; !end; offset, end = dns.NextLabel(domain, offset) {
		label = domain[offset:]
		var found bool
		if _, found = d.c[label]; found {
			return label, append(servers, d.c[label]...)
		}
	}
	return ".", append(servers, roots...)
}

// Add adds a server as a delegation for domain. If addrs is not specified,
// server will be looked up. Returns false if already there
func (d *DelegationCache) Add(domain string, server Server) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	domain = strings.ToLower(domain)
	for _, s2 := range d.c[domain] {
		if domainEqual(s2.Name, server.Name) {
			return false
		}
	}
	if d.c == nil {
		d.c = map[string][]Server{}
	}
	d.c[domain] = append(d.c[domain], server)
	return true
}

// AddressAttempt stores resolved address and retry count if it's unresolved
type AddressAttempt struct {
	Addresss   []string
	RetryCount uint8
}

// LookupCache stores mixed lookup results for A and AAAA records of labels with
// not support of TTL.
type LookupCache struct {
	c  map[string]AddressAttempt
	mu sync.Mutex
}

// IncAttempt increase attempt to recursive resolve the address
func (c *LookupCache) IncAttempt(label string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.c == nil {
		c.c = map[string]AddressAttempt{}
	}
	key := strings.ToLower(label)
	aa := c.c[key]
	if len(aa.Addresss) == 0 {
		aa.RetryCount++
		c.c[key] = aa
	}
}
func (c *LookupCache) Set(label string, addrs []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.c == nil {
		c.c = map[string]AddressAttempt{}
	}
	key := strings.ToLower(label)
	if len(addrs) == 0 {
		aa := c.c[key]
		if len(aa.Addresss) == 0 {
			aa.RetryCount++
			c.c[key] = aa
		}
		return
	}
	c.c[key] = AddressAttempt{Addresss: addrs, RetryCount: 1}
}

// Get retrieve the saved address or the attempt
func (c *LookupCache) Get(label string) AddressAttempt {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.c[strings.ToLower(label)]
}
