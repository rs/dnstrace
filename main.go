package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/rs/dnstrace/client"
)

const (
	cReset    = 0
	cBold     = 1
	cRed      = 31
	cGreen    = 32
	cYellow   = 33
	cBlue     = 34
	cMagenta  = 35
	cCyan     = 36
	cGray     = 37
	cDarkGray = 90
)

func colorize(s interface{}, color int, enabled bool) string {
	if !enabled {
		return fmt.Sprintf("%v", s)
	}
	return fmt.Sprintf("\x1b[%dm%v\x1b[0m", color, s)
}

func init() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: dnstrace [qtype] <domain>\n\n")
		flag.PrintDefaults()
	}
}

func main() {
	color := flag.Bool("color", true, "Enable/disable colors")
	flag.Parse()

	if len(os.Args) < 2 || len(os.Args) > 3 {
		flag.Usage()
		os.Exit(1)
	}
	name := ""
	rtype := dns.TypeA
	for _, arg := range flag.Args() {
		if t, found := dns.StringToType[arg]; found {
			rtype = t
			continue
		}
		if name != "" {
			flag.Usage()
			os.Exit(1)
		}
		name = dns.Fqdn(arg)
	}

	c := &client.Client{}
	delegs := client.DelegationCache{}
	col := func(s interface{}, c int) string {
		return colorize(s, c, *color)
	}

	m := &dns.Msg{}
	// Set DNSSEC opt to better emulate the default queries from a nameserver.
	o := &dns.OPT{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeOPT,
		},
	}
	o.SetDo()
	o.SetUDPSize(dns.DefaultMsgSize)
	m.Extra = append(m.Extra, o)

	for i := 1; i < 100; i++ {
		deleg, servers := delegs.Get(name)
		m.SetQuestion(name, rtype)
		rs := c.ParallelQuery(m, servers)
		fr := rs.Fastest()
		var r *dns.Msg
		if fr != nil {
			r = fr.Msg
		}
		if i > 1 {
			fmt.Println()
		}
		fmt.Printf("%d - query %s %s", i, dns.TypeToString[rtype], name)
		if r != nil {
			fmt.Printf(": %s", strings.Replace(strings.Replace(r.MsgHdr.String(), ";; ", "", -1), "\n", ", ", -1))
		}
		fmt.Println()
		for _, pr := range rs {
			ln := 0
			if pr.Msg != nil {
				ln = pr.Msg.Len()
			}
			rtt := float64(pr.RTT) / float64(time.Millisecond)
			fmt.Printf(col("  -%4d bytes in %6.2fms on %s(%s)", cDarkGray), ln, rtt, pr.Addr, pr.Server)
			if pr.Err != nil {
				err := pr.Err
				if oerr, ok := err.(*net.OpError); ok {
					err = oerr.Err
				}
				fmt.Printf(": %v", col(err, cRed))
			}
			fmt.Print("\n")
		}

		if r == nil {
			os.Exit(1)
		}

		for _, ns := range r.Ns {
			ns, ok := ns.(*dns.NS)
			if !ok {
				continue // skip DS records
			}
			var addrs []string
			for _, rr := range r.Extra {
				if a, ok := rr.(*dns.A); ok && a.Hdr.Name == ns.Ns {
					addrs = append(addrs, a.A.String())
				}
			}
			rtt, err := delegs.Add(ns.Header().Name, ns.Ns, addrs)
			glue := strings.Join(addrs, ",")
			if glue == "" {
				glue = col("no glue", cYellow)
				if err != nil {
					glue += fmt.Sprintf(col(": lookup err: %v", cDarkGray), col(err, cRed))
				} else if rtt == 0 {
					glue += fmt.Sprintf(col(": cached", cDarkGray))
				} else {
					glue += fmt.Sprintf(col(": lookup time: %s", cDarkGray), rtt)
				}
			}
			fmt.Printf("%s %d NS %s (%s)\n", ns.Header().Name, ns.Header().Ttl, ns.Ns, glue)
		}

		if len(r.Answer) > 0 {
			var cname string
			fmt.Println()
			for _, rr := range r.Answer {
				if rr.Header().Rrtype == dns.TypeCNAME {
					cname = rr.Header().Name
					name = rr.(*dns.CNAME).Target
				} else {
					fmt.Println(rr)
				}
			}
			if cname != "" {
				fmt.Printf(col("~ following CNAME %s -> %s\n", cBlue), cname, name)
				continue
			}
			break
		}

		if label, _ := delegs.Get(name); len(r.Ns) == 0 || deleg == label {
			break
		}
	}
}
