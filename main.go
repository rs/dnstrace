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
	qname := ""
	qtype := dns.TypeA
	for _, arg := range flag.Args() {
		if t, found := dns.StringToType[arg]; found {
			qtype = t
			continue
		}
		if qname != "" {
			flag.Usage()
			os.Exit(1)
		}
		qname = dns.Fqdn(arg)
	}

	col := func(s interface{}, c int) string {
		return colorize(s, c, *color)
	}

	m := &dns.Msg{}
	m.SetQuestion(qname, qtype)
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

	c := client.New()
	c.Client.Timeout = 500 * time.Millisecond
	t := client.Tracer{
		GotDelegateResponses: func(i int, m *dns.Msg, rs client.Responses, rtype client.ResponseType) {
			fr := rs.Fastest()
			var r *dns.Msg
			if fr != nil {
				r = fr.Msg
			}
			qname := m.Question[0].Name
			qtype := dns.TypeToString[m.Question[0].Qtype]
			if i > 1 {
				fmt.Println()
			}
			fmt.Printf("%d - query %s %s", i, qtype, qname)
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
				lrtt := float64(pr.Server.LookupRTT) / float64(time.Millisecond)
				fmt.Printf(col("  - %3d bytes in %6.2fms + %6.2fms on %s(%s)", cDarkGray), ln, rtt, lrtt, pr.Addr, pr.Server.Name)
				if pr.Err != nil {
					err := pr.Err
					if oerr, ok := err.(*net.OpError); ok {
						err = oerr.Err
					}
					fmt.Printf(": %v", col(err, cRed))
				}
				fmt.Print("\n")
			}

			if rtype == client.ResponseTypeDelegation {
				var label string
				for _, rr := range r.Ns {
					if ns, ok := rr.(*dns.NS); ok {
						label = ns.Header().Name
						break
					}
				}
				_, ns := c.DCache.Get(label)
				for _, s := range ns {
					var glue string
					if s.HasGlue {
						glue = col("glue: "+strings.Join(s.Addrs, ","), cDarkGray)
					} else {
						glue = col("no glue", cYellow)
						if s.LookupErr != nil {
							glue += fmt.Sprintf(col(": lookup err: %v", cDarkGray), col(s.LookupErr, cRed))
						} else if s.LookupRTT == 0 {
							glue += fmt.Sprintf(col(": lookup from cache", cDarkGray))
						} else {
							glue += fmt.Sprintf(col(": lookup time: %s", cDarkGray), s.LookupRTT)
						}
					}
					fmt.Printf("%s %d NS %s (%s)\n", label, s.TTL, s.Name, glue)
				}
			}
		},
		FollowingCNAME: func(domain, target string) {
			fmt.Printf(col("\n~ following CNAME %s -> %s\n", cBlue), domain, target)
		},
	}
	r, rtt, err := c.RecursiveQuery(m, t)
	if err != nil {
		fmt.Printf(col("*** error: %v\n", cRed), err)
		os.Exit(1)
	}

	fmt.Println()
	fmt.Printf(col(";; Cold best path time: %s\n\n", cGray), rtt)
	for _, rr := range r.Answer {
		fmt.Println(rr)
	}
}
