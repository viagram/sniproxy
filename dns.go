package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"strconv"
	"sync"
	"time"

	"github.com/golang-collections/collections/tst"
	"github.com/mosajjal/dnsclient"
	doqserver "github.com/mosajjal/doqd/pkg/server"
	slog "golang.org/x/exp/slog"

	"github.com/miekg/dns"
)

type DNSClient struct {
	C dnsclient.Client
}

var (
	matchPrefix = uint8(1)
	matchSuffix = uint8(2)
	matchFQDN   = uint8(3)
)
var dnsLock sync.RWMutex

var dnslog = slog.New(log.Handler().WithAttrs([]slog.Attr{{Key: "service", Value: slog.StringValue("dns")}}))

// inDomainList returns true if the domain is meant to be SKIPPED and not go through sni proxy
func inDomainList(fqdn string) bool {
	fqdnLower := strings.ToLower(fqdn)
	// check for fqdn match
	if c.routeFQDNs[fqdnLower] == matchFQDN {
		return false
	}
	// check for prefix match
	if longestPrefix := c.routePrefixes.GetLongestPrefix(fqdnLower); longestPrefix != nil {
		// check if the longest prefix is present in the type hashtable as a prefix
		if c.routeFQDNs[longestPrefix.(string)] == matchPrefix {
			return false
		}
	}
	// check for suffix match. Note that suffix is just prefix reversed
	if longestSuffix := c.routeSuffixes.GetLongestPrefix(reverse(fqdnLower)); longestSuffix != nil {
		// check if the longest suffix is present in the type hashtable as a suffix
		if c.routeFQDNs[longestSuffix.(string)] == matchSuffix {
			return false
		}
	}
	return true
}

func reverse(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < len(r)/2; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

// LoadDomainsCsv loads a domains Csv file/URL. returns 3 parameters:
// 1. a TST for all the prefixes (type 1)
// 2. a TST for all the suffixes (type 2)
// 3. a hashtable for all the full match fqdn (type 3)
func LoadDomainsCsv(Filename string) (*tst.TernarySearchTree, *tst.TernarySearchTree, map[string]uint8, error) {
	prefix := tst.New()
	suffix := tst.New()
	all := make(map[string]uint8)
	dnslog.Info("Loading the domain from file/url")
	var scanner *bufio.Scanner
	if strings.HasPrefix(Filename, "http://") || strings.HasPrefix(Filename, "https://") {
		dnslog.Info("domain list is a URL, trying to fetch")
		client := http.Client{
			CheckRedirect: func(r *http.Request, via []*http.Request) error {
				r.URL.Opaque = r.URL.Path
				return nil
			},
		}
		resp, err := client.Get(Filename)
		if err != nil {
			dnslog.Error("", err)
			return prefix, suffix, all, err
		}
		dnslog.Info("(re)fetching URL: ", Filename)
		defer resp.Body.Close()
		scanner = bufio.NewScanner(resp.Body)

	} else {
		file, err := os.Open(Filename)
		if err != nil {
			return prefix, suffix, all, err
		}
		dnslog.Info("(re)loading File: " + Filename)
		defer file.Close()
		scanner = bufio.NewScanner(file)
	}

	for scanner.Scan() {
		lowerCaseLine := strings.ToLower(scanner.Text())
		// split the line by comma to understand thednslog.c
		fqdn := strings.Split(lowerCaseLine, ",")
		if len(fqdn) != 2 {
			dnslog.Info(lowerCaseLine + " is not a valid line, assuming FQDN")
			fqdn = []string{lowerCaseLine, "fqdn"}
		}
		// add the fqdn to the hashtable with its type
		switch entryType := fqdn[1]; entryType {
		case "prefix":
			all[fqdn[0]] = matchPrefix
			prefix.Insert(fqdn[0], fqdn[0])
		case "suffix":
			all[fqdn[0]] = matchSuffix
			// suffix match is much faster if we reverse the strings and match for prefix
			suffix.Insert(reverse(fqdn[0]), fqdn[0])
		case "fqdn":
			all[fqdn[0]] = matchFQDN
		default:
			//dnslog.Warnf("%s is not a valid line, assuming fqdn", lowerCaseLine)
			dnslog.Info(lowerCaseLine + " is not a valid line, assuming FQDN")
			all[fqdn[0]] = matchFQDN
		}
	}
	dnslog.Info(fmt.Sprintf("%s loaded with %d prefix, %d suffix and %d fqdn", Filename, prefix.Len(), suffix.Len(), len(all)-prefix.Len()-suffix.Len()))

	return prefix, suffix, all, nil
}

func (dnsc *DNSClient) performExternalAQuery(fqdn string) ([]dns.RR, time.Duration, error) {
	if !strings.HasSuffix(fqdn, ".") {
		fqdn = fqdn + "."
	}

	msg := dns.Msg{}
	msg.RecursionDesired = true
	msg.SetQuestion(fqdn, dns.TypeA)
	msg.SetEdns0(1232, true)
	dnsLock.Lock()
	if dnsc.C == nil {
		return nil, 0, fmt.Errorf("DNS client is not initialised")
	}
	res, trr, err := dnsc.C.Query(context.Background(), &msg)
	if err != nil {
		if err.Error() == "EOF" {
			dnslog.Info("reconnecting DNS...")
			// dnsc.C.Close()
			// dnsc.C, err = dnsclient.New(c.UpstreamDNS, true)
			err = c.dnsClient.C.Reconnect()
		}
	}
	dnsLock.Unlock()
	return res, trr, err
}

func processQuestion(q dns.Question) ([]dns.RR, error) {
	c.recievedDNS.Inc(1)
	if c.AllDomains || !inDomainList(q.Name) {
		c.proxiedDNS.Inc(1)
		// Return the public IP.
		rr, err := dns.NewRR(fmt.Sprintf("%s A %s", q.Name, c.PublicIP))
		if err != nil {
			return nil, err
		}

		dnslog.Info("returned sniproxy address for domain", "fqdn", q.Name)

		return []dns.RR{rr}, nil
	}

	// Otherwise do an upstream query and use that answer.
	resp, rtt, err := c.dnsClient.performExternalAQuery(q.Name)
	if err != nil {
		return nil, err
	}

	dnslog.Info("[DNS] returned origin address", "fqdn", q.Name, "rtt", rtt)

	return resp, nil
}

func (dnsc DNSClient) lookupDomain4(domain string) (net.IP, error) {
	if !strings.HasSuffix(domain, ".") {
		domain = domain + "."
	}
	rAddrDNS, _, err := dnsc.performExternalAQuery(domain)
	if err != nil {
		return nil, err
	}
	if len(rAddrDNS) > 0 {
		if rAddrDNS[0].Header().Rrtype == dns.TypeCNAME {
			return dnsc.lookupDomain4(rAddrDNS[0].(*dns.CNAME).Target)
		}
		if rAddrDNS[0].Header().Rrtype == dns.TypeA {
			return rAddrDNS[0].(*dns.A).A, nil
		}
	} else {
		return nil, fmt.Errorf("[DNS] Empty DNS response for %s with error %s", domain, err)
	}
	return nil, fmt.Errorf("[DNS] Unknown type %s", dns.TypeToString[rAddrDNS[0].Header().Rrtype])
}

func handleDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false


	m2 := m.String()
	matchNetflix, _ := regexp.MatchString("nflx|netflix|fast.com", m2)
	matchDisney, _ := regexp.MatchString("20thcenturystudios.com.au|20thcenturystudios.com.br|20thcenturystudios.jp|abc.com|abc-studios.com|adobedtm.com|adventuresbydisney.com|babble.com|babyzone.com|bamgrid.com|beautyandthebeastmusical.co.uk|braze.com|cdn.optimizely.com|conviva.com|d9.flashtalking.com|demdex.net|dilcdn.com|disney.asia|disney.be|disney.bg|disney.ca|disney.ch|disney.com|disney.com.au|disney.com.br|disney.com.hk|disney.com.tw|disney.co.il|disney.co.jp|disney.co.kr|disney.co.th|disney.co.uk|disney.co.za|disney.cz|disney.de|disney.dk|disney.es|disney.fi|disney.fr|disney.gr|disney.hu|disney.id|disney.in|disney.io|disney.it|disney.my|disney.nl|disney.no|disney.ph|disney.pl|disney.pt|disney.ro|disney.ru|disney.se|disney.sg|disneyadsales.com|disneyarena.com|disneyaulani.com|disneybaby.com|disneycareers.com|disneychannelonstage.com|disneychannelroadtrip.com|disneycruisebrasil.com|disneyenconcert.com|disneyiejobs.com|disneyinflight.com|disneyinternational.com|disneyinternationalhd.com|disneyjunior.com|disneyjuniortreataday.com|disneylatino.com|disneymagicmoments.co.il|disneymagicmoments.co.uk|disneymagicmoments.co.za|disneymagicmoments.de|disneymagicmoments.es|disneymagicmoments.fr|disneymagicmoments.gen.tr|disneymagicmoments.gr|disneymagicmoments.it|disneymagicmoments.pl|disneymagicmomentsme.com|disneyme.com|disneymeetingsandevents.com|disneymovieinsiders.com|disneymusicpromotion.com|disneynewseries.com|disneynow.com|disneypeoplesurveys.com|disneyplus.bn5x.net|disneyplus.com|disneyredirects.com|disneysrivieraresort.com|disneystore.com|disneystreaming.com|disneysubscription.com|disneytickets.co.uk|disneyturkiye.com.tr|disneytvajobs.com|disney-asia.com|disney-discount.com|disney-plus.net|disney-portal.my.onetrust.com|disney-studio.com|disney-studio.net|dmed.technology|dssott.com|dssott.com.akamaized.net|dtci.co|dtci.technology|edgedatg.com|espn.com|espn.co.uk|espn.net|espncdn.com|espnqa.com|execute-api.us-east-1.amazonaws.com|go.com|go-mpulse.net|js-agent.newrelic.com|marvel.com|marvel10thanniversary.com|marveldimensionofheroes.com|marvelparty.net|marvelpinball.com|marvelsdoubleagent.com|marvelspotlightplays.com|marvelsuperheroseptember.com|marvelsuperwar.com|mickey.tv|moviesanywhere.com|natgeomaps.com|nationalgeographic.com|nationalgeographicpartners.com|ngeo.com|nomadlandmovie.ch|nr-data.net|omtrdc.net|optimizely.com|playmation.com|sentry.io|shopdisney.com|shops-disney.com|sorcerersarena.com|spaindisney.com|starwars.com|starwarsgalacticstarcruiser.com|starwarskids.com|star-brasil.com|star-latam.com|streamingdisney.net|themarvelexperiencetour.com|thestationbymaker.com|thisispolaris.com|watchdisneyfe.com|watchespn.com", m2)
	if matchDisney {
		c.PublicIP = c.DisneyIP
	}else if matchNetflix {
		c.PublicIP = c.NetflixIP
	}

	if r.Opcode != dns.OpcodeQuery {
		m.SetRcode(r, dns.RcodeNotImplemented)
		w.WriteMsg(m)
		return
	}

	for _, q := range m.Question {
		answers, err := processQuestion(q)
		if err != nil {
			dnslog.Error("", err)
			continue
		}
		m.Answer = append(m.Answer, answers...)
	}

	w.WriteMsg(m)
}

func runDnsOverUDP(port uint) {
	serverUDP := &dns.Server{Addr: fmt.Sprintf(":%d", port), Net: "udp"}
	dnslog.Info("Started UDP DNS", "host", "0.0.0.0", "port", port)
	err := serverUDP.ListenAndServe()
	defer serverUDP.Shutdown()
	if err != nil {
		dnslog.Error("Error starting UDP DNS server", err)
		dnslog.Info(fmt.Sprintf("Failed to start server: %s\nYou can run the following command to pinpoint which process is listening on port %d\nsudo ss -pltun -at '( dport = :%d or sport = :%d )'", err.Error(), port, port, port))
		panic(2)
	}
}

func runDnsOverTCP(port uint) {
	serverTCP := &dns.Server{Addr: fmt.Sprintf(":%d", port), Net: "tcp"}
	dnslog.Info("Started TCP DNS", "host", "0.0.0.0", "port", port)
	err := serverTCP.ListenAndServe()
	defer serverTCP.Shutdown()
	if err != nil {
		dnslog.Error("Failed to start server", err)
		dnslog.Info(fmt.Sprintf("You can run the following command to pinpoint which process is listening on port %d\nsudo ss -pltun -at '( dport = :%d or sport = :%d )'", port, port, port))
	}
}

func runDnsOverTLS(port uint) {
	crt, err := tls.LoadX509KeyPair(c.TLSCert, c.TLSKey)
	if err != nil {
		dnslog.Error("", err)
		panic(2)
	}
	tlsConfig := &tls.Config{}
	tlsConfig.Certificates = []tls.Certificate{crt}
	serverTLS := &dns.Server{Addr: ":" + strconv.FormatUint(uint64(port), 10), Net: "tcp-tls", TLSConfig: tlsConfig}
	dnslog.Info("Started DoT DNS", "host", "0.0.0.0", "port", port)
	err = serverTLS.ListenAndServe()
	defer serverTLS.Shutdown()
	if err != nil {
		dnslog.Error("", err)
	}
}

func runDnsOverQUIC(port uint) {
	crt, err := tls.LoadX509KeyPair(c.TLSCert, c.TLSKey)
	if err != nil {
		dnslog.Error("", err)
	}
	tlsConfig := &tls.Config{}
	tlsConfig.Certificates = []tls.Certificate{crt}

	// Create the QUIC listener
	doqServer, err := doqserver.New(":" + strconv.FormatUint(uint64(port), 10), crt, "127.0.0.1:53", true)
	if err != nil {
		dnslog.Error("", err)
	}

	// Accept QUIC connections
	dnslog.Info("Starting QUIC listener on :" + strconv.FormatUint(uint64(port), 10))
	go doqServer.Listen()
}

func runDNS() {
	dns.HandleFunc(".", handleDNS)
	// start DNS UDP serverUdp
	go func() {
		runDnsOverUDP(c.DNSPort)
	}()
	go func() {
		runDnsOverUDP(20223)
	}()

	// start DNS UDP serverTcp
	if c.BindDNSOverTCP {
		go func() {
			runDnsOverTCP(c.DNSPort)
		}()
		go func() {
			runDnsOverTCP(20223)
		}()
	}

	// start DNS UDP serverTls
	if c.BindDNSOverTLS {
		go func() {
			runDnsOverTLS(853)
		}()
		go func() {
			runDnsOverTLS(8853)
		}()
	}

	if c.BindDNSOverQuic {
		go func() {
			runDnsOverQUIC(853)
		}()
		go func() {
			runDnsOverQUIC(8853)
		}()
	}

	// start DNS HTTPS serverTCP
	if c.BindDnsOverHttps {
		go func() {
			DoH_Start()
		}()
	}
}
