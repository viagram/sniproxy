package main

import (
	"net/http"
	"strconv"
	"time"
)

func DoH_Start() {
	var (
		err				error
		httpsService	*http.Server
		httpHandler	=	new(HTTPHandler)
	)

	go func() {
		if c.DoHPort < 1 {
			log.Error("[DoH] DoH is disabled because the DoHPort parameter is not configured", err)
			return
		}
		if c.DNSQueryPath == "" && c.JSONQueryPath == "" {
			log.Error("[DoH] DoH is disabled, as none of the features that depend on DoH are enabled", err)
			return
		}
		httpsService = &http.Server{
			Addr:	c.BindIP + ":" + strconv.FormatUint(uint64(c.DoHPort), 10),
			Handler: httpHandler,
		}
		dnslog.Info("Started DoH DNS", "host", "0.0.0.0", "port", c.DoHPort)
		if err = httpsService.ListenAndServeTLS(c.TLSCert, c.TLSKey); err != nil {
			if err.Error() != http.ErrServerClosed.Error() {
				log.Error("Failed to enable DoH", err)
			}
			return
		}
	}()

	if c.HTTPPort > 0 || c.DoHPort > 0 {
		if c.DNSQueryPath != "" {
			log.Info("[DoH] DoH Query Path", "Path", c.DNSQueryPath)
		}
		if c.JSONQueryPath != "" {
			log.Info("[DoH] DoH JSON Query Path", "Path", c.JSONQueryPath)
		}
	}

	<-time.After(30 * time.Second)
}
