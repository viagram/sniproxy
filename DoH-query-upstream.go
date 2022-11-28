package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type RR struct {
	Name string `json:"name"`
	Type uint16 `json:"type"`
	TTL  uint32 `json:"TTL"`
	Data string `json:"data"`
}

type JSONResult struct {
	Status	uint16 `json:"Status"`
	TC		bool   `json:"TC"`
	RD		bool   `json:"RD"`
	RA		bool   `json:"RA"`
	AD		bool   `json:"AD"`
	CD		bool   `json:"CD"`
	Question  []RR   `json:"Question"`
	Answer	[]RR   `json:"Answer,omitempty"`
	Authority []RR   `json:"Authority,omitempty"`
	Extra	 []RR   `json:"Extra,omitempty"`
}

type Upstream struct {
	MethodByDoT string
	ReqMsg	  *dns.Msg
}

// 遍历上游进行查询
func (upstream *Upstream) Query() (respMsg *dns.Msg, err error) {
	var abort bool

	// 遍历查询上游服务
	for k := range c.DnsList {
		if abort {
			break
		}
		switch {
		case strings.HasPrefix(c.DnsList[k], "udp://"):
			upstreamAddr := strings.TrimPrefix(c.DnsList[k], "udp://")
			respMsg, err = upstream.QueryDNS("udp", upstreamAddr)
			if err != nil {
				log.Error("向上游UDP服务查询失败", err, "addr", c.DnsList[k])
				break
			}
			abort = true
		case strings.HasPrefix(c.DnsList[k], "tcp://"):
			upstreamAddr := strings.TrimPrefix(c.DnsList[k], "tcp://")
			respMsg, err = upstream.QueryDNS("tcp", upstreamAddr)
			if err != nil {
				log.Error("向上游TCP服务查询失败", err, "addr", c.DnsList[k])
				break
			}
			abort = true
		case strings.HasPrefix(c.DnsList[k], "tls://"):
			upstreamAddr := strings.TrimPrefix(c.DnsList[k], "tls://")
			respMsg, err = upstream.QueryDNS("tcp-tls", upstreamAddr)
			if err != nil {
				log.Error("向上游DoT服务查询失败", err, "addr", c.DnsList[k])
				break
			}
			abort = true
		case strings.HasPrefix(c.DnsList[k], "https://"):
			if upstream.MethodByDoT == http.MethodGet {
				respMsg, err = upstream.QueryByGET(c.DnsList[k], c.HTTPProxy)
			} else {
				respMsg, err = upstream.QueryByPOST(c.DnsList[k], c.HTTPProxy)
			}
			if err != nil {
				log.Error("向上游DoH服务查询失败", err, "addr", c.DnsList[k])
				break
			}
			abort = true
		default:
			err = errors.New("不支持的上游服务协议 " + c.DnsList[k])
		}
	}
	return
}

// 查询上游的DNS over UDP/TCP服务
func (upstream *Upstream) QueryDNS(netType string, addr string) (respMsg *dns.Msg, err error) {
	var (
		dnsReq = dns.Client{
			Timeout: 5 * time.Second,
			Net:	 netType,
		}
	)

	if netType == "tcp-tls" {
		dnsReq.TLSConfig = &tls.Config{InsecureSkipVerify: true} // nolint:gosec
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// 向上游发起请求
	respMsg, _, err = dnsReq.ExchangeContext(ctx, upstream.ReqMsg, addr)
	if err != nil {
		log.Error("请求上游DNS服务失败", err, "net", netType, "addr", addr)
		return
	}
	return
}

// DNS over TLS
func (upstream *Upstream) QueryTLS(addr string, tlsConfig *tls.Config) (respMsg *dns.Msg, err error) {
	dnsReq := dns.Client{
		Timeout: 5 * time.Second,
		Net:	 "tcp-tls",
	}

	if tlsConfig == nil {
		dnsReq.TLSConfig = &tls.Config{InsecureSkipVerify: true} // nolint:gosec
	} else {
		dnsReq.TLSConfig = tlsConfig
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// 向上游发起请求
	respMsg, _, err = dnsReq.ExchangeContext(ctx, upstream.ReqMsg, addr)
	if err != nil {
		log.Error("向上游DoT服务查询失败", err, "addr", addr)
		return
	}
	return
}

// DNS over HTTPS GET /dns-query
func (upstream *Upstream) QueryByGET(addr string, proxy string) (respMsg *dns.Msg, err error) {
	var (
		httpClient http.Client
		httpReq	*http.Request
		httpResp   *http.Response
		dnsParam   string
		reqMsgBuf  []byte
		respMsgBuf []byte
		proxyURL   *url.URL
	)
	respMsg = new(dns.Msg)

	// 设置代理
	if proxy != "" {
		proxyURL, err = url.Parse(proxy)
		if err != nil {
			log.Error("无效的HTTP代理地址", err)
			return
		}
		httpClient.Transport = &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 将请求消息体转为[]byte
	reqMsgBuf, err = upstream.ReqMsg.Pack()
	if err != nil {
		log.Error("构建请求消息失败", err)
		return
	}
	dnsParam = base64.RawURLEncoding.EncodeToString(reqMsgBuf)

	httpReq, err = http.NewRequestWithContext(ctx, http.MethodGet, addr, nil)
	if err != nil {
		log.Error("请求DoT服务失败", err, "url", addr)
		return
	}
	values := make(url.Values, 1)
	values.Set("dns", dnsParam)
	httpReq.URL.RawQuery = values.Encode()
	httpResp, err = httpClient.Do(httpReq)
	if err != nil {
		log.Error("请求上游DoT服务失败", err, "name", upstream.ReqMsg.Question[0].Name, "type", dns.TypeToString[upstream.ReqMsg.Question[0].Qtype], "addr", addr)
		return
	}
	defer func() {
		if err = httpResp.Body.Close(); err != nil {
			log.Error("关闭Body失败", err)
		}
	}()
	if httpResp.StatusCode != 200 {
		log.Error("收到错误响应", err, "statusCode", httpResp.StatusCode, "respStatus", httpResp.Status, "addr", addr)
		err = errors.New("收到错误响应：" + httpResp.Status)
		return
	}
	respMsgBuf, err = ioutil.ReadAll(httpResp.Body)
	if err != nil {
		log.Error("读取DoT服务响应数据失败", err)
		return
	}
	err = respMsg.Unpack(respMsgBuf)
	return
}

// DNS over HTTPS POST /dns-query
func (upstream *Upstream) QueryByPOST(addr string, proxy string) (respMsg *dns.Msg, err error) {
	var (
		httpClient http.Client
		httpReq	*http.Request
		httpResp   *http.Response
		reqBody	[]byte
		respBody   []byte
		proxyURL   *url.URL
	)
	respMsg = new(dns.Msg)

	// 设置代理
	if proxy != "" {
		proxyURL, err = url.Parse(proxy)
		if err != nil {
			log.Error("无效的HTTP代理地址", err)
			return
		}
		httpClient.Transport = &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 将请求消息体转为[]byte
	reqBody, err = upstream.ReqMsg.Pack()
	if err != nil {
		log.Error("构建请求消息失败", err)
		return
	}

	httpReq, err = http.NewRequestWithContext(ctx, http.MethodPost, addr, bytes.NewBuffer(reqBody))
	if err != nil {
		log.Error("请求DoT服务失败", err, "url", addr)
		return
	}
	httpReq.Header.Set("Content-Type", "application/dns-message")
	httpReq.Header.Set("accept", "application/dns-message")
	httpResp, err = httpClient.Do(httpReq)
	if err != nil {
		log.Error("请求上游服务失败", err, "name", upstream.ReqMsg.Question[0].Name, "type", dns.TypeToString[upstream.ReqMsg.Question[0].Qtype], "addr", addr)
		return
	}
	defer func() {
		if err = httpResp.Body.Close(); err != nil {
			log.Error("关闭Body失败", err)
		}
	}()
	if httpResp.StatusCode != 200 {
		log.Error("收到错误响应", err, "statusCode", httpResp.StatusCode, "respStatus", httpResp.Status, "addr", addr)
		err = errors.New("收到错误响应：" + httpResp.Status)
		return
	}
	respBody, err = ioutil.ReadAll(httpResp.Body)
	if err != nil {
		log.Error("读取DoT服务响应数据失败", err)
		return
	}
	err = respMsg.Unpack(respBody)
	return
}
