package main

import (
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/miekg/dns"
)

type HTTPHandler struct {
	resp http.ResponseWriter
	req  *http.Request
}

func (hh HTTPHandler) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	hh.resp = resp
	hh.req = req

	switch req.URL.Path {
	case c.DNSQueryPath:
		if c.DNSQueryPath == "" {
			break
		}
		if req.Method == http.MethodGet {
			hh.dnsQueryByGET()
			break
		} else if req.Method == http.MethodPost {
			hh.dnsQueryByPOST()
			break
		}
		hh.respStatus(http.StatusMethodNotAllowed, "")
	case c.JSONQueryPath:
		if c.JSONQueryPath == "" {
			break
		}
		if req.Method != http.MethodGet {
			hh.respStatus(http.StatusMethodNotAllowed, "")
			break
		}
		hh.jsonQueryHandler()
	default:
		hh.respStatus(http.StatusNotFound, "")
	}
}

func (hh *HTTPHandler) respStatus(status int, message string) {
	hh.resp.WriteHeader(status)
	if status == http.StatusNoContent {
		return
	}
	if message == "" {
		message = http.StatusText(status)
	}
	_, err := hh.resp.Write(StrToBytes(message))
	if err != nil {
		log.Warn("响应数据时出错", err, "status", status)
	}
}

// -> GET /dns-query -> dns.Msg
func (hh *HTTPHandler) dnsQueryByGET() {
	var (
		err		error
		param	  string
		paramBytes []byte
		reqMsg	 dns.Msg
		respMsg	*dns.Msg
		respData   []byte
	)

	if c.DNSQueryAuth && hh.req.Header.Get("Authorization") != c.Authorization {
		hh.respStatus(http.StatusUnauthorized, "")
		return
	}

	defer func() {
		if hh.req.Body != nil {
			err = hh.req.Body.Close()
			if err != nil {
				log.Warn("",err)
			}
		}
	}()

	param = hh.req.URL.Query().Get("dns")
	paramBytes, err = base64.RawURLEncoding.DecodeString(param)
	if err != nil {
		log.Error("解析dns参数值失败", err)
		hh.respStatus(http.StatusBadRequest, "Invalid 'dns' parameter")
		return
	}
	err = reqMsg.Unpack(paramBytes)
	if err != nil {
		log.Error("解析dns参数值失败", err)
		hh.respStatus(http.StatusBadRequest, "Invalid 'dns' parameter")
		return
	}

	if reqMsg.Question[0].Name == "" {
		hh.respStatus(http.StatusBadRequest, "Invalid question parameter: 'name'")
		return
	}
	if reqMsg.Question[0].Qtype == 0 {
		hh.respStatus(http.StatusBadRequest, "Invalid question parameter: 'type'")
		return
	}
	if !strings.HasSuffix(reqMsg.Question[0].Name, ".") {
		reqMsg.Question[0].Name += "."
	}

	// 查询上游服务
	upstream := Upstream{
		ReqMsg:	  &reqMsg,
		MethodByDoT: hh.req.Method,
	}
	respMsg, err = upstream.Query()
	if err != nil {
		log.Error("查询上游服务失败", err)
		hh.respStatus(http.StatusInternalServerError, "")
		return
	}

	respData, err = respMsg.Pack()
	if err != nil {
		log.Error("编码响应数据失败", err)
		hh.respStatus(http.StatusInternalServerError, "")
		return
	}

	_, err = hh.resp.Write(respData)
	if err != nil {
		log.Warn("响应数据时出错", err)
	}
}

// -> POST /dns-query -> dns.Msg
func (hh *HTTPHandler) dnsQueryByPOST() {
	var (
		err	  error
		body	 []byte
		respData []byte
		reqMsg   dns.Msg
		respMsg  *dns.Msg
	)

	if c.DNSQueryAuth && hh.req.Header.Get("Authorization") != c.Authorization {
		hh.respStatus(http.StatusUnauthorized, "")
		return
	}

	defer func() {
		if hh.req.Body != nil {
			err = hh.req.Body.Close()
			if err != nil {
				log.Warn("",err)
			}
		}
	}()

	body, err = ioutil.ReadAll(hh.req.Body)
	if err != nil {
		hh.respStatus(http.StatusBadRequest, "Invalid HTTP body data")
		return
	}

	err = reqMsg.Unpack(body)
	if err != nil {
		hh.respStatus(http.StatusBadRequest, "Invalid HTTP body data")
		return
	}

	if !strings.HasSuffix(reqMsg.Question[0].Name, ".") {
		reqMsg.Question[0].Name += "."
	}

	// 查询上游服务
	upstream := Upstream{
		ReqMsg:	  &reqMsg,
		MethodByDoT: hh.req.Method,
	}
	respMsg, err = upstream.Query()
	if err != nil {
		log.Error("查询上游服务失败", err)
		hh.respStatus(http.StatusInternalServerError, "")
		return
	}

	respData, err = respMsg.Pack()
	if err != nil {
		log.Error("编码响应数据失败", err)
		hh.respStatus(http.StatusInternalServerError, "")
		return
	}

	_, err = hh.resp.Write(respData)
	if err != nil {
		log.Warn("响应数据时出错", err)
	}
}

// -> GET /resolve -> json
func (hh *HTTPHandler) jsonQueryHandler() {
	var (
		err	  error
		reqMsg   = new(dns.Msg)
		respData []byte
		respMsg  *dns.Msg
	)

	if c.JSONQueryAuth && hh.req.Header.Get("Authorization") != c.Authorization {
		hh.respStatus(http.StatusUnauthorized, "")
		return
	}

	defer func() {
		if hh.req.Body != nil {
			err = hh.req.Body.Close()
			if err != nil {
				log.Warn("",err)
			}
		}
	}()

	if hh.req.URL.Query().Get("name") == "" {
		hh.respStatus(http.StatusBadRequest, "Invalid question parameter: 'name'")
		return
	}
	if hh.req.URL.Query().Get("type") == "" {
		hh.respStatus(http.StatusBadRequest, "Invalid question parameter: 'type'")
		return
	}

	reqMsg.SetQuestion(hh.req.URL.Query().Get("name"), dns.StringToType[hh.req.URL.Query().Get("type")])

	if !strings.HasSuffix(reqMsg.Question[0].Name, ".") {
		reqMsg.Question[0].Name += "."
	}

	upstream := Upstream{
		MethodByDoT: hh.req.Method,
		ReqMsg:	  reqMsg,
	}
	respMsg, err = upstream.Query()
	if err != nil {
		log.Error("查询上游服务失败", err)
		hh.respStatus(http.StatusInternalServerError, "")
		return
	}

	respData, err = json.Marshal(respMsg)
	if err != nil {
		log.Error("编码响应数据失败", err)
		hh.respStatus(http.StatusInternalServerError, "")
		return
	}

	_, err = hh.resp.Write(respData)
	if err != nil {
		log.Warn("响应数据时出错", err)
	}
}


func (hh *HTTPHandler) checkContentType() bool {
	if !strings.HasPrefix(hh.req.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		hh.respStatus(http.StatusUnsupportedMediaType, "")
		return false
	}
	return true
}
