package main

import (
	"crypto/tls"
	"flag"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"gopkg.in/yaml.v2"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func doNotFollowRedirectPolicy(req *http.Request, via []*http.Request) error {
	return http.ErrUseLastResponse
}

var inputFile = flag.String("config", "checkhttp.yaml", "Config file specifying the checks to be performed")

func main() {
	logger := log.NewLogfmtLogger(os.Stdout)
	logger = level.NewFilter(logger, level.AllowInfo())
	logger = log.With(logger, "ts", log.DefaultTimestampUTC, "caller", log.DefaultCaller)

	flag.Parse()
	config := HTTPRequests{}
	data, err := ioutil.ReadFile(*inputFile)
	check(err)

	err = yaml.Unmarshal(data, &config)
	check(err)

	d, err := yaml.Marshal(&config)
	check(err)
	level.Info(logger).Log("event", "parsed config", "config", d)

	// index 0:        verify TLS, do not follow redirects (default)
	// index 1:        verify TLS,        follow redirects
	// index 2: do not verify TLS, do not follow redirects
	// index 3: do not verify TLS,        follow redirects
	var httpClients [4]*http.Client

	level.Info(logger).Log("event", "initializing HTTP transports")
	defaultTransport := http.DefaultTransport.(*http.Transport)
	httpTransportInsecure := &http.Transport{
		Proxy:                 defaultTransport.Proxy,
		DialContext:           defaultTransport.DialContext,
		MaxIdleConns:          defaultTransport.MaxIdleConns,
		IdleConnTimeout:       defaultTransport.IdleConnTimeout,
		ExpectContinueTimeout: defaultTransport.ExpectContinueTimeout,
		TLSHandshakeTimeout:   defaultTransport.TLSHandshakeTimeout,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
	}
	httpTransport := &http.Transport{}
	level.Info(logger).Log("event", "HTTP transports initialized")

	level.Info(logger).Log("event", "initializing HTTP clients")
	httpClients[0] = &http.Client{Transport: httpTransport, CheckRedirect: doNotFollowRedirectPolicy}
	httpClients[1] = &http.Client{Transport: httpTransport}
	httpClients[2] = &http.Client{Transport: httpTransportInsecure, CheckRedirect: doNotFollowRedirectPolicy}
	httpClients[3] = &http.Client{Transport: httpTransportInsecure}
	level.Info(logger).Log("event", "HTTP clients initialized")

	var checkResults []Result

	for _, httpCheck := range config.Checks {
		result := new(Result)
		result.Name = httpCheck.Name

		req, err := http.NewRequest("GET", httpCheck.Request.URL, nil)
		check(err)
		for header, content := range httpCheck.Request.Headers {
			if strings.ToLower(header) == "host" {
				req.Host = content
			} else {
				req.Header.Set(header, content)
			}
		}

		var resp *http.Response
		var clientIndex = 0
		if httpCheck.Request.InsecureSkipVerify {
			clientIndex += 2
		}
		if httpCheck.Request.FollowRedirects {
			clientIndex++
		}

		if httpCheck.Request.InsecureSkipVerify {
			resp, err = httpClients[clientIndex].Do(req)
		} else {
			resp, err = httpClients[clientIndex].Do(req)
		}
		check(err)

		if httpCheck.Response.Code != 0 {
			if resp.StatusCode != httpCheck.Response.Code {
				result.Code = false
				result.ResponseCode = resp.StatusCode
				result.ExpectCode = httpCheck.Response.Code
			} else {
				result.Code = true
			}
		} else {
			result.Code = true
		}

		if httpCheck.Response.Headers != nil {
			for header, content := range httpCheck.Response.Headers {
				if val, present := resp.Header[http.CanonicalHeaderKey(header)]; present {
					if val[0] != content {
						result.Headers = false
						result.ResponseHeader[header] = [2]string{content, val[0]}
					} else {
						result.Headers = true
					}
				} else {
					// MISSING
					result.Headers = false
					result.ResponseHeader[header] = [2]string{content, "MISSING"}
				}
			}
		} else {
			result.Headers = true
		}
		checkResults = append(checkResults, *result)
	}
	for _, result := range checkResults {
		level.Info(logger).Log("check", result.Name, "code", result.Code, "headers", result.Headers)
		if !result.Code {
			level.Error(logger).Log("check", result.Name, "code-actual", result.ResponseCode, "code-want", result.ExpectCode)
		}
		if !result.Headers {
			for k, v := range result.ResponseHeader {
				level.Error(logger).Log("check", result.Name, "header", k, "header-actual", v[1], "header-want", v[0])
			}
		}
	}
}
