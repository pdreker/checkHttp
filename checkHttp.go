package main

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"gopkg.in/yaml.v2"
)

// HTTPRequest encapsulates the HTTP request to be used
type HTTPRequest struct {
	URL                string
	InsecureSkipVerify bool `yaml:"insecureSkipVerify"`
	FollowRedirects    bool `yaml:"followRedirects"`
	Headers            map[string]string
}

// UnmarshalYAML unmarshals the HTTPRequest portion of the configured request and sets the defaults
func (r *HTTPRequest) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type rawReq HTTPRequest
	raw := rawReq{InsecureSkipVerify: false, FollowRedirects: false}
	if err := unmarshal(&raw); err != nil {
		return err
	}

	*r = HTTPRequest(raw)
	return nil
}

// Config defines the YAML structure for the imput file
type Config struct {
	Checks []struct {
		Name     string
		Request  HTTPRequest
		Response struct {
			Code    int
			Headers map[string]string
		}
	} `yaml:",flow"`
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func redirectPolicyFunc(req *http.Request, via []*http.Request) error {
	return http.ErrUseLastResponse
}

func main() {
	config := Config{}
	data, err := ioutil.ReadFile("tests/simple.yaml")
	check(err)

	err = yaml.Unmarshal(data, &config)
	check(err)
	//fmt.Printf("--- config:\n%v\n\n", config)

	d, err := yaml.Marshal(&config)
	check(err)
	fmt.Printf("--- config dump:\n%s\n\n", d)

	// index 0:        verify TLS, do not follow redirects (default)
	// index 1:        verify TLS,        follow redirects
	// index 2: do not verify TLS, do not follow redirects
	// index 3: do not verify TLS,        follow redirects
	var httpClients [4]*http.Client

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
	httpClients[0] = &http.Client{Transport: httpTransport, CheckRedirect: redirectPolicyFunc}
	httpClients[1] = &http.Client{Transport: httpTransport}
	httpClients[2] = &http.Client{Transport: httpTransportInsecure, CheckRedirect: redirectPolicyFunc}
	httpClients[3] = &http.Client{Transport: httpTransportInsecure}

	for _, httpCheck := range config.Checks {
		fmt.Printf("--- Check: %s\n", httpCheck.Name)
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
		//fmt.Printf("   - Status: %d\n", resp.StatusCode)

		if httpCheck.Response.Code != 0 {
			if resp.StatusCode != httpCheck.Response.Code {
				fmt.Printf("Status Code: FAILED\n")
			} else {
				fmt.Printf("Status Code: OK\n")
			}
		} else {
			fmt.Printf("Status Code: n/a\n")
		}

		//fmt.Printf("DEBUG: Response Headers:\n")
		//for k, v := range resp.Header {
		//	fmt.Printf("%s: ", k)
		//	for _, v := range v {
		//		fmt.Printf("%s, ", v)
		//	}
		//	fmt.Printf("\n")
		//}

		if httpCheck.Response.Headers != nil {
			for header, content := range httpCheck.Response.Headers {
				// fmt.Printf("Checking Header: %s == %s\n", header, content)
				if val, present := resp.Header[http.CanonicalHeaderKey(header)]; present {
					// fmt.Printf("Header found in response: %s: %s\n", header, val)
					if val[0] != content {
						fmt.Printf("Headers: FAILED\n")
					} else {
						fmt.Printf("Headers: OK\n")
					}
				} else {
					fmt.Printf("Headers: MISSING\n")
				}
			}
		} else {
			fmt.Printf("Headers: n/a\n")
		}
	}
}
