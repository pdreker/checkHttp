package main

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

// HTTPRequests defines the YAML structure for the imput file
type HTTPRequests struct {
	Checks []struct {
		Name     string
		Request  HTTPRequest
		Response struct {
			Code    int
			Headers map[string]string
		}
	} `yaml:",flow"`
}
