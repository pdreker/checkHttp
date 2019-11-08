package main

// Result contains the results of an HTTP check and any deviation from the expected result
type Result struct {
	Name           string
	Code           bool
	Headers        bool
	ResponseCode   int
	ExpectCode     int
	ResponseHeader map[string][2]string // [0] = EXPECTED, [1] = ACTUAL
}
