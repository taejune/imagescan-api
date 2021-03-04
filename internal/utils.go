package internal

import (
	"encoding/base64"
	"net/http"
	"strings"
)

//
func ParseBasicAuthHeader(r *http.Request) (username, password string, err error) {

	basicAuth := strings.TrimPrefix(r.Header.Get("Authorization"), "Basic ")
	decodedBasicAuth, err := base64.StdEncoding.DecodeString(basicAuth)
	if err != nil {
		return "", "", err
	}

	tokens := strings.Split(string(decodedBasicAuth), ":")
	return tokens[0], tokens[1], nil
}
