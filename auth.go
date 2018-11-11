package inkfish

import (
	"encoding/base64"
	"fmt"
	"github.com/pkg/errors"
	"net/http"
	"regexp"
	"strings"
)

const ProxyAuthorizationHeader = "Proxy-Authorization"

func ParseProxyAuth(headerValue string) (string, string, error) {
	authheader := strings.SplitN(headerValue, " ", 2)
	if len(authheader) != 2 || authheader[0] != "Basic" {
		return "", "", errors.New("expected Basic auth")
	}
	userpassraw, err := base64.StdEncoding.DecodeString(authheader[1])
	if err != nil {
		return "", "", errors.Wrap(err, "could not decode auth header")
	}
	userpass := strings.SplitN(string(userpassraw), ":", 2)
	if len(userpass) != 2 {
		return "", "", errors.New("strange auth header value")
	}
	return userpass[0], userpass[1], nil
}

var srcRe = regexp.MustCompile(`^(.*):(\d+)$`)

func getRemoteIP(remoteAddr string) (string, error) {
	// We can't split by ":" because the source IP might be a v6 address.
	// Most commonly, this would be because the source is "localhost".
	// RemoteAddr will look like "[::]:31337" in this case.

	m := srcRe.FindStringSubmatch(remoteAddr)
	if m == nil || len(m) != 3 {
		return "", errors.Errorf("failed to get remote address from addr: %v", remoteAddr)
	}
	return m[1], nil
}

func (proxy *Inkfish) authenticateClient(req *http.Request) (string) {
	ip, err := getRemoteIP(req.RemoteAddr)
	if err != nil {
		panic(err)
	}
	// Check for client-supplied creds first
	if _, hasAuthHdr := req.Header[ProxyAuthorizationHeader]; hasAuthHdr {
		authHdr := req.Header[ProxyAuthorizationHeader]
		if len(authHdr) != 1 {
			// Multiple proxy auth headers. Get outta here.
			// TODO: logging
			return "INVALID"
		}
		hdrUser, hdrPass, err := ParseProxyAuth(req.Header.Get(ProxyAuthorizationHeader))
		if err != nil {
			// TODO: logging
			return "INVALID" // Something was wrong with the header
		}
		// We never want proxy-auth to be forwarded to an origin server
		req.Header.Del(ProxyAuthorizationHeader)
		if hdrUser != "" {
			if proxy.CredentialsAreValid(hdrUser, hdrPass) {
				return hdrUser
			}
		}
		return "INVALID" // They tried, and they failed
	}
	// Fall back on metadata lookup
	if proxy.MetadataProvider != nil {
		if tag, ok := proxy.MetadataProvider.Lookup(ip); ok {
			return fmt.Sprintf("tag:%v", tag)
		}
	}
	// No creds and no metadata, client is anonymous
	return "ANONYMOUS"
}
