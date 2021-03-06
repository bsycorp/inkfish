package inkfish

import (
	"encoding/base64"
	"fmt"
	"github.com/pkg/errors"
	"net"
	"net/http"
	"strings"
)

const ProxyAuthorizationHeader = "Proxy-Authorization"

func parseProxyAuth(headerValue string) (string, string, error) {
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

func getRemoteIP(remoteAddr string) (string, error) {
	// We can't split by ":" because the source IP might be a v6 address.
	// Most commonly, this would be because the source is "localhost".
	// RemoteAddr will look like "[::]:31337" in this case.
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return "", errors.Errorf("failed to get remote address from addr: %v", remoteAddr)
	}
	host = strings.Split(host, "%")[0]
	return host, nil
}

const authFailUser = "AUTH_FAIL"
const anonymousUser = "ANONYMOUS"

func (proxy *Inkfish) authenticateClient(req *http.Request) (string, error) {
	ip, err := getRemoteIP(req.RemoteAddr)
	if err != nil {
		panic(err)
	}
	// Check for client-supplied creds first
	if _, hasAuthHdr := req.Header[ProxyAuthorizationHeader]; hasAuthHdr {
		authHdr := req.Header[ProxyAuthorizationHeader]
		if len(authHdr) != 1 {
			return authFailUser, errors.New("denying request due to multiple proxy-auth headers")
		}
		hdrUser, hdrPass, err := parseProxyAuth(authHdr[0])
		if err != nil {
			return authFailUser, errors.Wrap(err, "could not understand proxy-auth header ")
		}
		if proxy.credentialsAreValid(hdrUser, hdrPass) {
			return "user:" + hdrUser, nil
		}
		return authFailUser, errors.New("authentication failed")
	}
	// Fall back on metadata lookup
	if proxy.MetadataProvider != nil {
		if tag, ok := proxy.MetadataProvider.Lookup(ip); ok {
			return fmt.Sprintf("tag:%v", tag), nil
		}
	}
	// No creds and no metadata, client is anonymous
	return anonymousUser, nil
}
