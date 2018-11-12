package inkfish

import (
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/url"
	"testing"
)

func TestGetRemoteIPEasy(t *testing.T) {
	ip, err := getRemoteIP("1.2.3.4:1234")
	assert.Nil(t, err)
	assert.Equal(t, "1.2.3.4", ip)
}

func TestGetRemoteIPGarbage(t *testing.T) {
	var err error
	_, err = getRemoteIP("1.2.3.4:abcd")
	assert.NotNil(t, err)
	_, err = getRemoteIP("whatever")
	assert.NotNil(t, err)
	_, err = getRemoteIP("12312312312312312123123123")
	assert.NotNil(t, err)
}

func TestGetRemoteIPv6Localhost(t *testing.T) {
	ip, err := getRemoteIP("[::]:1234")
	assert.Nil(t, err)
	assert.Equal(t, "[::]", ip)
}

func TestParseProxyAuth(t *testing.T) {
	// TODO
}

func MustParseUrl(s string) (*url.URL) {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}

func templateHttpRequest() (*http.Request) {
	return &http.Request{
		Method: "GET",
		URL: MustParseUrl("http://google.com/"),
		Proto: "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header: map[string][]string{
			"Accept-Encoding": {"gzip, deflate"},
			"Accept-Language": {"en-us"},
		},
		Host: "www.google.com",
		RemoteAddr: "127.0.0.1:1234",
	}
}

func TestAuthenticateClientByValidCreds(t *testing.T) {
	// If the client sends a proxy-auth header with valid creds,
	// the calling user should be taken from the header
	proxy := NewInkfish()
	proxy.Passwd = []UserEntry{ // foo:foo
		{ Username: "foo", PasswordHash: "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae" },
	}
	req := templateHttpRequest()
	req.Header.Add("Proxy-Authorization", "Basic Zm9vOmZvbw==")
	res, err := proxy.authenticateClient(req)
	assert.Equal(t, "foo", res)
	assert.Nil(t, err)
}

func TestAuthenticateClientByInvalidCreds(t *testing.T) {
	// If the client sends a proxy-auth header but the credentials
	// are not valid, the calling user should be INVALID
	proxy := NewInkfish()
	proxy.Passwd = []UserEntry{ // foo:foo
		{ Username: "foo", PasswordHash: "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae" },
	}
	req := templateHttpRequest()
	req.Header.Add("Proxy-Authorization", "Basic Zm9vOmJhcg==")
	res, err := proxy.authenticateClient(req)
	assert.Equal(t, "INVALID", res)
	assert.NotNil(t, err)

	req = templateHttpRequest()
	req.Header.Add("Proxy-Authorization", "")
	res, err = proxy.authenticateClient(req)
	assert.Equal(t, "INVALID", res)
	assert.NotNil(t, err)

	req = templateHttpRequest()
	req.Header.Add("Proxy-Authorization", "Basic 1fnord1!!")
	res, err = proxy.authenticateClient(req)
	assert.Equal(t, "INVALID", res)
	assert.NotNil(t, err)
}

func TestAuthenticateClientAnonymous(t *testing.T) {
	// Without any metadata lookup or proxy-auth headers, the calling
	// user should be ANONYMOUS
	req := templateHttpRequest()
	proxy := NewInkfish()
	res, err := proxy.authenticateClient(req)
	assert.Equal(t, "ANONYMOUS", res)
	assert.Nil(t, err)
}

type testMetadataProvider struct {}

func (m *testMetadataProvider) Lookup(s string) (string, bool) {
	if s == "155.144.114.41" {
		return "bojangles", true
	} else if s == "49.3.5.163" {
		return "snood", true
	}
	return "INVALID", false
}

func TestAuthenticateClientByMetadata(t *testing.T) {
	proxy := NewInkfish()
	proxy.MetadataProvider = &testMetadataProvider{}

	req := templateHttpRequest()
	req.RemoteAddr = "155.144.114.41:31337"
	res, err := proxy.authenticateClient(req)
	assert.Equal(t, "tag:bojangles", res)
	assert.Nil(t, err)

	req = templateHttpRequest()
	req.RemoteAddr = "49.3.5.163:31337"
	res, err = proxy.authenticateClient(req)
	assert.Equal(t, "tag:snood", res)
	assert.Nil(t, err)

	// If the client "falls through" the metadata provider, they are ANONYMOUS
	req = templateHttpRequest()
	req.RemoteAddr = "8.8.8.8:31337"
	res, err = proxy.authenticateClient(req)
	assert.Equal(t, "ANONYMOUS", res)
	assert.Nil(t, err)
}
