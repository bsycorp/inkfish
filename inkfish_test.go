package inkfish

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"github.com/stretchr/testify/assert"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// ----------------
// TEST HTTP SERVER
// ----------------

var srv_plain = httptest.NewServer(nil)
var srv_https = httptest.NewTLSServer(nil)

type QueryHandler struct{}

func (QueryHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if err := req.ParseForm(); err != nil {
		panic(err)
	}
	io.WriteString(w, req.Form.Get("result"))
}

type ConstantHandler string

func (h ConstantHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	io.WriteString(w, string(h))
}

func init() {
	http.DefaultServeMux.Handle("/foo", ConstantHandler("foo"))
	http.DefaultServeMux.Handle("/bar", ConstantHandler("bar"))
	http.DefaultServeMux.Handle("/query", QueryHandler{})
}

// -------------------
// PROXY TEST HARNESS
// -------------------

func NewInsecureInkfish() (*Inkfish) {
	// Disable client's TLS validation so we can connect to the test server
	ClientInsecureSkipVerify = true
	r := NewInkfish()
	// Allow CONNECT to any port, not just 443
	r.ConnectFilter = connectFilterAllowAny
	return r
}

// A test instance of an Inkfish proxy
type InkfishTestServer struct {
	Server *httptest.Server
}

func NewInkfishTest(proxy *Inkfish) (*InkfishTestServer) {
	testServer := &InkfishTestServer{}
	testServer.Server = httptest.NewServer(proxy.Proxy)
	return testServer
}

// Make an HTTP client for the server, optionally with creds
func (it *InkfishTestServer) Client(userInfo *url.Userinfo) (*http.Client) {
	proxyUrl, _ := url.Parse(it.Server.URL)
	proxyUrl.User = userInfo
	acceptAllCerts := &tls.Config{InsecureSkipVerify: true} // TODO: verify against own CA?
	tr := &http.Transport{TLSClientConfig: acceptAllCerts, Proxy: http.ProxyURL(proxyUrl)}
	return &http.Client{Transport: tr}
}

func (it *InkfishTestServer) Close() {
	it.Server.Close()
}

func get(client *http.Client, url string) (int, []byte, error) {
	resp, err := client.Get(url)
	if err != nil {
		return -1, nil, err
	}
	body, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, body, nil
}

func getExpect(t *testing.T, client *http.Client, url string, expectCode int, expectBody []byte) []byte {
	statusCode, body, err := get(client, url)
	if err != nil {
		t.Fatal("Can't fetch url", url, err)
	}
	if statusCode != expectCode {
		t.Error("Unexpected status code: ", statusCode)
	}
	if bytes.Compare(body, expectBody) != 0 {
		t.Error("Unexpected result: ", string(body))
	}
	return body
}

func MustParseAcl(s string) Acl {
	r, err := parseAcl(strings.Split(s, "\n"))
	if err != nil {
		panic(err)
	}
	return *r
}

// --------------------------------
// PROXY TEST CONFIGURATION HELPERS
// --------------------------------

var passwdNoUsers = []UserEntry{}
var passwdFooBarBaz = []UserEntry{
	{Username: "foo", PasswordHash: "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"},
	{Username: "bar", PasswordHash: "fcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fb9"},
	{Username: "baz", PasswordHash: "baa5a0964d3320fbc0c6a922140453c8513ea24ab8fd0577034804a967248096"},
}

func connectFilterAllowAny(string, int) bool {
	// We allow CONNECT to any port for testing
	// So we can run TLS server on non-default port
	// Do not want this "in real life".
	// Connect to port 443 only is the default.
	return true
}

type LocalHostIsMeMetadataProvider struct {}

func (m *LocalHostIsMeMetadataProvider) Lookup(s string) (string, bool) {
	if s == "127.0.0.1" {
		return "me", true
	}
	return "INVALID", false
}

// -----
// TESTS
// -----

func TestConnectFilter(t *testing.T) {
	// The default connect filter should block TLS traffic to the local test server,
	// because it's not running on port 443
	acl1 := MustParseAcl(`
		from tag:me
		url ^.*$
	`)
	proxy := NewInkfish()
	proxy.MetadataProvider = &LocalHostIsMeMetadataProvider{}
	proxy.Acls = []Acl{acl1}
	s := NewInkfishTest(proxy)
	defer s.Close()

	client := s.Client(nil)

	// How client libraries deal with "CONNECT denied" varies a fair bit.
	// The go client will *not* give you an HTTP response and therefore you
	// cannot inspect the response code (403) or body of the proxy's
	// response to the CONNECT request.

	code, body, err := get(client, srv_https.URL+"/foo")
	assert.Equal(t, -1, code)
	assert.Nil(t, body)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "Forbidden")
}

func TestAllowFooNotBar(t *testing.T) {
	acl1 := MustParseAcl(`
		from tag:me
		url ^.*/foo$
	`)
	proxy := NewInsecureInkfish()
	proxy.MetadataProvider = &LocalHostIsMeMetadataProvider{}
	proxy.Acls = []Acl{acl1}
	s := NewInkfishTest(proxy)
	defer s.Close()

	client := s.Client(nil)

	getExpect(t, client, srv_plain.URL+"/foo", 200, []byte("foo"))
	getExpect(t, client, srv_https.URL+"/foo", 200, []byte("foo"))
	getExpect(t, client, srv_plain.URL+"/bar", 403, []byte(AccessDenied))
	getExpect(t, client, srv_https.URL+"/bar", 403, []byte(AccessDenied))
}

func TestAllowWithAuth(t *testing.T) {
	acl1 := MustParseAcl(`
		from user:foo
		url ^.*/foo$
	`)
	acl2 := MustParseAcl(`
		from user:bar
		url ^.*/bar$
	`)
	proxy := NewInsecureInkfish()
	proxy.Acls = []Acl{acl1, acl2}
	proxy.Passwd = passwdFooBarBaz

	s := NewInkfishTest(proxy)
	defer s.Close()

	// Foo can access foo only
	client := s.Client(url.UserPassword("foo", "foo"))
	getExpect(t, client, srv_plain.URL+"/foo", 200, []byte("foo"))
	getExpect(t, client, srv_https.URL+"/foo", 200, []byte("foo"))
	getExpect(t, client, srv_plain.URL+"/bar", 403, []byte(AccessDenied))
	getExpect(t, client, srv_https.URL+"/bar", 403, []byte(AccessDenied))

	// Bar can access bar only
	client = s.Client(url.UserPassword("bar", "bar"))
	getExpect(t, client, srv_plain.URL+"/foo", 403, []byte(AccessDenied))
	getExpect(t, client, srv_https.URL+"/foo", 403, []byte(AccessDenied))
	getExpect(t, client, srv_plain.URL+"/bar", 200, []byte("bar"))
	getExpect(t, client, srv_https.URL+"/bar", 200, []byte("bar"))

	// Baz gets nothing
	client = s.Client(url.UserPassword("baz", "baz"))
	getExpect(t, client, srv_plain.URL+"/foo", 403, []byte(AccessDenied))
	getExpect(t, client, srv_https.URL+"/foo", 403, []byte(AccessDenied))
	getExpect(t, client, srv_plain.URL+"/bar", 403, []byte(AccessDenied))
	getExpect(t, client, srv_https.URL+"/bar", 403, []byte(AccessDenied))

	// Foo with wrong password gets nothing
	client = s.Client(url.UserPassword("foo", "wrong"))
	getExpect(t, client, srv_plain.URL+"/foo", 403, []byte(AccessDenied))
	getExpect(t, client, srv_https.URL+"/foo", 403, []byte(AccessDenied))
	getExpect(t, client, srv_plain.URL+"/bar", 403, []byte(AccessDenied))
	getExpect(t, client, srv_https.URL+"/bar", 403, []byte(AccessDenied))

	// Foo with blank password gets nothing
	client = s.Client(url.UserPassword("foo", ""))
	getExpect(t, client, srv_plain.URL+"/foo", 403, []byte(AccessDenied))
	getExpect(t, client, srv_https.URL+"/foo", 403, []byte(AccessDenied))
	getExpect(t, client, srv_plain.URL+"/bar", 403, []byte(AccessDenied))
	getExpect(t, client, srv_https.URL+"/bar", 403, []byte(AccessDenied))

	// Unauthenticated client gets nothing
	client = s.Client(nil)
	getExpect(t, client, srv_plain.URL+"/foo", 403, []byte(AccessDenied))
	getExpect(t, client, srv_https.URL+"/foo", 403, []byte(AccessDenied))
	getExpect(t, client, srv_plain.URL+"/bar", 403, []byte(AccessDenied))
	getExpect(t, client, srv_https.URL+"/bar", 403, []byte(AccessDenied))
}

func TestAnonymousAccess(t *testing.T) {
	acl1 := MustParseAcl(`
		from user:foo
		url ^.*/foo$
	`)
	acl2 := MustParseAcl(`
		from ANONYMOUS
		url ^.*/bar$
	`)
	proxy := NewInsecureInkfish()
	proxy.Acls = []Acl{acl1, acl2}
	proxy.Passwd = passwdFooBarBaz

	s := NewInkfishTest(proxy)
	defer s.Close()

	// Foo can access foo only
	client := s.Client(url.UserPassword("foo", "foo"))
	getExpect(t, client, srv_plain.URL+"/foo", 200, []byte("foo"))
	getExpect(t, client, srv_https.URL+"/foo", 200, []byte("foo"))
	getExpect(t, client, srv_plain.URL+"/bar", 403, []byte(AccessDenied))
	getExpect(t, client, srv_https.URL+"/bar", 403, []byte(AccessDenied))

	// ANONYMOUS can access bar only
	client = s.Client(nil)
	getExpect(t, client, srv_plain.URL+"/foo", 403, []byte(AccessDenied))
	getExpect(t, client, srv_https.URL+"/foo", 403, []byte(AccessDenied))
	getExpect(t, client, srv_plain.URL+"/bar", 200, []byte("bar"))
	getExpect(t, client, srv_https.URL+"/bar", 200, []byte("bar"))
}

func TestMitmBypassByUser(t *testing.T) {
	proxy := NewInsecureInkfish()
	proxy.Passwd = passwdFooBarBaz

	s := NewInkfishTest(proxy)
	defer s.Close()

	// Figure out host and port for bypass
	u, _ := url.Parse(srv_https.URL)

	// Gotta do ACLs last so we know the right server port.
	acl1 := MustParseAcl(fmt.Sprintf(`
		from user:foo
		bypass ^%v$
	`, strings.Replace(u.Host, ".", "\\.", -1)))
	acl2 := MustParseAcl(`
		from user:bar
		url ^.*/bar$
	`)
	proxy.Acls = []Acl{acl1,acl2}

	// This test relies on there being no ACL to allow requests
	// to the server port for "foo", so if the request is allowed it must be
	// because MITM was successfully bypassed.
	client := s.Client(url.UserPassword("foo", "foo"))
	getExpect(t, client, srv_https.URL+"/foo", 200, []byte("foo"))
	getExpect(t, client, srv_https.URL+"/bar", 200, []byte("bar"))

	// User bar should be Acl'd as usual because they don't have bypass.
	client = s.Client(url.UserPassword("bar", "bar"))
	getExpect(t, client, srv_https.URL+"/foo", 403, []byte(AccessDenied))
	getExpect(t, client, srv_https.URL+"/bar", 200, []byte("bar"))
}

func TestMultipleUserPasswords(t *testing.T) {
	// TODO: test that the same user with multiple passwords set, works
}