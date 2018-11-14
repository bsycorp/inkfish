package inkfish

// build +linux

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// Taken from: https://gist.github.com/oec/34d6acf1457b779ed7e446ddf3275762

func printfds(msg string, t *testing.T) int {
	fd, _ := os.Open("/proc/self/fd")
	fds, _ := fd.Readdir(-1)
	fd.Close()
	names := []string{}
	links := []string{}
	for _, f := range fds {
		names = append(names, f.Name())
		link, _ := os.Readlink("/proc/self/fd/" + f.Name())
		links = append(links, link)
	}
	lines := []string{}
	for i := range names {
		lines = append(lines, fmt.Sprintf("%2v → %v", names[i], links[i]))
	}
	t.Logf("[%s] /proc/self/fd:\n\t%s", msg, strings.Join(lines, "\n\t"))
	return len(fds)
}

// Make 100 requests and check for fd leaks, with MITM
func TestFDCountConnectWithMITM(t *testing.T) {
	acl1 := MustParseAcl(`
		from tag:me
		url ^.*$
	`)
	proxy := NewInsecureInkfish()
	proxy.MetadataProvider = &LocalHostIsMeMetadataProvider{}
	proxy.Acls = []Acl{acl1}
	s := NewInkfishTest(proxy)
	defer s.Close()

	before := printfds("before", t)

	// Check with MITM
	client := s.Client(nil, "DisableKeepAlives")
	for i := 0; i < 100; i++ {
		getExpect(t, client, srv_plain.URL+"/foo", 200, []byte("foo"))
		getExpect(t, client, srv_https.URL+"/foo", 200, []byte("foo"))
	}
	time.Sleep(1 * time.Second)
	after := printfds("after", t)

	if before != after {
		t.Errorf("#FD before ≠ after! FD before: %d, after: %d", before, after)
	}
}

// Make 100 requests and check for fd leaks, with MITM
// TODO: this test fails :(
func DisabledTestFDCountConnectWithBypass(t *testing.T) {
	srvu, _ := url.Parse(srv_https.URL)
	acl1 := MustParseAcl(fmt.Sprintf(`
		from tag:me
		bypass %v
	`, srvu.Host))
	proxy := NewInsecureInkfish()
	proxy.MetadataProvider = &LocalHostIsMeMetadataProvider{}
	proxy.Acls = []Acl{acl1}
	s := NewInkfishTest(proxy)
	defer s.Close()

	before := printfds("before", t)

	// Check with MITM Bypass
	client := s.Client(nil, "DisableKeepAlives")
	for i := 0; i < 100; i++ {
		getExpect(t, client, srv_https.URL+"/foo", 200, []byte("foo"))
	}
	time.Sleep(1 * time.Second)
	after := printfds("after", t)

	if before != after {
		t.Errorf("#FD before ≠ after! FD before: %d, after: %d", before, after)
	}
}
