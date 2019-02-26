package inkfish

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"regexp"
)

func TestCheckCredentials(t *testing.T) {
	proxy := &Inkfish{
		Passwd: []UserEntry{
			{
				// $ echo -n "foo" | shasum -a 256
				// 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae  -
				Username:     "foo",
				PasswordHash: "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
			},
		},
	}
	assert.False(t, proxy.credentialsAreValid("bar", "bar"))
	assert.False(t, proxy.credentialsAreValid("foo", "bar"))
	assert.True(t, proxy.credentialsAreValid("foo", "foo"))
}

func TestParseAclUrl(t *testing.T) {
	aclUrl, err := parseAclURLEntry([]string{})
	assert.Nil(t, aclUrl)
	assert.NotNil(t, err)

	aclUrl, err = parseAclURLEntry([]string{"foo", "bar", "baz"})
	assert.Nil(t, aclUrl)
	assert.NotNil(t, err)

	url := `^http://boards\.4chan\.org/b/`

	// 2-form
	// url ^http://boards\.4chan\.org/b/
	aclUrl, err = parseAclURLEntry([]string{"url", url})
	assert.NotNil(t, aclUrl)
	assert.Nil(t, err)
	assert.Equal(t, true, aclUrl.AllMethods)
	assert.Empty(t, aclUrl.Methods)
	assert.Equal(t, url, aclUrl.Pattern.String())

	// 3-form
	// url GET,POST,HEAD ^http://boards\.4chan\.org/b/
	aclUrl, err = parseAclURLEntry([]string{"url", "GET,POST,HEAD", url})
	assert.NotNil(t, aclUrl)
	assert.Nil(t, err)
	assert.Equal(t, false, aclUrl.AllMethods)
	assert.Equal(t, []string{"GET", "POST", "HEAD"}, aclUrl.Methods)
	assert.Equal(t, url, aclUrl.Pattern.String())
}

func TestParseAclS3Bucket(t *testing.T) {
	aclUrl, err := parseAclS3BucketEntry([]string{})
	assert.Nil(t, aclUrl)
	assert.NotNil(t, err)

	//invalid bucket name
	aclUrl, err = parseAclS3BucketEntry([]string{"s3", "weird.WRONG.*bucket"})
	assert.Nil(t, aclUrl)
	assert.NotNil(t, err)

	aclUrl, err = parseAclS3BucketEntry([]string{"foo", "bar", "baz"})
	assert.Nil(t, aclUrl)
	assert.NotNil(t, err)

	bucket := "my-bucket"
	expectedExpr := `https?\:\/\/(s3\-[a-z0-9\-]+|s3)\.amazonaws\.com\/my-bucket|https?\:\/\/my-bucket\.(s3\-[a-z0-9\-]+|s3)\.amazonaws\.com\/`
	aclUrl, err = parseAclS3BucketEntry([]string{"s3", bucket})
	assert.NotNil(t, aclUrl)
	assert.Nil(t, err)
	assert.Equal(t, true, aclUrl.AllMethods)
	assert.Empty(t, aclUrl.Methods)
	assert.Equal(t, expectedExpr, aclUrl.Pattern.String())

	regexp, _ := regexp.Compile(expectedExpr)
	assert.True(t, regexp.Match([]byte("https://s3.amazonaws.com/my-bucket/woot")))
	assert.True(t, regexp.Match([]byte("http://s3-somewhere.amazonaws.com/my-bucket/woot")))
	assert.True(t, regexp.Match([]byte("https://s3-somewhere.amazonaws.com/my-bucket/woot")))
	assert.True(t, regexp.Match([]byte("http://my-bucket.s3-ap-southeast-2.amazonaws.com/woot")))
	assert.True(t, regexp.Match([]byte("https://my-bucket.s3-ap-southeast-2.amazonaws.com/woot")))
	assert.False(t, regexp.Match([]byte("https://evil-bucket.s3-ap-southeast-2.amazonaws.com/woot")))
	assert.False(t, regexp.Match([]byte("https://s3.amazonaws.com/evil-bucket/woot")))
	assert.False(t, regexp.Match([]byte("https://evil.host/s3.amazonaws.com/evil-bucket/woot")))
	assert.False(t, regexp.Match([]byte("https://evil.host/https://s3.amazonaws.evil/my-bucket/woot")))
}


func TestBrokenAclConfigs(t *testing.T) {
	aclConfig, err := parseAcl([]string{
		"klaatu", "barada", "nikto",
	})
	assert.Nil(t, aclConfig)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "line: 1")

	aclConfig, err = parseAcl([]string{
		"from foo",
		"url SOME THING WRONG",
	})
	assert.Nil(t, aclConfig)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "line: 2")
}

func TestAclConfig(t *testing.T) {
	aclConfig, err := parseAcl([]string{
		"from foo",
		"from bar",
		"url ^http(s)?://google.com/",
		"url GET,HEAD ^http(s)?://yahoo.com/",
	})
	assert.NotNil(t, aclConfig)
	assert.Nil(t, err)

	assert.True(t, aclConfig.permits("foo", "GET", "https://google.com/"))
	assert.True(t, aclConfig.permits("bar", "GET", "https://google.com/"))
	assert.False(t, aclConfig.permits("baz", "GET", "https://google.com/"))
	assert.True(t, aclConfig.permits("foo", "GET", "https://yahoo.com/"))
	assert.False(t, aclConfig.permits("foo", "POST", "https://yahoo.com/"))
}

func TestAclConfigWithBypass(t *testing.T) {
	aclConfig, err := parseAcl([]string{
		"from foo",
		"from bar",
		"url ^http(s)?://google.com/",
		"url GET,HEAD ^http(s)?://yahoo.com/",
		"bypass foo.com:443",
		"bypass bar.com:443",
	})
	assert.NotNil(t, aclConfig)
	assert.Nil(t, err)

	assert.True(t, aclConfig.bypassMitm("foo", "foo.com:443"))
	assert.True(t, aclConfig.bypassMitm("foo", "bar.com:443"))
	assert.False(t, aclConfig.bypassMitm("baz", "foo.com:443"))
}

func TestAclConfigWithRegexpBypass(t *testing.T) {
	aclConfig, err := parseAcl([]string{
		"from foo",
		`bypass ^(.*\.)?foo\.com:443$`,
		`bypass ^foo\.com:443$`,
	})
	assert.NotNil(t, aclConfig)
	assert.Nil(t, err)

	assert.True(t, aclConfig.bypassMitm("foo", "hosta.foo.com:443"))
	assert.True(t, aclConfig.bypassMitm("foo", "hostb.foo.com:443"))
	assert.True(t, aclConfig.bypassMitm("foo", "foo.com:443"))
	assert.False(t, aclConfig.bypassMitm("foo", "foofoo.com:443"))
	assert.False(t, aclConfig.bypassMitm("foo", "a.bar.com:443"))
}

func TestAclConfigWithMissingPortInBypass(t *testing.T) {
	aclConfig, err := parseAcl([]string{
		"from foo",
		"from bar",
		"url ^http(s)?://google.com/",
		"url GET,HEAD ^http(s)?://yahoo.com/",
		"bypass foo.com",
		"bypass bar.com:443",
	})
	assert.Nil(t, aclConfig)
	assert.NotNil(t, err)
	assert.Equal(t, "missing port in bypass at line: 5", err.Error())
}

func TestLoadConfig(t *testing.T) {
	proxy := NewInkfish(NewCertSigner(&StubCA))
	err := proxy.LoadConfigFromDirectory("testdata/unit_test_config")
	assert.NotNil(t, proxy.Acls)
	assert.Nil(t, err)

	assert.Equal(t, 2, len(proxy.Acls))
}
