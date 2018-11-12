# inkfish
A forward proxy for machines, with access control lists

[![Build Status](https://travis-ci.org/bsycorp/inkfish.svg?branch=master)](https://travis-ci.org/bsycorp/inkfish)

https://hub.docker.com/r/bsycorp/inkfish

## Command-line arguments

```
$ ./inkfish -h
Usage of ./inkfish:
  -addr string
    	proxy listen address (default ":8080")
  -cacert string
    	path to CA cert file (default "ca.pem")
  -cakey string
    	path to CA key file (default "ca.key.pem")
  -config string
    	path to configuration files (default ".")
  -metadata string
    	default metadata provider (aws,none) (default "aws")
  -v	should every proxy request be logged to stdout
```

## Configuration file format

The `-config` argument supplies a path to a directory full of "access control lists".  Roughly, these 
should look like:

```
from <user>[,user2,user3...]
from ...
acl [METHOD,METHOD2] <url-regex>
acl ...
```

Blank lines and comments (lines starting with `#`) are ignored. The "from" line gates entry into the ACL.

## Metadata lookup

Rather than distributing proxy credentials, the preferred method of access control in inkfish is via
cloud instance metadata. 

### AWS

For AWS, specify the `ProxyUser` tag on an instance. So for example if you apply tag of ProxyUser=foo,
then in your ACL you would write:

```
from tag:foo
acl ^http(s)?://.*$
```

To grant instances with that tag unrestricted outbound HTTP(s) access.

## MITM, SSL certificates and Security

By default, Inkfish's HTTP client will perform SSL/TLS certificate validation on all forwarded requests. A
good way to test this is working properly is to start the proxy locally and visit https://badssl.com/dashboard/

There are a variety of strategies that MITM proxies can use to create acceptable certificates for clients.

Some proxies "sneak and peek", attempting to mirror the origin server's certificate as closely as possible,
with the exception of the signing CA. 

This is not one of those proxies.  Inkfish inherits the goproxy strategy of looking at the client's CONNECT 
target and just generating a cert with that in it. 

## Known issues / TODO

* Generated certs for sites expire in 2049(!)
* Potential file descriptor leak on SSL connections.
* Graceful shutdown / draining not tested


