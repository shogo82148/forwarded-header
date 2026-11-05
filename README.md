[![test](https://github.com/shogo82148/fowarded-header/actions/workflows/test.yml/badge.svg)](https://github.com/shogo82148/fowarded-header/actions/workflows/test.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/shogo82148/fowarded-header.svg)](https://pkg.go.dev/github.com/shogo82148/fowarded-header)

# forwarded-header

Parser of HTTP Forward Header defined by [RFC 7239: Forwarded HTTP Extension](https://www.rfc-editor.org/info/rfc7239).

## Synopsis

```go
package main

import (
	"fmt"
	"net/http"
	"net/netip"
	"os"

	forwardedheader "github.com/shogo82148/forwarded-header"
)

func main() {
	// build the Forwarded Header
	forwarded := []*forwardedheader.Forwarded{
		{
			For: forwardedheader.Node{
				IP: netip.MustParseAddr("192.0.2.60"),
			},
			Proto: "http",
			By: forwardedheader.Node{
				IP: netip.MustParseAddr("203.0.113.43"),
			},
		},
	}
	encoded, err := forwardedheader.Encode(forwarded)
	if err != nil {
		panic(err)
	}
	header := make(http.Header)
	header.Set("Forwarded", encoded)
	header.Write(os.Stdout)
	// Output:
	// Forwarded: by=203.0.113.43;for=192.0.2.60;proto=http

	// parse the Forwarded Header
	parsed, err := forwardedheader.Parse(header.Values("Forwarded"))
	if err != nil {
		panic(err)
	}
	for _, f := range parsed {
		fmt.Println(f)
	}
	// Output:
	// by=203.0.113.43;for=192.0.2.60;proto=http
}
```

## References

- [RFC 7239: Forwarded HTTP Extension](https://www.rfc-editor.org/info/rfc7239)
