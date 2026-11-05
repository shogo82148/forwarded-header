package forwardedheader

import (
	"errors"
	"net/netip"
	"runtime"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestForwarded_String(t *testing.T) {
	tests := []struct {
		name string
		f    *Forwarded
		want string
	}{
		{
			name: "empty",
			f:    &Forwarded{},
			want: "for=unknown",
		},
		{
			name: "for",
			f: &Forwarded{
				For: Node{
					ObfuscatedNode: "_gazonk",
				},
			},
			want: `for=_gazonk`,
		},
		{
			name: "for-ipv6",
			f: &Forwarded{
				For: Node{
					IP: netip.MustParseAddr("2001:db8:cafe::17"),
				},
			},
			want: `for="[2001:db8:cafe::17]"`,
		},
		{
			name: "for-ipv4-and-port",
			f: &Forwarded{
				For: Node{
					IP:   netip.MustParseAddr("192.0.2.43"),
					Port: 47011,
				},
			},
			want: `for="192.0.2.43:47011"`,
		},
		{
			name: "for-ipv6-and-port",
			f: &Forwarded{
				For: Node{
					IP:   netip.MustParseAddr("2001:db8:cafe::17"),
					Port: 4711,
				},
			},
			want: `for="[2001:db8:cafe::17]:4711"`,
		},
		{
			name: "for-ipv6-and-port-and-extensions",
			f: &Forwarded{
				For: Node{
					IP: netip.MustParseAddr("192.0.2.60"),
				},
				Proto: "http",
				By: Node{
					IP: netip.MustParseAddr("203.0.113.43"),
				},
			},
			want: `by=203.0.113.43;for=192.0.2.60;proto=http`,
		},
		{
			name: "proto-http",
			f: &Forwarded{
				Proto: "http",
			},
			want: `proto=http`,
		},
		{
			name: "proto-https",
			f: &Forwarded{
				Proto: "https",
			},
			want: `proto=https`,
		},
		{
			name: "invalid ip address",
			f: &Forwarded{
				For: Node{
					Port: 47011,
				},
			},
			want: `for=":47011"`,
		},

		{
			name: "sanitize-obfuscated-node",
			f: &Forwarded{
				For: Node{
					ObfuscatedNode: "_*****",
				},
			},
			want: `for=______`,
		},
		{
			name: "sanitize-obfuscated-port",
			f: &Forwarded{
				For: Node{
					ObfuscatedNode: "foo",
					ObfuscatedPort: "_*****",
				},
			},
			want: `for="_foo:______"`,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			f := tt.f
			if got := f.String(); got != tt.want {
				t.Errorf("Forwarded.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		headers []string
		want    []*Forwarded
	}{
		{
			name:    "empty-string",
			headers: []string{""},
			want: []*Forwarded{
				{},
			},
		},

		// Examples from RFC 7239 Section 4.
		{
			name: "for-gazonk",
			headers: []string{
				`for="_gazonk"`,
			},
			want: []*Forwarded{
				{
					For: Node{
						ObfuscatedNode: "_gazonk",
					},
				},
			},
		},
		{
			name: "for-ipv6",
			headers: []string{
				`For="[2001:db8:cafe::17]:4711"`,
			},
			want: []*Forwarded{
				{
					For: Node{
						IP:   netip.MustParseAddr("2001:db8:cafe::17"),
						Port: 4711,
					},
				},
			},
		},
		{
			name: "for-and-proto",
			headers: []string{
				`for=192.0.2.60;proto=http;by=203.0.113.43`,
			},
			want: []*Forwarded{
				{
					For: Node{
						IP: netip.MustParseAddr("192.0.2.60"),
					},
					Proto: "http",
					By: Node{
						IP: netip.MustParseAddr("203.0.113.43"),
					},
				},
			},
		},
		{
			name: "multiple-for",
			headers: []string{
				`for=192.0.2.43, for=198.51.100.17`,
			},
			want: []*Forwarded{
				{
					For: Node{
						IP: netip.MustParseAddr("192.0.2.43"),
					},
				},
				{
					For: Node{
						IP: netip.MustParseAddr("198.51.100.17"),
					},
				},
			},
		},

		// Examples from RFC 7239 Section 7.1.
		{
			name: "rfc7239-section7-example1",
			headers: []string{
				`for=192.0.2.43,for="[2001:db8:cafe::17]",for=unknown`,
			},
			want: []*Forwarded{
				{
					For: Node{
						IP: netip.MustParseAddr("192.0.2.43"),
					},
				},
				{
					For: Node{
						IP: netip.MustParseAddr("2001:db8:cafe::17"),
					},
				},
				{
					For: Node{},
				},
			},
		},
		{
			name: "rfc7239-section7-example2",
			headers: []string{
				`for=192.0.2.43, for="[2001:db8:cafe::17]", for=unknown`,
			},
			want: []*Forwarded{
				{
					For: Node{
						IP: netip.MustParseAddr("192.0.2.43"),
					},
				},
				{
					For: Node{
						IP: netip.MustParseAddr("2001:db8:cafe::17"),
					},
				},
				{
					For: Node{},
				},
			},
		},
		{
			name: "rfc7239-section7-example3",
			headers: []string{
				`for=192.0.2.43`,
				`for="[2001:db8:cafe::17]", for=unknown`,
			},
			want: []*Forwarded{
				{
					For: Node{
						IP: netip.MustParseAddr("192.0.2.43"),
					},
				},
				{
					For: Node{
						IP: netip.MustParseAddr("2001:db8:cafe::17"),
					},
				},
				{
					For: Node{},
				},
			},
		},

		{
			name: "unknown-key",
			headers: []string{
				`foo=bar`,
			},
			want: []*Forwarded{
				{},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.headers)
			if err != nil {
				t.Errorf("Parse() error = %v", err)
				return
			}
			opts := cmpopts.EquateComparable(netip.Addr{})
			if diff := cmp.Diff(tt.want, got, opts); diff != "" {
				t.Errorf("Parse() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestParse_Error(t *testing.T) {
	tests := []struct {
		name    string
		headers []string
	}{
		{
			name: "unbalanced-quotes",
			headers: []string{
				`for="[2001:db8:cafe::17]`, // missing closing quote
			},
		},
		{
			"missing-bracket",
			[]string{
				`for="[2001:db8:cafe::17:4711"`,
			},
		},
		{
			name: "garbage-after-ipv6-address",
			headers: []string{
				`for="[2001:db8:cafe::17]4711"`,
			},
		},
		{
			name: "unexpected-colon",
			headers: []string{
				`for="[2001:db8:cafe::17]4711:"`,
			},
		},
		{
			name: "invalid-ipv6-address",
			headers: []string{
				`for="[2001:db8:cafe::INVALID]"`,
			},
		},
		{
			name: "invalid-ipv4-address",
			headers: []string{
				`for=192.0.2.256`,
			},
		},
		{
			name: "invalid-port",
			headers: []string{
				`for="192.0.2.1:0x12"`,
			},
		},
		{
			name: "invalid-obfuscated-node",
			headers: []string{
				`for="_*****"`,
			},
		},
		{
			name: "invalid-obfuscated-port",
			headers: []string{
				`for="_gazonk:_*****"`,
			},
		},
		{
			name: "duplicate-key",
			headers: []string{
				`for=192.0.2.1; for="[2001:db8:cafe::17]"`,
			},
		},
		{
			name: "issue-10",
			headers: []string{
				"For=\"::%]:00\"",
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(tt.headers)
			if err == nil {
				t.Errorf("Parse() error = %v", err)
				return
			}
		})
	}
}

func TestParse_TooManyElements(t *testing.T) {
	elems := func(n int) string {
		return strings.Repeat("for=192.0.2.43,", n-1) + "for=192.0.2.43"
	}

	// the limit itself is accepted.
	got, err := Parse([]string{elems(maxElements)})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(got) != maxElements {
		t.Errorf("len(Parse()) = %d, want %d", len(got), maxElements)
	}

	tests := []struct {
		name    string
		headers []string
	}{
		{
			name:    "single-header",
			headers: []string{elems(maxElements + 1)},
		},
		{
			name:    "multiple-headers",
			headers: []string{elems(maxElements), "for=192.0.2.43"},
		},
		{
			name:    "commas-only",
			headers: []string{strings.Repeat(",", 1<<20)},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(tt.headers)
			var e *Error
			if !errors.As(err, &e) {
				t.Fatalf("Parse() error = %v, want *Error", err)
			}
		})
	}
}

func BenchmarkString(b *testing.B) {
	f := &Forwarded{
		For: Node{
			IP: netip.MustParseAddr("2001:db8:cafe::17"),
		},
	}
	for i := 0; i < b.N; i++ {
		runtime.KeepAlive(f.String())
	}
}

func BenchmarkParse(b *testing.B) {
	headers := []string{`For="[2001:db8:cafe::17]:4711"`, `for=192.0.2.60;proto=http;by=203.0.113.43`}
	for i := 0; i < b.N; i++ {
		f, err := Parse(headers)
		if err != nil {
			b.Fatal(err)
		}
		runtime.KeepAlive(f)
	}
}

func FuzzParse(f *testing.F) {
	f.Add(`for="_gazonk"`)
	f.Add(`For="[2001:db8:cafe::17]:4711"`)
	f.Add(`for=192.0.2.60;proto=http;by=203.0.113.43`)

	f.Fuzz(func(t *testing.T, s string) {
		parsed, err := Parse([]string{s})
		if err != nil {
			return
		}

		encoded := Encode(parsed)

		parsed2, err := Parse([]string{encoded})
		if err != nil {
			t.Errorf("%q: %v", encoded, err)
		}

		opts := cmpopts.EquateComparable(netip.Addr{})
		if diff := cmp.Diff(parsed, parsed2, opts); diff != "" {
			t.Errorf("Parse() mismatch (-want +got):\n%s", diff)
		}
	})
}
