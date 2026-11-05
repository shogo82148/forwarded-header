package forwardedheader

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
)

// Forwarded represents the Forwarded header.
type Forwarded struct {
	// By is used to disclose the interface where the request came in to the proxy server.
	By Node

	// For is used to disclose information about the client that initiated the request and subsequent proxies in a chain of proxies.
	For Node

	// Host is used to forward the original value of the "Host" header field.
	Host string

	// Proto is the value of the used protocol type.
	Proto string
}

// A Node represents a node identifier in a Forwarded header
type Node struct {
	IP             netip.Addr
	Port           int
	ObfuscatedNode string
	ObfuscatedPort string
}

func (n Node) String() string {
	var buf strings.Builder
	n.write(&buf)
	return buf.String()
}

func (n Node) write(buf *strings.Builder) {
	if n == (Node{}) {
		buf.WriteString("unknown")
		return
	}
	if n.ObfuscatedNode != "" {
		n.writeObfuscated(buf, n.ObfuscatedNode)
	} else if n.IP.IsValid() {
		if n.IP.Is6() {
			buf.WriteByte('[')
			buf.WriteString(n.IP.WithZone("").String())
			buf.WriteByte(']')
		} else {
			buf.WriteString(n.IP.String())
		}
	}
	if n.ObfuscatedPort != "" {
		buf.WriteByte(':')
		n.writeObfuscated(buf, n.ObfuscatedPort)
	} else if n.Port != 0 {
		buf.WriteByte(':')
		buf.WriteString(strconv.Itoa(n.Port))
	}
}

func (Node) writeObfuscated(buf *strings.Builder, s string) {
	if !strings.HasPrefix(s, "_") {
		buf.WriteByte('_')
	}
	for _, b := range []byte(s) {
		if validObfChar[b] {
			buf.WriteByte(b)
		} else {
			buf.WriteByte('_')
		}
	}
}

// Error represents an error that occurred while parsing the Forwarded header.
type Error struct {
	Message string
	Index   int
	Pos     int
}

func (e *Error) Error() string {
	return fmt.Sprintf("forwardedheader: %s at %d in %d", e.Message, e.Pos, e.Index)
}

var validTchar = [256]bool{
	'!':  true,
	'#':  true,
	'$':  true,
	'%':  true,
	'&':  true,
	'\'': true,
	'*':  true,
	'+':  true,
	'-':  true,
	'.':  true,
	'^':  true,
	'_':  true,
	'`':  true,
	'|':  true,
	'~':  true,

	// DIGIT
	'0': true,
	'1': true,
	'2': true,
	'3': true,
	'4': true,
	'5': true,
	'6': true,
	'7': true,
	'8': true,
	'9': true,

	// ALPHA
	'a': true,
	'b': true,
	'c': true,
	'd': true,
	'e': true,
	'f': true,
	'g': true,
	'h': true,
	'i': true,
	'j': true,
	'k': true,
	'l': true,
	'm': true,
	'n': true,
	'o': true,
	'p': true,
	'q': true,
	'r': true,
	's': true,
	't': true,
	'u': true,
	'v': true,
	'w': true,
	'x': true,
	'y': true,
	'z': true,
	'A': true,
	'B': true,
	'C': true,
	'D': true,
	'E': true,
	'F': true,
	'G': true,
	'H': true,
	'I': true,
	'J': true,
	'K': true,
	'L': true,
	'M': true,
	'N': true,
	'O': true,
	'P': true,
	'Q': true,
	'R': true,
	'S': true,
	'T': true,
	'U': true,
	'V': true,
	'W': true,
	'X': true,
	'Y': true,
	'Z': true,
}

var validObfChar = [256]bool{
	'-': true,
	'.': true,
	'_': true,

	// DIGIT
	'0': true,
	'1': true,
	'2': true,
	'3': true,
	'4': true,
	'5': true,
	'6': true,
	'7': true,
	'8': true,
	'9': true,

	// ALPHA
	'a': true,
	'b': true,
	'c': true,
	'd': true,
	'e': true,
	'f': true,
	'g': true,
	'h': true,
	'i': true,
	'j': true,
	'k': true,
	'l': true,
	'm': true,
	'n': true,
	'o': true,
	'p': true,
	'q': true,
	'r': true,
	's': true,
	't': true,
	'u': true,
	'v': true,
	'w': true,
	'x': true,
	'y': true,
	'z': true,
	'A': true,
	'B': true,
	'C': true,
	'D': true,
	'E': true,
	'F': true,
	'G': true,
	'H': true,
	'I': true,
	'J': true,
	'K': true,
	'L': true,
	'M': true,
	'N': true,
	'O': true,
	'P': true,
	'Q': true,
	'R': true,
	'S': true,
	'T': true,
	'U': true,
	'V': true,
	'W': true,
	'X': true,
	'Y': true,
	'Z': true,
}

func isValidToken(s string) bool {
	for _, r := range []byte(s) {
		if !validTchar[r] {
			return false
		}
	}
	return true
}

func isValidObf(s string) bool {
	for _, r := range []byte(s) {
		if !validObfChar[r] {
			return false
		}
	}
	return true
}

// isValidQuotedChar reports whether b may appear in a quoted-string,
// either as qdtext or as the second byte of a quoted-pair (RFC 7230 Section 3.2.6).
// It rejects control characters except HTAB, and DEL.
func isValidQuotedChar(b byte) bool {
	return b == '\t' || (b >= 0x20 && b != 0x7f)
}

// isValidValue reports whether s can be encoded as a token or a quoted-string.
func isValidValue(s string) bool {
	for _, b := range []byte(s) {
		if !isValidQuotedChar(b) {
			return false
		}
	}
	return true
}

// writeQuotedString writes s as a quoted-string.
// s must satisfy isValidValue.
func writeQuotedString(w io.ByteWriter, s string) {
	w.WriteByte('"')
	for _, r := range []byte(s) {
		if r == '"' || r == '\\' {
			w.WriteByte('\\')
		}
		w.WriteByte(r)
	}
	w.WriteByte('"')
}

func writeNode(buf *strings.Builder, start int, key string, node Node) {
	if node == (Node{}) {
		return
	}
	if buf.Len() > start {
		buf.WriteByte(';')
	}
	needQuote := (node.IP.IsValid() && node.IP.Is6()) || node.ObfuscatedPort != "" || node.Port != 0

	buf.WriteString(key)
	buf.WriteByte('=')
	if needQuote {
		buf.WriteByte('"')
	}
	node.write(buf)
	if needQuote {
		buf.WriteByte('"')
	}
}

func writePair(buf *strings.Builder, start int, key, value string) {
	if value == "" {
		return
	}
	if buf.Len() > start {
		buf.WriteByte(';')
	}

	buf.WriteString(key)
	buf.WriteByte('=')
	if isValidToken(value) {
		buf.WriteString(value)
	} else {
		writeQuotedString(buf, value)
	}
}

// String returns the string representation of the Forwarded header.
// The returned string is a valid Forwarded header.
// Host and Proto values that contain control characters are omitted.
// Use [Encode] to detect such values as an error.
func (f *Forwarded) String() string {
	var buf strings.Builder
	if f != nil {
		g := *f
		if !isValidValue(g.Host) {
			g.Host = ""
		}
		if !isValidValue(g.Proto) {
			g.Proto = ""
		}
		f = &g
	}
	f.write(&buf)
	return buf.String()
}

// validate reports an error if f cannot be encoded as a valid Forwarded header.
func (f *Forwarded) validate() error {
	if f == nil {
		return nil
	}
	if !isValidValue(f.Host) {
		return errors.New("host contains a control character")
	}
	if !isValidValue(f.Proto) {
		return errors.New("proto contains a control character")
	}
	return nil
}

// write writes f to buf. f must pass validate.
func (f *Forwarded) write(buf *strings.Builder) {
	if f == nil || *f == (Forwarded{}) {
		buf.WriteString("for=unknown")
		return
	}
	start := buf.Len()
	writeNode(buf, start, "by", f.By)
	writeNode(buf, start, "for", f.For)
	writePair(buf, start, "host", f.Host)
	writePair(buf, start, "proto", f.Proto)
}

// Encode encodes the Forwarded header.
// It returns an error if a Host or Proto value contains a control character
// (other than HTAB), because such a value cannot be represented in a valid header.
func Encode(f []*Forwarded) (string, error) {
	for i, elem := range f {
		if err := elem.validate(); err != nil {
			return "", fmt.Errorf("forwardedheader: element %d: %w", i, err)
		}
	}
	if len(f) == 0 {
		return "", nil
	}

	var buf strings.Builder
	f[0].write(&buf)
	for i := 1; i < len(f); i++ {
		buf.WriteByte(',')
		f[i].write(&buf)
	}
	return buf.String(), nil
}

// maxElements is the maximum number of forwarded-elements that Parse accepts
// across all header values. It is far beyond any real proxy chain and bounds
// the number of Forwarded values a single untrusted header can make Parse
// allocate. It does not bound memory used for parameters or quoted values
// within an element.
const maxElements = 256

// Parse parses the Forwarded header.
// It returns an error if h contains more than 256 forwarded-elements in total.
func Parse(h []string) ([]*Forwarded, error) {
	ret := []*Forwarded{}
	for i, s := range h {
		var err error
		p := &parser{s: s, index: i}
		ret, err = p.parse(ret)
		if err != nil {
			return nil, err
		}
	}
	return ret, nil
}

type parser struct {
	s     string
	pos   int
	index int
}

// peek returns the next byte without advancing the parser.
func (p *parser) peek() int {
	if p.pos >= len(p.s) {
		return -1
	}
	return int(p.s[p.pos])
}

// next advances the parser and returns the current position.
func (p *parser) next() int {
	if p.pos >= len(p.s) {
		return -1
	}
	p.pos++
	return p.pos
}

func (p *parser) skipSpace() {
	for ch := p.peek(); ch == ' ' || ch == '\t'; ch = p.peek() {
		p.next()
	}
}

func (p *parser) newError(msg string) error {
	return &Error{
		Message: msg,
		Index:   p.index,
		Pos:     p.pos,
	}
}

// decodeToken decodes a token that is defined in RFC 7239 Section 4.
func (p *parser) decodeToken() (string, error) {
	p.skipSpace()
	start := p.pos
	for ch := p.peek(); ch >= 0 && validTchar[ch]; ch = p.peek() {
		p.next()
	}
	if start == p.pos {
		return "", p.newError("expected token but not")
	}
	return p.s[start:p.pos], nil
}

// decodeQuotedString decodes a quoted-string that is defined in RFC 7239 Section 4.
func (p *parser) decodeQuotedString() (string, error) {
	p.skipSpace()
	if p.peek() != '"' {
		return "", p.newError("expected '\"' but not")
	}
	p.next()

	var buf strings.Builder
	for {
		ch := p.peek()
		if ch < 0 {
			return "", p.newError("unexpected EOF")
		}
		if ch == '"' {
			p.next()
			break
		}
		if ch == '\\' {
			p.next()
			ch = p.peek()
			if ch < 0 {
				return "", p.newError("unexpected EOF")
			}
		}
		if !isValidQuotedChar(byte(ch)) {
			return "", p.newError("invalid character in quoted-string")
		}
		buf.WriteByte(byte(ch))
		p.next()
	}

	return buf.String(), nil
}

// decodeValue decodes a value that is defined in RFC 7239 Section 4.
func (p *parser) decodeValue() (string, error) {
	p.skipSpace()
	if p.peek() == '"' {
		return p.decodeQuotedString()
	}
	return p.decodeToken()
}

// decodeForwardedPair decodes a forwarded-pair that is defined in RFC 7239 Section 4.
func (p *parser) decodeForwardedPair() (string, string, error) {
	key, err := p.decodeToken()
	if err != nil {
		return "", "", err
	}

	p.skipSpace()
	if p.peek() != '=' {
		return "", "", p.newError("expected '=' but not")
	}
	p.next()

	value, err := p.decodeValue()
	if err != nil {
		return "", "", err
	}
	return key, value, nil
}

// decodeForwardedElement decodes a forwarded-element that is defined in RFC 7239 Section 4.
func (p *parser) decodeForwardedElement() (*Forwarded, error) {
	seen := map[string]bool{}
	f := &Forwarded{}

	p.skipSpace()
	if ch := p.peek(); ch < 0 || !validTchar[ch] {
		return f, nil
	}

	for {
		if len(seen) > 0 {
			p.skipSpace()
			if p.peek() != ';' {
				return f, nil
			}
			p.next()
		}

		key, value, err := p.decodeForwardedPair()
		if err != nil {
			return nil, err
		}
		key = strings.ToLower(key)
		if seen[key] {
			return nil, p.newError("duplicate key")
		}
		seen[key] = true

		switch key {
		case "by":
			node, err := p.parseNode(value)
			if err != nil {
				return nil, err
			}
			f.By = node
		case "for":
			node, err := p.parseNode(value)
			if err != nil {
				return nil, err
			}
			f.For = node
		case "host":
			// host is case-insensitive
			f.Host = strings.ToLower(value)
		case "proto":
			if strings.EqualFold(value, "https") {
				f.Proto = "https"
			} else if strings.EqualFold(value, "http") {
				f.Proto = "http"
			} else {
				f.Proto = strings.ToLower(value)
			}
		}
	}
}

func (p *parser) parseNode(s string) (Node, error) {
	s = strings.TrimSpace(s)
	if s == "" || strings.EqualFold(s, "unknown") {
		return Node{}, nil
	}

	var n Node
	portPos := strings.LastIndexByte(s, ':')

	if s[0] == '_' {
		// obfuscated node
		if portPos < 0 {
			n.ObfuscatedNode = s
		} else {
			n.ObfuscatedNode = s[:portPos]
		}
		if !isValidObf(n.ObfuscatedNode) {
			return Node{}, p.newError("invalid obfuscated node")
		}
	} else if s[0] == '[' {
		// ipv6
		end := strings.IndexByte(s, ']')
		if end < 0 {
			return Node{}, p.newError("missing ']' in address")
		}
		if portPos < end {
			portPos = -1
			if end != len(s)-1 {
				return Node{}, p.newError("unexpected ']' in address")
			}
		} else if portPos != end+1 {
			return Node{}, p.newError("unexpected ':' in address")
		}
		ip, err := netip.ParseAddr(s[1:end])
		if err != nil {
			return Node{}, err
		}
		if ip.Zone() != "" {
			return Node{}, p.newError("unexpected zone identifier")
		}
		n.IP = ip
	} else {
		// ipv4
		var ip netip.Addr
		var err error
		if portPos < 0 {
			ip, err = netip.ParseAddr(s)
		} else {
			ip, err = netip.ParseAddr(s[:portPos])
		}
		if err != nil {
			return Node{}, err
		}
		if ip.Zone() != "" {
			return Node{}, p.newError("unexpected zone identifier")
		}
		n.IP = ip
	}

	// parse port
	if portPos < 0 {
		return n, nil
	}
	if portPos+1 < len(s) && s[portPos+1] == '_' {
		// obfuscated port
		n.ObfuscatedPort = s[portPos+1:]
		if !isValidObf(n.ObfuscatedPort) {
			return Node{}, p.newError("invalid obfuscated port")
		}
	} else {
		port, err := strconv.Atoi(s[portPos+1:])
		if err != nil {
			return Node{}, err
		}
		n.Port = port
	}
	return n, nil
}

func (p *parser) parse(f []*Forwarded) ([]*Forwarded, error) {
	if len(f) >= maxElements {
		return nil, p.newError("too many elements")
	}
	elem, err := p.decodeForwardedElement()
	if err != nil {
		return nil, err
	}
	f = append(f, elem)

	for {
		p.skipSpace()
		ch := p.peek()
		if ch < 0 {
			// EOF
			break
		}
		if ch != ',' {
			return f, p.newError("expected ',' but not")
		}
		p.next()
		if len(f) >= maxElements {
			return nil, p.newError("too many elements")
		}
		elem, err := p.decodeForwardedElement()
		if err != nil {
			return nil, err
		}
		f = append(f, elem)
	}
	return f, nil
}
