package main

import (
	"errors"
	"github.com/miekg/dns"
	"strings"
)

type nameFilter map[string]bool

func (n *nameFilter) AddString(name string) error {
	if *n == nil {
		*n = make(map[string]bool)
	}

	name = strings.ToLower(name)
	if name[len(name)-1] != '.' {
		name += "."
	}
	b := make([]byte, len(name)+1)
	_, err := dns.PackDomainName(name, b, 0, nil, false)
	if err != nil {
		return err
	}
	(*n)[string(b)] = true
	return nil
}

func (n nameFilter) Lookup(name []byte) bool {
	for len(name) > 0 {
		llen, rest := name[0], name[1:]

		// Uncompressed DNS names have label lengths
		// between 0 and 63, with 0 terminating the name.
		if llen == 0 || llen > 63 {
			break
		}

		if int(llen) > len(rest) {
			break
		}

		if n[strings.ToLower(string(name))] {
			return true
		}
		name = rest[llen:]
	}
	return false
}

func (n *nameFilter) UnmarshalYAML(u func(interface{}) error) error {
	var l []string
	var err error

	err = u(&l)
	if err != nil {
		return err
	}

	for _, name := range l {
		err = n.AddString(name)
		if err != nil {
			return err
		}
	}
	return nil
}

func (n *nameFilter) Set(s string) error {
	return n.AddString(s)
}

func (n *nameFilter) String() string {
	return ""
}

var errShortMessage = errors.New("DNS Message too short")
var errTruncMessage = errors.New("DNS Message truncated")
var errInvalidQname = errors.New("Invalid qname")

func lowerByte(b byte) byte {
	const lower = byte('a') - byte('A')
	if b >= byte('A') && b <= byte('Z') {
		return b + lower
	}
	return b
}

func (n nameFilter) FilterMsgQname(m []byte) (bool, error) {
	if n == nil {
		return false, nil
	}

	// Chop off 12-byte fixed DNS message header
	if len(m) <= 12 {
		return false, errShortMessage
	}

	// Pass if qdcount != 1
	if m[4] != 0 || m[5] != 1 {
		return false, nil
	}

	m = m[12:]

	var name []byte
	for i := 0; i < len(m); i += int(m[i]) + 1 {
		llen := int(m[i])
		if llen == 0 {
			name = append(name, 0)
			break
		}
		if llen > 63 {
			return false, errInvalidQname
		}

		lend := llen + i + 1
		if lend >= len(m) {
			return false, errTruncMessage
		}
		name = append(name, byte(llen))

		label := m[i+1 : lend]
		for _, b := range label {
			name = append(name, lowerByte(b))
		}
	}
	if len(name) == 0 {
		return false, errTruncMessage
	}

	return n.Lookup(name), nil
}
