package main

import (
	"errors"
	"github.com/miekg/dns"
)

type nameFilter map[string]bool

func (n *nameFilter) AddString(name string) error {
	if *n == nil {
		*n = make(map[string]bool)
	}

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

		if n[string(name)] {
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

var errShortMessage = errors.New("DNS Message too short")
var errTruncMessage = errors.New("DNS Message truncated")
var errInvalidQname = errors.New("Invalid qname")

func (n nameFilter) FilterMsgQname(m []byte) (bool, error) {
	if n == nil {
		return false, nil
	}

	// Chop off 12-byte fixed DNS message header
	if len(m) <= 12 {
		return false, errShortMessage
	}
	m = m[12:]

	var qnameLen int
	for i := 0; i < len(m); i += int(m[i]) + 1 {
		if m[i] == 0 {
			qnameLen = i + 1
			break
		}
		if m[i] > 63 {
			return false, errInvalidQname
		}
	}
	if qnameLen == 0 {
		return false, errTruncMessage
	}

	return n.Lookup(m[:qnameLen]), nil
}
