package main

import (
	"testing"

	"github.com/miekg/dns"
	"gopkg.in/yaml.v2"
)

func TestUnmarshalFilter(t *testing.T) {
	var filter nameFilter
	var yamlBytes = []byte(`[ sie-network.net, dnsdb.info ]`)

	err := yaml.Unmarshal(yamlBytes, &filter)
	if err != nil {
		t.Error(err)
	}
}

func testLookup(f nameFilter, name string, res bool) func(t *testing.T) {
	return func(t *testing.T) {
		msg := &dns.Msg{Question: []dns.Question{dns.Question{Name: name}}}
		m, err := msg.Pack()
		if err != nil {
			t.Errorf("Failed to pack message: %v", err)
		}

		match, err := f.FilterMsgQname(m)
		if err != nil {
			t.Errorf("FilterMsgQname error: %v", err)
		}
		if match != res {
			t.Errorf("FilterMsgQname(%s) returned %v, expected %v", name, match, res)
		}
	}
}

func TestFilterQuery(t *testing.T) {
	var filter nameFilter
	var yamlBytes = []byte(`[ sie-network.net, dnsdb.info ]`)

	err := yaml.Unmarshal(yamlBytes, &filter)
	if err != nil {
		t.Error(err)
	}

	for _, n := range []string{"sie-network.net.", "a1.sie-network.net.", "a.b.c.d.e.dnsdb.info."} {
		t.Run("match "+n, testLookup(filter, n, true))
	}

	for _, n := range []string{"sie-network.com.", "foo.net.", "info."} {
		t.Run("nomatch "+n, testLookup(filter, n, false))
	}
}
