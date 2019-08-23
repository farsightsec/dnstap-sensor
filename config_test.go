/*
 * Copyright (c) 2019 Farsight Security, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package main

import (
	"reflect"
	"strings"
	"testing"
)

func TestArgCompleteValid(t *testing.T) {
	testCases := []struct {
		Valid bool
		Args  []string
		Name  string
	}{
		{false, nil, "no args"},
		{false,
			[]string{"ws://test-submit.net"},
			"no apikey, input, channel"},
		{false,
			[]string{"-apikey", "foo", "ws://test-submit.net"},
			"no input, channel"},
		{false,
			[]string{"-input", "/tmp/foo.sock", "ws://test-submit.net"},
			"no apikey, channel"},
		{false,
			[]string{"-apikey", "foo", "-input", "/tmp/foo.sock",
				"ws://test-submit.net"},
			"no channel"},
		{true,
			[]string{"-apikey", "foo", "-input", "/tmp/foo.sock",
				"-channel", "25", "ws://test-submit.net"},
			"complete"},
		{false,
			[]string{"-apikey", "foo", "-input", "/tmp/foo.sock",
				"-channel", "25", "test-submit.net"},
			"bad url scheme"},
		{false,
			[]string{"-apikey", "foo", "-input", "/tmp/foo.sock",
				"-channel", "25", ":test-submit.net"},
			"bad url syntax"},
	}

	for _, tc := range testCases {
		_, err := parseConfig(tc.Args)
		switch tc.Valid {
		case true:
			if err != nil {
				t.Errorf("rejected valid argument set (%s): %v", tc.Name, err)
				break
			}
			t.Logf("%s - no error", tc.Name)
		case false:
			if err != nil {
				t.Logf("%s - %v", tc.Name, err)
				break
			}
			t.Errorf("accepted incomplete argument set (%s)", tc.Name)
		}
	}
}

func TestConfigValid(t *testing.T) {
	testCases := []struct {
		Valid bool
		Name  string
	}{
		{false, "no args"},
		{false,
			"no apikey, input, channel"},
		{false,
			"no input, channel"},
		{false,
			"no apikey, channel"},
		{false,
			"no channel"},
		{true,
			"complete"},
		{false,
			"bad url scheme"},
		{false,
			"bad url syntax"},
		{false,
			"invalid channel"},
	}

	for _, tc := range testCases {
		fname := "t/config/" + strings.Join(strings.Fields(
			strings.Replace(tc.Name, ",", "", -1)), "-") + ".conf"
		_, err := parseConfig([]string{"-config", fname})
		switch tc.Valid {
		case true:
			if err != nil {
				t.Errorf("rejected valid config (%s): %v", tc.Name, err)
				break
			}
			t.Logf("%s - no error", tc.Name)
		case false:
			if err != nil {
				t.Logf("%s - %v", tc.Name, err)
				break
			}
			t.Errorf("accepted incomplete config(%s)", tc.Name)
		}
	}
}

func TestConfigOverride(t *testing.T) {
	fname := "t/config/complete.conf"
	conf, err := parseConfig([]string{"-config", fname})
	if err != nil {
		t.Fatal("failed to parse config file: ", err)
	}

	overrides := []struct {
		Args      []string
		FieldName string
	}{
		// input - /tmp/foo.sock in config
		{[]string{"-input", "/tmp/bar.sock"}, "DnstapInput"},
		// apikey - foo
		{[]string{"-apikey", "bar"}, "APIKey"},
		// 	channel - 25
		{[]string{"-channel", "203"}, "Channel"},
		//      heartbeat - 30s
		{[]string{"-heartbeat", "1s"}, "Heartbeat"},
		//      retry - 30s
		{[]string{"-retry", "1s"}, "Retry"},
		// 	flush - 500ms
		{[]string{"-flush", "1s"}, "Flush"},
		//	servers - ws://test-submit.net
		{[]string{"ws://dev-submit.net"}, "Servers"},
	}

	for _, o := range overrides {
		args := append([]string{"-config", fname}, o.Args...)
		oconf, err := parseConfig(args)
		if err != nil {
			t.Error("failed to parse command line: ", args)
			continue
		}

		v := reflect.ValueOf(*conf).FieldByName(o.FieldName)
		ov := reflect.ValueOf(*oconf).FieldByName(o.FieldName)

		t.Logf("args: %v", args)
		t.Logf("old: %v", v)
		t.Logf("new: %v", ov)

		if v.Kind() == reflect.Slice {
			if v.Len() != ov.Len() {
				continue
			}
			for i := 0; i < v.Len(); i++ {
				if v.Index(i).Interface() == ov.Index(i).Interface() {
					t.Errorf("command line failed to override (element %d): %v", i, args)
				}
			}
			continue
		}

		if v.Interface() == ov.Interface() {
			t.Error("command line failed to override: ", args)
		}
	}
}
