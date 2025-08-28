/*
 * Copyright (c) 2017 Farsight Security, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package main

import (
	"bytes"
	"errors"
	"fmt"
	"log"

	"github.com/xeipuuv/gojsonschema"
	"gopkg.in/yaml.v2"
)

var schemaYaml = []byte(`
id: http://farsightsecurity.com/sie-router-config-schema#
$schema: http://json-schema.org/draft-04/schema#
description: dnstap sensor configuration
type: object
properties:
    servers:
        type: array
        items:
            type: string
            format: uri
    udp_output:
        type: string
    mtu:
        type: integer
        mininum: 512
        maximum: 1048576
    api_key:
        type: string
    channel:
        type: integer
        minimum: 1
    dnstap_input:
        type: string
    stats_interval:
        type: string
    heartbeat:
        type: string
    retry:
        type: string
    flush:
        type: string
    filter_qnames:
        type: array
        items:
            type: string
            format: hostname
additionalProperties: false
`)
var schema *gojsonschema.Schema

// stringifyMap converts a map[any]any as returned from
// yaml.Unmarshal into a map[string]any usable by the json-schema
// library.
func stringifyMap(in map[any]any) map[string]any {
	ret := make(map[string]any)
	for k, v := range in {
		key, ok := k.(string)
		if !ok {
			key = fmt.Sprintf("%s", k)
		}
		switch v := v.(type) {
		case []any:
			ret[key] = stringifySlice(v)
		case map[any]any:
			ret[key] = stringifyMap(v)
		default:
			ret[key] = v
		}
	}
	return ret
}

// stringifySlice converts map[any]any elements of
// the input []any to map[string]any using stringifyMap
func stringifySlice(in []any) []any {
	var ret []any
	for _, v := range in {
		switch v := v.(type) {
		case []any:
			ret = append(ret, stringifySlice(v))
		case map[any]any:
			ret = append(ret, stringifyMap(v))
		default:
			ret = append(ret, v)
		}
	}
	return ret
}

func init() {
	var schemaObject map[any]any
	err := yaml.Unmarshal(schemaYaml, &schemaObject)
	if err != nil {
		log.Fatal("init-yaml: ", err)
	}
	loader := gojsonschema.NewGoLoader(stringifyMap(schemaObject))
	schema, err = gojsonschema.NewSchema(loader)
	if err != nil {
		log.Fatalf("init-schema: %#v", err)
	}
}

type errList []error

func (e errList) Error() string {
	ebuf := new(bytes.Buffer)
	for i := range e {
		fmt.Fprintf(ebuf, "%s\n", e[i].Error())
	}
	return ebuf.String()
}

// Validate parses the configuration contents in the supplied buffer and
// returns nil if it is a valid config, or an appropriate error otherwise.
func Validate(b []byte) error {
	var configObject map[any]any
	err := yaml.Unmarshal(b, &configObject)
	if err != nil {
		return err
	}
	res, err := schema.Validate(gojsonschema.NewGoLoader(stringifyMap(configObject)))
	if err != nil {
		return err
	}
	if res.Valid() {
		return nil
	}

	errbuf := new(bytes.Buffer)
	for _, err := range res.Errors() {
		fmt.Fprintf(errbuf, "%s\n", err)
	}
	return errors.New(errbuf.String())
}
