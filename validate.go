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
    tls:
        $ref: "#/definitions/tls"
    filter_qnames:
        type: array
        items:
            type: string
            format: hostname
additionalProperties: false
definitions:
            tls:
                    type: object
                    properties:
                            rootCAFiles:
                                    type: array
                                    items:
                                            type: string
                            certificates:
                                    type: array
                                    items:
                                            type: object
                                            properties:
                                                    certFile:
                                                            type: string
                                                    keyFile:
                                                            type: string
                                            additionalProperties: false
                    additionalProperties: false

`)
var schema *gojsonschema.Schema

// stringifyMap converts a map[interface{}]interface{} as returned from
// yaml.Unmarshal into a map[string]interface{} usable by the json-schema
// library.
func stringifyMap(in map[interface{}]interface{}) map[string]interface{} {
	ret := make(map[string]interface{})
	for k, v := range in {
		key, ok := k.(string)
		if !ok {
			key = fmt.Sprintf("%s", k)
		}
		switch v := v.(type) {
		case []interface{}:
			ret[key] = stringifySlice(v)
		case map[interface{}]interface{}:
			ret[key] = stringifyMap(v)
		default:
			ret[key] = v
		}
	}
	return ret
}

// stringifySlice converts map[interface{}]interface{} elements of
// the input []interface{} to map[string]interface{} using stringifyMap
func stringifySlice(in []interface{}) []interface{} {
	var ret []interface{}
	for _, v := range in {
		switch v := v.(type) {
		case []interface{}:
			ret = append(ret, stringifySlice(v))
		case map[interface{}]interface{}:
			ret = append(ret, stringifyMap(v))
		default:
			ret = append(ret, v)
		}
	}
	return ret
}

func init() {
	var schemaObject map[interface{}]interface{}
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
	var configObject map[interface{}]interface{}
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
