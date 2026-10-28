/*
 * Copyright (c) 2026 DomainTools LLC
 * Copyright (c) 2017, 2019 Farsight Security, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package main

import (
	"log"
	"net"
	"strings"

	dnstap "github.com/dnstap/golang-dnstap"
	"google.golang.org/protobuf/proto"

	"github.com/farsightsec/go-config"
	"github.com/farsightsec/go-nmsg"
	"github.com/farsightsec/go-nmsg/nmsg_base"
)

type dnstapInput string

func (i dnstapInput) run(ctx *Context) {
	var fsinput dnstap.Input
	var err error
	traceMsg(ctx, "Opening dnstap socket input at %s", i)
	var addr config.Addr
	if strings.Contains(string(i), ":") {
		err = addr.Set(string(i))
	} else {
		err = addr.Set("unix:" + string(i))
	}
	if err != nil {
		log.Fatalf("Invalid input address '%s'", string(i))
	}
	listener, err := net.Listen(addr.Network(), addr.String())
	if err != nil {
		log.Fatalf("Could not listen on %s: %s", i, err.Error())
	}
	fsinput = dnstap.NewFrameStreamSockInput(listener)
	ch := make(chan []byte, 100)
	go i.publish(ctx, ch)
	fsinput.ReadInto(ch)
	log.Printf("input %s finished", i)
}

func dnstapUnmarshal(b []byte) (*nmsg_base.Dnstap, error) {
	d := new(nmsg_base.Dnstap)
	err := proto.Unmarshal(b, d)
	if err != nil {
		return nil, err
	}
	return d, nil
}

func (i dnstapInput) publish(ctx *Context, ch <-chan []byte) {
	var outputs []nmsg.Output
	if ctx.Client != nil {
		output := nmsg.TimedBufferedOutput(
			newPayloadWriter(ctx),
			ctx.Config.Flush.Duration,
		)
		output.SetMaxSize(nmsg.MaxContainerSize, 2*nmsg.MaxContainerSize)
		output.SetCompression(true)
		outputs = append(outputs, output)
	}
	if ctx.Output != nil {
		outputs = append(outputs, ctx.Output)
	}
	for b := range ch {
		ctx.DnstapIn.Messages.Add(1)
		ctx.DnstapIn.Bytes.Add(uint64(len(b)))
		tapm, err := dnstapUnmarshal(b)
		if err != nil {
			ctx.DnstapError.Messages.Add(1)
			ctx.DnstapError.Bytes.Add(uint64(len(b)))
			traceMsg(ctx, "Error unmarshaling Dnstap message: %s", err)
			continue
		}
		if tapm.GetMessage().GetType() != dnstap.Message_RESOLVER_RESPONSE {
			ctx.DnstapFiltered.Messages.Add(1)
			ctx.DnstapFiltered.Bytes.Add(uint64(len(b)))
			traceMsg(ctx, "Filtering message of type %s", tapm.GetMessage().GetType())
			continue
		}
		ok, _ := ctx.Config.FilterQnames.FilterMsgQname(tapm.GetMessage().GetResponseMessage())
		if ok {
			ctx.QnameFiltered.Messages.Add(1)
			ctx.QnameFiltered.Bytes.Add(uint64(len(b)))
			if ctx.Trace {
				b, ok := dnstap.TextFormat(&tapm.Dnstap)
				if ok {
					traceMsg(ctx, "Qname filtered response: %s", string(b))
				} else {
					traceMsg(ctx, "Qname filtered response: formatting failed")
				}
			}
			continue
		}
		p, err := nmsg.Payload(tapm)
		if err != nil {
			ctx.NmsgError.Messages.Add(1)
			ctx.NmsgError.Bytes.Add(uint64(len(b)))
			traceMsg(ctx, "Error converting to NMSG: %s", err)
			continue
		}
		if ctx.Trace {
			b, ok := dnstap.TextFormat(&tapm.Dnstap)
			if ok {
				traceMsg(ctx, "Submitting response: %s", string(b))
			} else {
				traceMsg(ctx, "Submitting response: formatting failed")
			}
		}
		for _, o := range outputs {
			err = o.Send(p)
			if err != nil {
				log.Fatal("Output error: ", err)
			}
		}
	}
}
