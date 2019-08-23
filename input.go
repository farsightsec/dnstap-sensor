/*
 * Copyright (c) 2017, 2019 Farsight Security, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package main

import (
	"log"

	"github.com/dnstap/golang-dnstap"
	"github.com/golang/protobuf/proto"

	"github.com/farsightsec/go-nmsg"
	"github.com/farsightsec/go-nmsg/nmsg_base"
)

type dnstapInput string

func (i dnstapInput) run(ctx *Context) {
	traceMsg(ctx, "Opening dnstap socket input at %s", i)
	fsinput, err := dnstap.NewFrameStreamSockInputFromPath(string(i))
	if err != nil {
		log.Fatalf("Could not listen on %s: %s", i, err.Error())
	}
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
	output := nmsg.TimedBufferedOutput(
		newPayloadWriter(ctx),
		ctx.Config.Flush.Duration,
	)
	output.SetMaxSize(nmsg.MaxContainerSize, 2*nmsg.MaxContainerSize)
	output.SetCompression(true)
	for b := range ch {
		ctx.DnstapIn.Messages++
		ctx.DnstapIn.Bytes += uint64(len(b))
		tapm, err := dnstapUnmarshal(b)
		if err != nil {
			ctx.DnstapError.Messages++
			ctx.DnstapError.Bytes += uint64(len(b))
			traceMsg(ctx, "Error unmarshaling Dnstap message: %s", err)
			continue
		}
		if tapm.GetMessage().GetType() != dnstap.Message_RESOLVER_RESPONSE {
			ctx.DnstapFiltered.Messages++
			ctx.DnstapFiltered.Bytes += uint64(len(b))
			traceMsg(ctx, "Filtering message of type %s", tapm.GetMessage().GetType())
			continue
		}
		p, err := nmsg.Payload(tapm)
		if err != nil {
			ctx.NmsgError.Messages++
			ctx.NmsgError.Bytes += uint64(len(b))
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
		err = output.Send(p)
		if err != nil {
			log.Fatal("Link error: ", err)
		}
	}
}
