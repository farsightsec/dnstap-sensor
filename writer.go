/*
 * Copyright (c) 2017,2019 Farsight Security, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package main

import (
	"github.com/farsightsec/sielink"
	"github.com/golang/protobuf/proto"
)

// A payloadWriter packs up its input in a sielink Payload as an
// nmsg container with channel `channel`, and sends it over
// `writeChannel` to a writer goroutine writing to the client link.
//
// `writeChannel` has a buffer of size 1. If a a new payload is
// ready to send, and the previous payload hasn't been collected
// by the writer goroutine, the previous payload is dropped and
// its loss recorded in the new payload.
type payloadWriter struct {
	ctx          *Context
	channel      *uint32
	writeChannel chan *sielink.Payload
}

func newPayloadWriter(ctx *Context) *payloadWriter {
	wchan := make(chan *sielink.Payload, 1)
	res := &payloadWriter{
		ctx:          ctx,
		writeChannel: wchan,
		channel:      proto.Uint32(ctx.Config.Channel),
	}
	go func() {
		for p := range wchan {
			traceMsg(ctx, "Sending payload: len=%d loss=%d payloads",
				len(p.GetData()),
				p.GetLinkLoss().GetPayloads())
			ctx.Client.Send(p)
		}
	}()
	return res
}

func (c *payloadWriter) sendPayload(p *sielink.Payload) {
	for {
		// Note: this presumes cap(c.writeChannel) == 1
		// If c.writeChannel is larger, the "case discard := "
		// case needs to be moved under a default: case.
		select {
		case c.writeChannel <- p:
			c.ctx.NmsgUp.Messages++
			c.ctx.NmsgUp.Bytes += uint64(len(p.GetData()))
			return
		case discard := <-c.writeChannel:
			p.RecordDiscard(discard)
			c.ctx.NmsgDiscard.Messages++
			c.ctx.NmsgDiscard.Bytes += uint64(len(discard.GetData()))
		}
	}
}

func (c *payloadWriter) Write(b []byte) (int, error) {
	c.sendPayload(&sielink.Payload{
		Channel:     c.channel,
		PayloadType: sielink.PayloadType_NmsgContainer.Enum(),
		Data:        b,
	})
	return len(b), nil
}
