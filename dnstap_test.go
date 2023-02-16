/*
 * Copyright (c) 2019 Farsight Security, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package main

import (
	"bytes"
	"testing"
	"time"

	dnstap "github.com/dnstap/golang-dnstap"
	"github.com/golang/protobuf/proto"

	nmsg "github.com/farsightsec/go-nmsg"
	"github.com/farsightsec/go-nmsg/nmsg_base"
	"github.com/farsightsec/sielink"
)

type sliceClient []*dnstap.Dnstap

func (tc *sliceClient) Close() error                     { return nil }
func (tc *sliceClient) DialAndHandle(uri string) error   { return nil }
func (tc *sliceClient) Receive() <-chan *sielink.Payload { return nil }
func (tc *sliceClient) Subscribe(...uint32)              {}

func (tc *sliceClient) Send(p *sielink.Payload) error {
	inp := nmsg.NewInput(bytes.NewReader(p.GetData()), len(p.GetData()))
	msgs := *tc
	for {
		p, err := inp.Recv()
		if err != nil {
			break
		}
		m, err := p.Message()
		if err != nil {
			break
		}
		if dt, ok := m.(*nmsg_base.Dnstap); ok {
			msgs = append(msgs, &dt.Dnstap)
		}
	}
	*tc = msgs
	return nil
}

func TestDnstapMessageType(t *testing.T) {
	testCases := []dnstap.Dnstap{
		{Type: dnstap.Dnstap_MESSAGE.Enum(),
			Message: &dnstap.Message{
				Type: dnstap.Message_CLIENT_QUERY.Enum(),
			}},
		{Type: dnstap.Dnstap_MESSAGE.Enum(),
			Message: &dnstap.Message{
				Type: dnstap.Message_RESOLVER_RESPONSE.Enum(),
			}},
	}

	tclient := make(sliceClient, 0)

	ctx := &Context{
		Client: &tclient,
		Config: &Config{Channel: 203},
	}
	ctx.Config.Flush.Set("10ms")
	dtin := dnstapInput("in")
	dtch := make(chan []byte)

	go dtin.publish(ctx, dtch)
	for i := range testCases {
		tc := &testCases[i]
		b, err := proto.Marshal(tc)
		if err != nil {
			t.Error(tc, err)
		}
		dtch <- b
	}

	dtch <- make([]byte, 100)

	<-time.After(50 * time.Millisecond)
	if len(tclient) != 1 {
		t.Error("expected 1 message, got ", len(tclient))
	}
}

type chanClient chan *sielink.Payload

func (cc chanClient) DialAndHandle(uri string) error   { return nil }
func (cc chanClient) Receive() <-chan *sielink.Payload { return nil }
func (cc chanClient) Subscribe(...uint32)              {}

func (cc chanClient) Close() error {
	close(cc)
	return nil
}

func (cc chanClient) Send(p *sielink.Payload) error {
	cc <- p
	return nil
}

func TestWriterDiscard(t *testing.T) {
	testMessage, err := proto.Marshal(
		&dnstap.Dnstap{
			Type: dnstap.Dnstap_MESSAGE.Enum(),
			Message: &dnstap.Message{
				Type: dnstap.Message_RESOLVER_RESPONSE.Enum(),
			}})

	if err != nil {
		t.Fatal(err)
	}

	chClient := make(chanClient)
	ctx := &Context{
		Client: chClient,
		Config: &Config{Channel: 203},
	}
	ctx.Config.Flush.Set("10ms")
	dtin := dnstapInput("in")
	dtch := make(chan []byte)

	go dtin.publish(ctx, dtch)

	// First message goes through buffer, is picked up by the
	// sending goroutine
	dtch <- testMessage
	<-time.After(50 * time.Millisecond)
	// Second message stalls in the buffer
	dtch <- testMessage
	<-time.After(50 * time.Millisecond)
	// Third message should kick the above message out out,
	// and record a loss of one payload.
	dtch <- testMessage
	<-time.After(50 * time.Millisecond)

	// Fetch first message, should have loss counter zero
	p := <-chClient
	ploss := p.GetLinkLoss().GetPayloads()
	if ploss != 0 {
		t.Error("First message, loss not zero")
	}

	// Fetch third message, with expected loss
	p = <-chClient
	ploss = p.GetLinkLoss().GetPayloads()
	if ploss != 1 {
		t.Error("Third message in, second message out, loss is ", ploss)
	}
}
