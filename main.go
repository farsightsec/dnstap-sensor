/*
 * Copyright (c) 2017, 2019 Farsight Security, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package main

import (
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/farsightsec/go-nmsg"
	"github.com/farsightsec/sielink/client"
)

// Context stores state and configuration referenced by multiple functions.
type Context struct {
	*Config
	client.Client
	nmsg.Output
	stats
}

func traceMsg(ctx *Context, fmt string, args ...interface{}) {
	if !ctx.Trace {
		return
	}
	log.Printf(fmt, args...)
}

type statCounter struct {
	Bytes, Messages uint64
}

func (sc *statCounter) Add(n uint64) {
	if sc == nil {
		return
	}
	sc.Bytes += n
	sc.Messages++
}

type statWriter struct {
	wstats   *statCounter
	errstats *statCounter
	io.Writer
}

func (sw *statWriter) Write(p []byte) (n int, err error) {
	n, err = sw.Writer.Write(p)
	if err != nil {
		sw.errstats.Add(uint64(n))
		return
	}
	sw.wstats.Add(uint64(n))
	return
}

type stats struct {
	StartTime                             time.Time
	DnstapIn, DnstapError, DnstapFiltered statCounter
	QnameFiltered                         statCounter
	NmsgOut                               statCounter
	NmsgUp, NmsgError, NmsgDiscard        statCounter
}

func (s *stats) Log() {
	log.Printf("Uptime: %s dnstap-input %d bytes / %d msgs; "+
		"dnstap-error %d bytes / %d msgs; "+
		"dnstap-filtered %d bytes / %d msgs; "+
		"qname-filtered %d bytes / %d msgs; "+
		"nmsg-out %d bytes / %d msgs; "+
		"nmsg-up %d bytes / %d msgs; "+
		"nmsg-error %d bytes / %d msgs; "+
		"nmsg-discard %d bytes / %d msgs; ",
		time.Duration(time.Since(s.StartTime).Seconds())*time.Second,
		s.DnstapIn.Bytes, s.DnstapIn.Messages,
		s.DnstapError.Bytes, s.DnstapError.Messages,
		s.DnstapFiltered.Bytes, s.DnstapFiltered.Messages,
		s.QnameFiltered.Bytes, s.QnameFiltered.Messages,
		s.NmsgOut.Bytes, s.NmsgOut.Messages,
		s.NmsgUp.Bytes, s.NmsgUp.Messages,
		s.NmsgError.Bytes, s.NmsgError.Messages,
		s.NmsgDiscard.Bytes, s.NmsgDiscard.Messages,
	)
}

func main() {
	var err error

	// leave date stamp to external logger.
	log.SetFlags(0)

	ctx := new(Context)
	ctx.Config, err = parseConfig(os.Args[1:])
	if err != nil {
		log.Fatal(err)
	}

	cconfig := &client.Config{
		Heartbeat: ctx.Config.Heartbeat.Duration,
		URL:       "http://localhost/dnstap-client",
		APIKey:    ctx.Config.APIKey.String(),
	}

	ctx.stats.StartTime = time.Now()

	if len(ctx.Config.Servers) > 0 {
		ctx.Client = client.NewClient(cconfig)
	}

	for _, s := range ctx.Config.Servers {
		if !strings.HasPrefix(s.Path, "/session/") {
			s.Path = "/session/dnstap-sensor-upload"
		}
		go func(uri string) {
			for {
				log.Printf("Connecting to %s", uri)
				log.Printf("%s: connection closed: %v", uri, ctx.Client.DialAndHandle(uri))
				if ctx.Config.Retry.Duration == 0 {
					log.Printf("No retry specified. Abandoning %s", uri)
					return
				}
				<-time.After(ctx.Config.Retry.Duration)
			}
		}(s.String())
	}

	if ctx.Config.UDPOutput.UDPAddr != nil {
		conn, err := net.DialUDP("udp", nil, ctx.Config.UDPOutput.UDPAddr)
		if err != nil {
			log.Fatalf("Failed to dial %s: %v", ctx.Config.UDPOutput, err)
		}
		statConn := &statWriter{
			Writer: conn,
			wstats: &ctx.NmsgOut,
		}
		ctx.Output = nmsg.TimedBufferedOutput(statConn, ctx.Config.Flush.Duration)
		ctx.Output.SetSequenced(true)
		ctx.Output.SetMaxSize(ctx.Config.MTU, ctx.Config.MTU)
	}

	ticker := time.NewTicker(ctx.Config.StatsInterval.Duration)
	go func() {
		for _ = range ticker.C {
			ctx.stats.Log()
		}
	}()

	ctx.Config.DnstapInput.run(ctx)
}
