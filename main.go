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
	"os"
	"strings"
	"time"

	"github.com/farsightsec/sielink/client"
)

// Context stores state and configuration referenced by multiple functions.
type Context struct {
	*Config
	client.Client
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

type stats struct {
	StartTime                             time.Time
	DnstapIn, DnstapError, DnstapFiltered statCounter
	QnameFiltered                         statCounter
	NmsgOut, NmsgError, NmsgDiscard       statCounter
}

func (s *stats) Log() {
	log.Printf("Uptime: %s dnstap-input %d bytes / %d msgs; "+
		"dnstap-error %d bytes / %d msgs; "+
		"dnstap-filtered %d bytes / %d msgs; "+
		"qname-filtered %d bytes / %d msgs; "+
		"nmsg-out %d bytes / %d msgs; "+
		"nmsg-error %d bytes / %d msgs; "+
		"nmsg-discard %d bytes / %d msgs; ",
		time.Duration(time.Since(s.StartTime).Seconds())*time.Second,
		s.DnstapIn.Bytes, s.DnstapIn.Messages,
		s.DnstapError.Bytes, s.DnstapError.Messages,
		s.DnstapFiltered.Bytes, s.DnstapFiltered.Messages,
		s.QnameFiltered.Bytes, s.QnameFiltered.Messages,
		s.NmsgOut.Bytes, s.NmsgOut.Messages,
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

	ctx.Client = client.NewClient(cconfig)
	ctx.stats.StartTime = time.Now()

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

	ticker := time.NewTicker(ctx.Config.StatsInterval.Duration)
	go func() {
		for _ = range ticker.C {
			ctx.stats.Log()
		}
	}()

	ctx.Config.DnstapInput.run(ctx)
}
