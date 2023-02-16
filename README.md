# Dnstap Sensor for Farsight SIE

`dnstap-sensor` is an SIE sensor which reads Dnstap messages from
a Frame Streams socket and packages them for delivery to one or more
SIE submission servers.

## Synopsis

    dnstap-sensor -channel <channel-number>
                  -input /path/to/dnstap.sock
                  [ -config /path/to/config.yaml ]
                  [ -apikey [key | /path/to/keyfile] ]
                  [ -stats_interval <interval> ]
                  [ -heartbeat <interval> ]
                  [ -retry <interval> ]
                  [ -flush <interval> ]
                  wss://server-1/session/dnstap-upload
                  [ wss://server-2/session/dnstap-upload ]

    dnstap-sensor -input /path/to/dnstap.sock
                  [ -config /path/to/config.yaml ]
                  [ -stats_interval <interval> ]
                  [ -flush <interval> ]
                  [ -mtu <size> ]
                  -udp_output udp:<address>:<port>
## Building

`dnstap-sensor` may be built and installed with:

	go get github.com/farsightsec/dnstap-sensor

	go build -o ${prefix:=/usr}/sbin/dnstap-sensor \
		github.com/farsightsec/dnstap-sensor

Because `dnstap-sensor` has no non-go dependencies, cross compilation
is supported with:

        GOOS=<target-os>
        GOARCH=<target-arch>
        go build -o ....

## Configuration

Configuration of `dnstap-sensor` can be stored in a config file or specified
on the command line. If a config file is specified, any command line values
override the corresponding values in the config file.

### Channel

The channel on which to send NMSG-encapsulated Dnstap data is a required
parameter when any `ws://` or `wss://` server URLs are configured. It
can be specified in the config file with:

        channel: 203

or on the command line with:

        -channel=203

### Dnstap Input  

`dnstap-sensor` collects input by opening a unix domain socket and accepting
connections from the DNS server. The path to this socket can be specified in
the config file with:

        dnstap_input: /path/to/input.sock

or on the command line with:

        -input=/path/to/input.sock

The input socket path is a required parameter. `dnstap-sensor` should run
as the same user as the DNS software connecting to it.

### Heartbeat and Retry

The server connections maintained by `dnstap-sensor` send periodic heartbeats
to instruct the server to keep the connection open. If the server connection
drops, `dnstap-sensor` attempts to reconnect after a given `retry` interval.

These can be specified in the config file with:

        heartbeat: 10s
        retry: 1s

or on the command line with:

        -heartbeat=10s -retry=1s

The interval is specified in the syntax supported by
(time.ParseDuration)[https://godoc.org/time#ParseDuration]. Both default to 30s.

Heartbeat and Retry intervals are ignored if no `ws://` or `wss://` server URLs
are configured.

### Flush Interval

`dnstap-sensor` will attempt to combine multiple Dnstap messages into large
containers. The flush interval provides a maximum time data will be buffered.
It can be specified in the config file with:

        flush: 400ms

or on the command line with:

        -flush=400ms

The default is 500ms.

### Statistics Interval

`dnstap-sensor` periodically logs statistics of its activity every 15 minutes
by default. This interval can be changed in the config file with:

	stats_interval: 1h

or on the command line with:

	-stats_interval 1h

a stats_interval of `0` turns off statistics logging.

### API Key

`dnstap-sensor` authenticates itself to the server with an API key. This can
be specified in the config file with:

        api_key: <key>

or:

        api_key: /path/to/keyfile

or on the command line with:

        -apikey=<key-or-file>

The API Key parameter is ignored if no `ws://` or `wss://` server URLs are
configured.

### Servers

The remainder of the command line arguments to `dnstap-sensor` is treated as
a list of server URLs. If none are specified on the command line, the values
from the config file (if any) are used. Servers can be specified in the config
file with:

        servers:
            - wss://server-1-hostname/session/<name>
            - wss://server-2-hostname/session/<name>

At least one server must be specified. If the `/session/` path is not given,
it defaults to `/session/dnstap-sensor-upload`.

### UDP Output

A UDP output address may be specified in the config file with:

	udp_output: udp:<address>:<port>

or on the command line with:

	-udp_output udp:<address>:<port>

The `udp:` prefix can be replaced with `udp4:` or `udp6:` to force IPv4
or IPv6 transport.

The UDP output may be used instead of or along with `ws://` or `ws://`
server URLs. If used together, the UDP output will mirror the data sent
to the configured servers.

The buffer size for the UDP output may be configured in the config file
with:

	mtu: <size>

or on the command line with:

	-mtu <size>

The default size is 1280, for transport over 1500 byte MTU ethernet. When
using loopback interfaces or jumbo frames, a larger `mtu` value is recommended
for efficiency.
