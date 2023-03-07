# Dnstap Sensor for Farsight SIE

`dnstap-sensor` is an SIE sensor which reads Dnstap messages from
a Frame Streams socket and packages them for delivery to one or more
SIE submission servers or a UDP output.

## Building

`dnstap-sensor` may be built and installed with:

	go install github.com/farsightsec/dnstap-sensor@latest

Because `dnstap-sensor` has no non-go dependencies, cross compilation
is supported with:

        GOOS=<target-os>
        GOARCH=<target-arch>
        go install ...
