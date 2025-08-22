# this is creates an executable package and a binary package

%global provider        github
%global provider_tld    com
%global project         farsightsec
%global repo            dnstap-sensor
# https://github.com/farsightsec/dnstap-sensor
%global provider_prefix %{provider}.%{provider_tld}/%{project}/%{repo}
%global import_path     %{provider_prefix}
%global commit          ba3914c3f411de820f4df27d5de38adbf9f9f1e8
%global shortcommit     %(c=%{commit}; echo ${c:0:7})
%undefine _missing_build_ids_terminate_build

Name:           dnstap-sensor
Version:        0.3.0
Release:        1%{?dsist}
Summary:        Upload dnstap data to Farsight Security SIE 
License:        MPLv2.0
URL:            https://%{provider_prefix}
# using github generated tarball for now                                                    
Source0:        https://%{provider_prefix}/archive/%{commit}/%{repo}-%{shortcommit}.tar.gz

BuildRequires: golang-dnstap
BuildRequires: golang-github-farsightsec-sielink
BuildRequires: golang-github-farsightsec-go-nmsg-devel
BuildRequires: golang-google-protobuf-devel
BuildRequires: golang-golangorg-crypto-devel
#BuildRequires: golang(github.com/farsightsec/go-nmsg/nmsg_base)

%description
%{summary}

dnstap-sensor is an SIE sensor which reads Dnstap messages from a Frame Streams socket and packages them for delivery to one or more SIE submission servers.

%prep
%setup -q -n %{repo}-%{commit}

%build

#mkdir -p /builddir/go/src/github.com/dnstap
#ln -s $PWD /builddir/go/src/github.com/dnstap/dnstap-sensor
#find /builddir/go/src/github.com -ls
export GO111MODULE=off 
export GOPATH=/usr/share/gocode:/builddir/go
go build
pwd 
find . -ls
%install
install -d -p %{buildroot}%{_bindir}
install ./dnstap-sensor-%{commit} %{buildroot}/%{_bindir}/dnstap-sensor
install -d -p %{buildroot}%{_mandir}/man8
install ./dnstap-sensor.8 %{buildroot}%{_mandir}/man8/

%{!?_licensedir:%global license %doc}

%files
%{_bindir}/dnstap-sensor
%license LICENSE 
%doc README.md
%_mandir/man8/*

%changelog
