%define latestcommitstamp %(git rev-list -n1 --format=format:%ct HEAD | tail -n1)
%define releasestr %(date -u +%Y%m%dT%H%M%SZ --date=@%{latestcommitstamp}).git%(git rev-list --abbrev-commit -n1 HEAD)

Name:		s3proxy
Version:	0
Release:	%{releasestr}%{?dist}
Summary:	HTTP proxy authenticating requests to AWS S3 buckets

Group:		Applications/Internet
License:	GPLv2
URL:		https://github.com/abustany/s3proxy

%description
S3Proxy is an HTTP proxy that can be configured to authenticate requests to AWS
S3 buckets. That allows applications to access private buckets as normal
websites, without needing to know the API keys.

%prep

%build
echo $RPM_SOURCE_DIR
export GOPATH=$RPM_SOURCE_DIR
go install s3proxy

%check
export GOPATH=$RPM_SOURCE_DIR
go test s3proxy

%install
install -D -m 0755 $RPM_SOURCE_DIR/bin/s3proxy $RPM_BUILD_ROOT%{_bindir}/s3proxy
install -D -m 0644 $RPM_SOURCE_DIR/config.json.dist \
	$RPM_BUILD_ROOT%{_sysconfdir}/s3proxy/config.json.dist

%files
%defattr(-,root,root,-)
%doc $RPM_SOURCE_DIR/README $RPM_SOURCE_DIR/LICENSE
%{_sysconfdir}/s3proxy/config.json.dist
%{_bindir}/s3proxy

%changelog
* Tue Jul 09 2013 Adrien Bustany <adrien@bustany.org> - 0
- Initial specfile
