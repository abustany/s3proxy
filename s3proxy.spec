# debuginfo not supported with Go
%global debug_package %{nil}

Name:		s3proxy
Version:	1.0.0
Release:	1%{?dist}
Summary:	HTTP proxy authenticating requests to AWS S3 buckets

Group:		Applications/Internet
License:	GPLv2
URL:		https://github.com/ewdurbin/s3proxy

BuildRequires:	golang >= 1.1

# Download from a github release
Source0:	s3proxy-%{version}.tar.gz

%description
S3Proxy is an HTTP proxy that can be configured to authenticate requests to AWS
S3 buckets. That allows applications to access private buckets as normal
websites, without needing to know the API keys.

%prep
%setup -q -n s3proxy-%{version}

%build
GOPATH="%{_builddir}/s3proxy-%{version}" go install s3proxy

%check
GOPATH="%{_builddir}/s3proxy-%{version}" go test s3proxy

%install
install -D -m 0755 %{_builddir}/s3proxy-%{version}/bin/s3proxy \
                   $RPM_BUILD_ROOT%{_bindir}/s3proxy
install -D -m 0644 %{_builddir}/s3proxy-%{version}/config.json.dist \
	           $RPM_BUILD_ROOT%{_sysconfdir}/s3proxy/config.json.dist


%files
%defattr(-,root,root,-)
%doc README.md
%doc LICENSE
%{_sysconfdir}/s3proxy/config.json.dist
%{_bindir}/s3proxy

%changelog
* Fri Aug 29 2014 Ernest W. Durbin III <ewdurbin@gmail.com> - 1.0.0-1
- unhack rpm build tooling
* Tue Jul 09 2013 Adrien Bustany <adrien@bustany.org> - 0
- Initial specfile
