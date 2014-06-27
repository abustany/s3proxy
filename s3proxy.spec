# This specfile is a bit "weird" in the sense that it's meant to be run directly
# off the git repository, not with a tarball in the RPM source dir.
# Check the build-rpm.sh and build-srpm.sh scripts to see how to use it.

# debuginfo not supported with Go
%global debug_package %{nil}

%define latestcommitstamp %(git rev-list -n1 --format=format:%ct HEAD | tail -n1)
%define releasestr %(date -u +%Y%m%dT%H%M%SZ --date=@%{latestcommitstamp}).git%(git rev-list --abbrev-commit -n1 HEAD)

%if %{?s3proxy_intree_build:%{s3proxy_intree_build}}%{!?s3proxy_intree_build:0}
%define s3proxy_src_dir $RPM_SOURCE_DIR
%else
%define s3proxy_src_dir $(readlink -m .)
%endif

Name:		s3proxy
Version:	0
Release:	%{releasestr}%{?dist}
Summary:	HTTP proxy authenticating requests to AWS S3 buckets

Group:		Applications/Internet
License:	GPLv2
URL:		https://github.com/abustany/s3proxy

BuildRequires:	golang >= 1.1

%if %{?s3proxy_intree_build:%{s3proxy_intree_build}}%{!?s3proxy_intree_build:0}
# No need for a Source field since we're (ab)using $RPM_SOURCE_DIR
%else
Source0:	s3proxy-%{releasestr}.tar.bz2
%endif

%description
S3Proxy is an HTTP proxy that can be configured to authenticate requests to AWS
S3 buckets. That allows applications to access private buckets as normal
websites, without needing to know the API keys.

%prep
%if %{?s3proxy_intree_build:%{s3proxy_intree_build}}%{!?s3proxy_intree_build:0}
%else
%setup -q -n s3proxy-%{releasestr}
%endif

%build
export GOPATH="%{s3proxy_src_dir}"
go install s3proxy

%check
export GOPATH="%{s3proxy_src_dir}"
go test s3proxy

%install
install -D -m 0755 %{s3proxy_src_dir}/bin/s3proxy $RPM_BUILD_ROOT%{_bindir}/s3proxy
install -D -m 0644 %{s3proxy_src_dir}/config.json.dist \
	$RPM_BUILD_ROOT%{_sysconfdir}/s3proxy/config.json.dist

%files
%defattr(-,root,root,-)
%doc %{s3proxy_src_dir}/README.md %{s3proxy_src_dir}/LICENSE
%{_sysconfdir}/s3proxy/config.json.dist
%{_bindir}/s3proxy

%changelog
* Tue Jul 09 2013 Adrien Bustany <adrien@bustany.org> - 0
- Initial specfile
