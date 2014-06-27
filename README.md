Simple authenticating proxy for AWS S3
======================================

This proxy allows any application supporting HTTP proxies to access files in a
private S3 bucket (upload or download). The authorization headers are only sent
if the proxy detects a S3 URL (of the form `*.s3.amazonaws.com/*`). Multiple
buckets can be configured with different settings.

The proxy supports fetching tokens from an IAM role, so you don't have to store
the keys in clear text in the configuration file when running on an EC2 instance
with a properly configured role.

Transparent client-side AES encryption is supported. The size of your encryption
key (16, 24, or 32 characters) will determine whether 128, 192 or 256 bit
encryption is used. When encryption is used, files are encrypted on the fly
during upload, and decrypted during download. Encryption keys are defined per
bucket.

The difference between client side encryption and the server side encryption
also available in S3 is that with client side encryption, you keys are never
stored on Amazon servers.

Build
=====
You'll need Go 1.1 to compile s3proxy. Note that the Go tools are only needed
for compiling s3proxy, the resulting binary does not depend on any external
libraries.

- Export GOPATH to the root directory of s3proxy
- Run go install s3proxy

You should now have a s3proxy binary in bin/s3proxy

Setup
=====
- Copy config.json.dist to a file somewhere and edit the values inside
- Start the proxy, passing the path to the config file as the only command line
  parameter

Future
======
- Support wildcards in bucket configurations?
