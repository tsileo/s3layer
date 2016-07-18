# S3Layer

[![Travis](https://img.shields.io/travis/tsileo/s3layer.svg?maxAge=2592000)](https://travis-ci.org/tsileo/s3layer)

An AWS **S3** compatibility **layer** for custom data sources.

Still in early development, the API is still unstable.

## S3 API compatibility

I'm not aiming for a 100% compatibility.

Here what is working now:

 - Listing bucket
 - List/Get/Put/Delete object
 - Basic canned ACL support (only support for `private` and `public-read`, and can only be set via headers)
 - Multipart upload support (via an optional interface)

I use [s3cmd](http://s3tools.org/s3cmd) to ensure the API works, please open an issue if something is not working as expected.

### Supported authentication

**S3Layyer** supports two authentication methods:

 - [AWS Signature Version 4](http://docs.aws.amazon.com/general/latest/gr/signature-version-4.html) (the preferred way)
 - [AWS Signature Version 2](http://docs.aws.amazon.com/general/latest/gr/signature-version-2.html) (HMAC-SHA1 only)

## License

MIT, see LICENSE file.
