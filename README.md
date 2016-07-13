# S3Layer

An AWS S3 compatibility layer for custom data sources.

Still in early development, the API is still unstable.

# Example

You can check out [shs2](https://github.com/tsileo/shs2) for a basic usage example.

## S3 API compatibility

I'm not aiming for a 100% compatibility.

Here what is working now:

 - Listing bucket
 - List/Get/Put/Delete object
 - Basic canned ACL support (only support `private` and `public-read`)

I use `s3cmd` to ensure the API works, please open an issue if something is not working as attended.
