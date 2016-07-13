# S3Layer

A AWS S3 compatibility layer for custom data sources.

Still in early development, expect the API to change a lot.

# Example

You can check out [shs2](https://github.com/tsileo/shs2) for a basic usage example.

## S3 API compatibility

I'm not aiming for a 100% compatibility, but basic ACL support (for public object) is on the roadmap.

 - Listing bucket
 - List/Get/Put/Delete object
 - Basic canned ACL support (only support `private` and `public-read`)

I use `s3cmd` to ensure the API works, please open an issue if something is not working as attended.

Basically, the `s3cmd` `ls`, `get` and `put` works for now.
