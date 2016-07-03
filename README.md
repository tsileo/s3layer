# S3Layer

A AWS S3 compatibility layer for custom data sources.

# Example

You can check out [shs2](https://github.com/tsileo/shs2) for a basic usage example.

## S3 API compatibility

I'm not aiming for a 100% compatibility, but basic ACL support (for public object) is on the roadmap.

 - Listing bucket (bucket are automatically created when an object is put)
 - Get object, Put object

Basically, the `s3cmd` `ls`, `get` and `put` works for now.
