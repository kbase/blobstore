# KBase Blob store

The blob store is a simple file storage service backed by an S3 compatible storage system
such as [Minio](https://min.io/). Storing a file provides a key - currently a UUID - that
allows retrival of the file when provided along with proper credentials.

The user is responsible for saving the key for use later - in the context of KBase, that means
creating a handle for the file via the [handle service](https://github.com/kbase/handle_service2)
and saving an object to the [workspace](https://github.com/kbase/workspace_deluxe) containing that handle in an `@id handle` annotation, or saving the key directly in the workspace object in an `@id bytestream` annotation. See the workspace documentation for details; also the
[DataFileUtil](https://github.com/kbaseapps/DataFileUtil)
module can assist with these functions in the context of KBase applications.

The API is nominally compatible with a minimal subset of the
[KBase fork of Shock](https://github.com/kbase/Shock) API. The vast majority of functions are
not supported; only those required for the KBase codebase are included.


# Testing

Copy `test.cfg.example` to `test.cfg` and adjust the values as necessary.

```
BLOBSTORE_TEST_CFG=[absolute path to test.cfg] go test ./...
```

Each package gets its own working directory during tests so the path to the `test.cfg` file
cannot be relative.

# TODO
* HTTP2 support

