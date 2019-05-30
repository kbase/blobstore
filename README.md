# KBase Blob store

Build status (master):
[![Build Status](https://travis-ci.org/kbase/blobstore.svg?branch=master)](https://travis-ci.org/kbase/blobstore) [![codecov](https://codecov.io/gh/kbase/blobstore/branch/master/graph/badge.svg)](https://codecov.io/gh/kbase/blobstore)

The blob store is a simple file storage service backed by an S3 compatible storage system
such as [Minio](https://min.io/). Storing a file provides a key - currently a UUID - that
allows retrival of the file when provided along with proper credentials.

The user is responsible for saving the key for use later - in the context of KBase, that means
creating a handle for the file via the [handle service](https://github.com/kbase/handle_service2)
and saving an object to the [workspace](https://github.com/kbase/workspace_deluxe) containing
that handle in an `@id handle` annotation, or saving the key directly in the workspace object
in an `@id bytestream` annotation. See the workspace documentation for details; also the
[DataFileUtil](https://github.com/kbaseapps/DataFileUtil) module can assist with these functions
in the context of KBase applications.

The API is nominally compatible with a minimal subset of the
[KBase fork of Shock's](https://github.com/kbase/Shock) API. The vast majority of functions are
not supported; only those required for the KBase codebase are included.

# Requirements:
* go 1.12
* An S3 compatible storage system. The Blobstore is tested with Minio version 2019-05-23T00-29-34Z.
  * If Minio is used, at least version 2019-05-14T23-57-45Z is required.
* MongoDB 2.6+

# Testing

Copy `test.cfg.example` to `test.cfg` and adjust the values as necessary.

```
BLOBSTORE_TEST_CFG=[absolute path to test.cfg] go test ./...
```

Each package gets its own working directory during tests so the path to the `test.cfg` file
cannot be relative.

Mocks are generated with https://github.com/vektra/mockery v1.0.0.


# Known issues

* Providing a `Content-Type` header of `multipart/form-data; boundary=` when trying to copy a node
  will result in the `go` function that parses multipart data asserting that the http body is
  not form data, and so the body will be processed as a file upload. This is an issue in the
  `go` `mime` library.

# TODO
* HTTP2 support

# S3/Minio experimental server

While exploring upload speeds with various upload methods,
[this server](https://github.com/MrCreosote/minioAWSAndGoClient) was generated.

