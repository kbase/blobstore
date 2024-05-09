# KBase Blob store

Build status (master):
[![Build Status](https://travis-ci.org/kbase/blobstore.svg?branch=master)](https://travis-ci.org/kbase/blobstore) [![codecov](https://codecov.io/gh/kbase/blobstore/branch/master/graph/badge.svg)](https://codecov.io/gh/kbase/blobstore)

The blob store is a simple file storage service backed by an S3 compatible storage system
such as [Minio](https://min.io/). Storing a file provides a key - currently a UUID - that
allows retrival of the file when provided along with proper credentials. Once stored, files are
immutable other than deletion.

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

# API Data structures

## Node

This data structure is a subset of Shock's node data structure.

```
{
  "data": {
    "attributes": null,                               # DEPRECATED
    "created_on": "2019-05-30T23:50:19.000Z",
    "file": {
      "checksum": {
        "md5": "1b9554867d35f0d59e4705f6b2712cd1"
      },
      "name": "foo",                                  # Provided filename (see below)
      "size": 8
    },
    "format": "bar",                                  # Provided file format (see below)
    "id": "c39192c7-45b1-4fec-b196-5976d8e628f7",     # The node ID generated by the blobstore.
    "last_modified": "2019-05-30T23:50:19.000Z"
  },
  "error": null,
  "status": 200
}
```

`attributes` is deprecated, always null and is only provided for backwards compatibility reasons.

`last_modified` is always the same as `created_on` and is only included for backwards compatibility
reasons. Unlike Shock, the blobstore does not take ACL modifications into account when setting
the `last_modified` date.

## ACL

This data structure is a subset of Shock's ACL data structure.

```
{
  "data": {
    "delete": [User],
    "owner": User,
    "public": {
      "delete": false,
      "read:" <true if the node is publically readable, false otherwise>,
      "write": false
    },
    "read": [User...],
    "write": [User],
  },
  "error": null,
  "status": 200
}
```

`delete` and `write` ACLs are deprecated and only provided for backwards compatibility reasons.
They are always `false` for public access or contain only the node owner for standard ACLs.

A User is usually just the UUID assigned to the user by the blobstore, but when full verbosity
(see below) is requested, the User data structure is:

```
{
  "uuid": <the user's UUID assigned by the blobstore>,
  "username": <the user's KBase account name>
}
```

## Error

This data structure is identical to Shock's error data structure.
```
{
  "data": null,
  "error": [<error string>],
  "status": <http status code as an integer>
}
```

# API

Requests are authenticated by including the header `Authorization: OAuth <kbase token>` in the
request.

## Root

```
GET /
{
  "deprecationwarning": "The id and version fields are deprecated.",
  "id": "Shock",
  "servername": "blobstore",
  "servertime": <server time in epoch milliseconds>,
  "serverversion": <server version>,
  "version": "0.9.6"
  "gitcommit": <git commit from which the server was built>
}
```

The `id` and `version` fields are deprecated and present only for backwards compatibility with
Shock. The `version` field will not change.

## Upload a file / create a node
```
AUTHORIZATION REQUIRED
Content-Length header required
POST /node[?filename=<filename>&format=<file format>]
<file content>

RETURNS: a Node.
```

The `Content-Length` header must be present and accurate.

`PUT` is also supported - **but is not idempotent** - in order to ease using the `curl -T` option:

```
curl -H "Authorization: OAuth $KBASE_TOKEN" -T mylittlefile
  "http://<host>/node?filename=mylittlefile&format=text"
```

`filename` can be at most 256 characters with no control characters.  
`format` can be at most 100 characters with no control characters.

## Copy a node
```
AUTHORIZATION REQUIRED
POST /node/<id>/copy

RETURNS: a Node.
```

## Get a node
```
AUTHORIZATION OPTIONAL
GET /node/<id>

RETURNS: a Node.
```

## Get a node's ACLs
```
AUTHORIZATION OPTIONAL
GET /node/<id>/acl[?verbosity=full]

RETURNS: an ACL.
```

## Download a file from a node
```
AUTHORIZATION OPTIONAL
GET /node/<id>?download[_raw][&seek=#][&length=#][&del]

RETURNS: the file content.
```

`?download_raw`, as opposed to `?download`, causes the `Content-Disposition` header to be
omitted.

`seek` causes the first `#` bytes of the file to be skipped. A `seek` value greater than or equal
to the file size is an error. Defaults to 0.

`length` determines the number of bytes of the file to return after skipping `seek` bytes.
`length` may be greater than the remaining file length. Defaults to 0, which indicates that the
remainder of the file should be returned.

`del` causes the node to be deleted once the file contents have been streamed. The user must
be the node owner or a service administrator. Note this is playing very fast and loose with the
semantics of an HTTP GET.

## Set a node to be publicly readable
```
AUTHORIZATION REQUIRED
PUT /node/<id>/acl/public_read[?verbosity=full]

RETURNS: an ACL.
```

## Set a node to be privately readable
```
AUTHORIZATION REQUIRED
DELETE /node/<id>/acl/public_read[?verbosity=full]

RETURNS: an ACL.
```

## Add users to a node's read ACL

```
AUTHORIZATION REQUIRED
PUT /node/<id>/acl/read?users=<comma separated list of KBase user names>[&verbosity=full]

RETURNS: an ACL.
```

## Remove users from a node's read ACL

```
AUTHORIZATION REQUIRED
DELETE /node/<id>/acl/read?users=<comma separated list of KBase user names>[&verbosity=full]

RETURNS: an ACL.
```

## Change a node's owner
```
AUTHORIZATION REQUIRED
PUT /node/<id>/acl/owner?users=<KBase user name>[&verbosity=full]

RETURNS: an ACL.
```

The `users` parameter must contain a single user name.

## Upload a file / create a node via a MIME multipart form

This upload method is provided for Shock compatibilty. It is recommended that the prior upload
method is used rather than this one.

```
AUTHORIZATION REQUIRED
POST /node
<multipart form>

RETURNS: a Node.
```

The form **MUST** contain a part called `upload` where the part contents are the file to be
uploaded.
The part **MUST** have an accurate `Content-Length` header specifing the size of the file, **not**
the entire multipart form.

The form **may** contain a part called `format` where the part contents are the format of the
file, equivalent to the `format` query parameter for the standard upload method and with the same
restrictions. The `format` part **MUST** come before the `upload` part.

Any file name provided in the `Content-Disposition` header can be at most 256 characters with no
control characters.

### Curl example

```
curl -H "Authorization: OAuth $KBASE_TOKEN" \
  -F "upload=@mydata.fasta;headers=\"Content-Length: 67452\"" \
  http://<host>/node
```

### Python example

```python
import os
import requests
from requests_toolbelt.multipart.encoder import MultipartEncoder

df = open(filename, 'rb')
files = {'upload': (filename, df, None, {'Content-Length': os.path.getsize(filename)})}
mpe = MultipartEncoder(fields=files)
headers = {'Content-Type': mpe.content_type,
           'authorization': 'OAuth ' + token}

res = requests.post('http://<host>/node', headers=headers, data=mpe, stream=True)
res.json()
```

### Java example

```java
package blobstoreclienttest;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.apache.commons.io.IOUtils;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.mime.FormBodyPartBuilder;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.apache.http.entity.mime.content.InputStreamBody;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

public class blobstoreclient {
	
	public static void main(final String[] args) throws ClientProtocolException, IOException {
		final String fileName = args[0];
		final String token = args[1];
		// probably don't want to use the default client for most applications
		final CloseableHttpClient cli = HttpClients.createDefault();
		
		final HttpPost htp = new HttpPost("http://<host>/node");
		htp.setHeader("authorization", "OAuth " + token);

		final Path p = Paths.get(fileName);
		final MultipartEntityBuilder mpeb = MultipartEntityBuilder.create();
		final InputStream in = Files.newInputStream(p);
		
		mpeb.addPart(FormBodyPartBuilder.create()
				.setName("upload")
				.addField("Content-Length", "" + Files.size(p))
				.setBody(new InputStreamBody(in, p.getFileName().toString())).build());
		
		
		htp.setEntity(mpeb.build());
		
		final CloseableHttpResponse response = cli.execute(htp);
		in.close();
		IOUtils.copy(response.getEntity().getContent(), System.out);
		response.close();
	}
}
```

## Copy a node via a MIME multipart form

This copy method is provided for Shock compatibilty. It is recommended that the prior copy
method is used rather than this one.

```
AUTHORIZATION REQUIRED
POST /node
<multipart form>

RETURNS: a Node.
```

The multipart form must have exactly one part with the name `copy_data` and the value the id of
the node to copy.

Curl example:
```
curl -H "Authorization: OAuth $KBASE_TOKEN" -F "copy_data=<node id>" http://<host>/node/
```

# Requirements:
* go 1.12
* An S3 compatible storage system. The Blobstore is tested with Minio version 2019-05-23T00-29-34Z.
  * If Minio is used and the version is 2019-05-14T23-57-45Z or larger the server must
    be run in `--compat` mode.
* MongoDB 2.6+

# Running the server:
* An S3 compatible storage system and MongoDB must be running.
* Copy `deploy.cfg.example` to `deploy.cfg` and adjust the values as necessary.
* In the module directory:
  * `go build app/blobstore.go`
  * `./blobstore --conf deploy.cfg`

To build the git commit into the server:
```
export GIT_COMMIT=$(git rev-list -1 HEAD) 
    && go build -ldflags "-X main.gitCommit=$GIT_COMMIT" app/blobstore.go
```

# Developers

* Adding code
  * All code additions and updates must be made as pull requests directed at the develop branch.
    * All tests must pass and all new code must be covered by tests.
    * All new code must be documented appropriately
      * Godoc
      * General documentation if appropriate
      * Release notes
  * Exception mapping is handled in `server/errortypes.go`.
* Releases
  * The master branch is the stable branch. Releases are made from the develop branch to the master
    branch.
  * Update the version as per the semantic version rules in `app/blobstore.go`.
  * Tag the version in git and github.
    * Tags must follow the Go module semantic version format, e.g. `vX.Y.Z`.

## Testing

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

* Providing a `Content-Length` that is larger than the http body when uploading a file will
  cause the [connection to hang forever.](https://github.com/golang/go/issues/16100#issuecomment-267594064)
  (Note that a content length > file length looks the same to the server as a hanging upload.)

# TODO
* HTTP2 support

# S3/Minio experimental server

While exploring upload speeds with various upload methods,
[this server](https://github.com/MrCreosote/minioAWSAndGoClient) was generated.

