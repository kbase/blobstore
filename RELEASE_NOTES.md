# 0.1.5

* Upgraded from go 1.12 to 1.16, which is now required
* Changed build base image from FROM `golang:1.12.5-alpine3.9` to `golang:1.16.15-alpine3.15`


# 0.1.4

* Added the `del` param when downloading the file from a node.
* The Blobstore will now look for auth tokens in cookies specified in the deployment configuration.
* The filename and format strings are now much more restrictive in regard to allowed contents.
  See the API documenation for details.
  * Any extant data is not affected and will be returned when requested as normal.

# 0.1.3

* Added GHA workflows and removed Travis CI
* MongoController is now compatible with Mongo versions 2 through 7
* Updated test config file to specify the auth2 shadow jar path vs. the jars repo path

# 0.1.2

* Support for disabling SSL verification of remote S3 certificates (default false)
  with the s3-disable-ssl-verify option in the configuration file.

# 0.1.1

* Added seek & length parameters to file download requests

# 0.1.0

* Initial release
