For unknown reasons downloading this version of minio from their site is unreliable and often
fails. As such it's checked in here. 

When upgrading to a new version, check the reliability of the download and prefer using their
site to obtain the binary.

The original setup lines in the GHA test file were:

```
wget -q https://dl.minio.io/server/minio/release/linux-amd64/archive/minio.RELEASE.${{matrix.minio}} -O minio
chmod a+x minio
export MINIOD=`pwd`/minio
```
