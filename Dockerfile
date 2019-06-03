FROM golang:1.12.5-alpine3.9 as build

# git is not included, weirdly, so nothing with ext deps can build
RUN apk add git

COPY . /tmp/blobstore
RUN cd /tmp/blobstore \
    && go build app/blobstore.go

FROM alpine:3.9.4

# These ARGs values are passed in via the docker build command
ARG BUILD_DATE
ARG VCS_REF
ARG BRANCH=develop

# Dockerize installation
RUN apk add wget
ENV DOCKERIZE_VERSION v0.6.1
RUN wget https://github.com/jwilder/dockerize/releases/download/$DOCKERIZE_VERSION/dockerize-linux-amd64-$DOCKERIZE_VERSION.tar.gz \
    && tar -C /usr/local/bin -xzvf dockerize-linux-amd64-$DOCKERIZE_VERSION.tar.gz \
    && rm dockerize-linux-amd64-$DOCKERIZE_VERSION.tar.gz

COPY --from=build /tmp/blobstore/deployment /kb/deployment/
RUN mkdir /kb/deployment/blobstore
COPY --from=build /tmp/blobstore/blobstore /kb/deployment/blobstore

RUN chmod a+x /kb/deployment/blobstore/blobstore

# The BUILD_DATE value seem to bust the docker cache when the timestamp changes, move to
# the end
LABEL org.label-schema.build-date=$BUILD_DATE \
      org.label-schema.vcs-url="https://github.com/kbase/blobstore.git" \
      org.label-schema.vcs-ref=$VCS_REF \
      org.label-schema.schema-version="1.0.0-rc1" \
      us.kbase.vcs-branch=$BRANCH \
      maintainer="Steve Chan sychan@lbl.gov"

EXPOSE 8080
ENTRYPOINT [ "/usr/local/bin/dockerize" ]
WORKDIR /kb/deployment/blobstore
CMD [ "-template", "/kb/deployment/conf/deployment.cfg.templ:/kb/deployment/blobstore/deployment.cfg", \
    "/kb/deployment/blobstore/blobstore", "--conf", "/kb/deployment/blobstore/deployment.cfg" ]
