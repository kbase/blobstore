FROM golang:1.19.3-alpine3.15 as build

# git is not included, weirdly, so nothing with ext deps can build
RUN apk add git

COPY . /tmp/blobstore
RUN cd /tmp/blobstore \
    && export GIT_COMMIT=$(git rev-list -1 HEAD) \
    && go build -ldflags "-X main.gitCommit=$GIT_COMMIT" app/blobstore.go

FROM alpine:3.9.4

# These ARGs values are passed in via the docker build command
ARG BUILD_DATE
ARG VCS_REF
ARG BRANCH=develop

# Dockerize installation
RUN apk add wget ca-certificates
RUN wget -O dockerize.tar.gz https://github.com/kbase/dockerize/blob/ed320f524669d49edc7c8215d520ddd7e085c9fd/dockerize-alpine-linux-amd64-v0.6.1.tar.gz?raw=true \
    && tar -C /usr/local/bin -xzvf dockerize.tar.gz \
    && rm dockerize.tar.gz

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
      maintainer="Gavin Price gaprice@lbl.gov"

EXPOSE 8080
ENTRYPOINT [ "/usr/local/bin/dockerize" ]
WORKDIR /kb/deployment/blobstore
CMD [ "-multiline", \
      "-template", "/kb/deployment/conf/deployment.cfg.templ:/kb/deployment/blobstore/deployment.cfg", \
      "/kb/deployment/blobstore/blobstore", "--conf", "/kb/deployment/blobstore/deployment.cfg" ]
