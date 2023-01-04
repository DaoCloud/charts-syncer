FROM alpine:3.15
RUN apk add --no-cache ca-certificates

ARG IMAGE_VERSION
ENV IMAGE_VERSION=${IMAGE_VERSION}

COPY charts-syncer /bin/
ENTRYPOINT [ "/bin/charts-syncer" ]
