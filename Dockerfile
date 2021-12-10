FROM golang:1.11 AS build-env
WORKDIR /src

COPY go.mod go.sum /src/
RUN apt-get --allow-releaseinfo-change update && apt upgrade -y
RUN go mod download
ADD . /src
RUN make

FROM bitnami/minideb:stretch
RUN useradd -u 10001 inkfish
RUN install_packages ca-certificates
COPY --from=build-env /src/build/inkfish-linux /app/inkfish
COPY --from=build-env /src/testdata/demo_config/ /config/demo
USER inkfish

CMD ["/app/inkfish"]
