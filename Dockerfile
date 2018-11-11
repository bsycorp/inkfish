# build
FROM golang:1.11 AS build-env
ADD . /src
RUN cd /src && make

# run
FROM bitnami/minideb:stretch
WORKDIR /app
COPY --from=build-env /src/build/inkfish-linux /app/inkfish
CMD ["/app/inkfish"]
