FROM golang:1.11 AS build-env
WORKDIR /src

COPY go.mod go.sum /src/
RUN apt-get --allow-releaseinfo-change update && apt upgrade -y
RUN go mod download
ADD . /src
RUN make
RUN useradd -u 10001 inkfish

FROM scratch
WORKDIR /
COPY --from=build-env /src/build/inkfish-linux /app/inkfish
COPY --from=build-env /etc/passwd /etc/passwd
USER inkfish

ENTRYPOINT ["/app/inkfish"]
CMD ["/app/inkfish"]