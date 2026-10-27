# Online scanner image for container-based serverless (Cloud Run, Zeabur, Fly.io, App Runner).
FROM golang:1.25 AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /phpscan-web ./cmd/phpscan-web

FROM gcr.io/distroless/static
COPY --from=build /phpscan-web /
ENTRYPOINT ["/phpscan-web"]
