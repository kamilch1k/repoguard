FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN go build -trimpath -ldflags="-s -w" -o /out/repoguard-api ./cmd/api
RUN go build -trimpath -ldflags="-s -w" -o /out/repoguard ./cmd/repoguard

FROM alpine:3.22
RUN adduser -D -H repoguard
USER repoguard
COPY --from=build /out/repoguard-api /usr/local/bin/repoguard-api
COPY --from=build /out/repoguard /usr/local/bin/repoguard
EXPOSE 8080
ENTRYPOINT ["repoguard-api"]
