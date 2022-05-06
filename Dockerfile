FROM rust:1.54 as builder
ENV PKG_CONFIG_ALLOW_CROSS=1

WORKDIR /usr/src/auth-api
COPY ./Cargo.lock ./Cargo.lock
COPY ./Cargo.toml ./Cargo.toml
COPY ./src ./src

RUN cargo build --release

FROM gcr.io/distroless/cc-debian10

#EXPOSE 8080

COPY --from=builder /usr/src/auth-api/target/release/auth-api /usr/local/bin/auth-api

CMD ["auth-api"]
