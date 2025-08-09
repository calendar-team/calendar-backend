FROM rust:1.89.0 AS build

WORKDIR /usr/src/calendar-backend
COPY . .

RUN cargo install --path .

FROM gcr.io/distroless/cc-debian12

COPY --from=build /usr/local/cargo/bin/calendar-backend /usr/local/bin/calendar-backend

CMD ["calendar-backend"]
