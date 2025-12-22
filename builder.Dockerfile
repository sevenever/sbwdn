FROM alpine:3.20
RUN apk add git build-base libevent-dev confuse-dev libbsd-dev libevent-static confuse-static
RUN git config --global --add safe.directory /src

