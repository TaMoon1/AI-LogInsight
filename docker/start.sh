#!/bin/sh
set -eu

uvicorn app.main:app --host 127.0.0.1 --port 8000 &
api_pid=$!
nginx -g 'daemon off;' &
nginx_pid=$!

stop_services() {
    kill "$api_pid" "$nginx_pid" 2>/dev/null || true
    wait "$api_pid" "$nginx_pid" 2>/dev/null || true
}
trap stop_services INT TERM

while kill -0 "$api_pid" 2>/dev/null && kill -0 "$nginx_pid" 2>/dev/null; do
    sleep 1
done
stop_services
