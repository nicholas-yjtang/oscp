#!/bin/bash
start_http_server() {
    if [ -z "$http_port" ]; then
        echo "Define http_port before running start_http_server."
        return 1
    fi
    if [ $(port_in_use "$http_port") == "true" ]; then
        echo "Port $http_port is already in use. Assuming HTTP server is running."
        return 1
    fi
    echo "Starting HTTP server on port $http_port"
    python3 -m http.server $http_port
}