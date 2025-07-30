#!/bin/bash
start_http_server() {
    if [ ! -z "$1" ]; then
        http_port=$1
    fi
    if [ -z "$http_port" ]; then
        echo "Going to use default HTTP port 8000"
        http_port=8000
    fi
    if [ -z "$http_ip" ]; then
        http_ip=$(get_host_ip)
    fi
    if pgrep -f "python3 -m http.server $http_port"; then
        echo "HTTP server is already running on port $http_port."
        return 1
    fi
    echo "Starting HTTP server on port $http_port"
    python3 -m http.server $http_port | tee -a $trail_log 2>&1 &
}

stop_http_server() {
    if [ ! -z "$1" ]; then
        http_port=$1
    fi
    if pgrep -f "python3 -m http.server $http_port"; then
        echo "Stopping HTTP server on port $http_port"
        pkill -f "python3 -m http.server $http_port"
    else
        echo "No HTTP server is running on port $http_port."
    fi
}

start_webdav_server() {
    if [ -z "$http_port" ]; then
        echo "Going to use default HTTP port 8000"
        http_port=8000
    fi
    if [ -z "$http_ip" ]; then
        http_ip=$(get_host_ip)
    fi   
    echo "port: $http_port" > config.yml
    echo "directory: /data" >> config.yml
    echo "permissions: RC" >> config.yml
    echo "debug: true" >> config.yml
    echo "Starting WebDAV server on port $http_port"
    sudo docker run -d -p $http_port:$http_port -v "$(pwd)/config.yml:/config.yml:ro" -v "$(pwd):/data" hacdias/webdav:latest -c /config.yml

}

stop_webdav_server(){

    container_id=$(sudo docker ps -f ancestor=hacdias/webdav --format "{{.ID}}")
    if [ ! -z "$container_id" ]; then
        echo "Stopping WebDAV server with container ID: $container_id"  
        sudo docker stop $container_id
    fi

}