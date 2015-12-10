#!/bin/bash
if [[ ! $1 ]]; then
    echo "usage: ./demo_wrapper.sh tenant_name"
    exit 1
fi
./demo.sh add-tenant $1 ||exit $?
./demo.sh create-public-net $1 ||exit $?
./demo.sh create-tenant-net $1 ||exit $?
./demo.sh boot-vm $1 ||exit $?
