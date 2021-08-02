#!/bin/bash

# Create data-dir if not exists
mkdir -p /data

# TryCopy configs to data-dir
cp -n data/* /data/

# Execute daemon
python3 daemon.py