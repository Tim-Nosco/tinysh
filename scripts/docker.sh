#!/bin/bash

docker build -t tinysh .
docker run -it --rm -v $PWD:/opt/tinysh tinysh
