#!/bin/bash

docker build -t tinysh:mipsel .
docker run -it --rm -v $PWD:/opt/tinysh tinysh:mipsel
