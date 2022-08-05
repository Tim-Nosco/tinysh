#!/bin/bash

sudo rm -rf target

sudo service docker start
docker build -t tinysh:mipsel .
docker run -it --rm -v $PWD:/opt/tinysh tinysh:mipsel
