#!/bin/bash
docker login -u $DOCKERUSER -p $DOCKERPASS
docker build . -t bsycorp/inkfish:$TRAVIS_BRANCH
docker push bsycorp/inkfish