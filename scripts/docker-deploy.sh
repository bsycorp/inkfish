#!/bin/bash
docker login -u $DOCKERUSER -p $DOCKERPASS
docker tag  bsycorp/inkfish:${TRAVIS_BRANCH} bsycorp/inkfish:latest
docker push bsycorp/inkfish
