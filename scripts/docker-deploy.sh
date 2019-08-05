#!/bin/bash
docker login -u $DOCKERUSER -p $DOCKERPASS
docker tag  bsycorp/inkfish:${TRAVIS_BRANCH} bsycorp/inkfish:latest
docker tag  bsycorp/inkfish:${TRAVIS_BRANCH}-slim bsycorp/inkfish:latest-slim
docker push bsycorp/inkfish
