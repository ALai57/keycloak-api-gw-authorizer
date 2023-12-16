#!/usr/bin/env sh

PY_DIR='build/python/lib/python3.10/site-packages'

# Per this post, we need to build the AWS bundle for a specific platform
# because AWS linux is slightly different and doesn't have the same
# GCC version
# https://github.com/pyca/cryptography/issues/6391
# https://github.com/pyca/cryptography/issues/6390
mkdir -p $PY_DIR
pip freeze > requirements.txt

pip install \
    --platform manylinux2014_x86_64 \
    --implementation cp \
    --python 3.10 \
    --only-binary=:all: --upgrade \
    --target awsbundle \
    -r requirements.txt

rm dist/keycloak-authorizer.zip
cd awsbundle
zip -r ../dist/keycloak-authorizer.zip .
cd ../authorizer
zip ../dist/keycloak-authorizer.zip authorizer.py


# Old version of the build script - if we didn't need
# to install for a specific Linux version in AWS
#pip install -r requirements.txt -t $PY_DIR
#cd build
#zip -r ../dist/keycloak-authorizer-deps.zip .
