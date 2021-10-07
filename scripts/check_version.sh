#!/bin/sh

version=$1
echo "Input version : '$version'"

echo "Fetch tags..."
git fetch --tags

if [ $(git tag -l "$version") ]; then
  echo "ERROR: version '$version' has already been released"
  exit 1
fi
