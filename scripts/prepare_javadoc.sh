#!/bin/sh

echo "Compute the current API version..."

version=$1

if [ "$2" = true ]
then
  version="$version-SNAPSHOT"
fi

echo "Computed current API version: $version"

repository_name=`git rev-parse --show-toplevel | xargs basename | cut -f2 -d'_'`
echo $repository_name

echo "Clone $repository_name..."
git clone https://github.com/eclipse/$repository_name.git

cd $repository_name

echo "Checkout gh-pages branch..."
git checkout -f gh-pages

echo "Delete existing SNAPSHOT directory..."
rm -rf *-SNAPSHOT

echo "Delete existing RC directories in case of final release..."
rm -rf $version-rc*

echo "Create target directory $version..."
mkdir $version

echo "Copy javadoc and uml files..."
cp -rf ../build/docs/javadoc/* $version/
cp -rf ../src/main/uml/api_*.svg $version/

echo "Update versions list..."
echo "| Version | Documents |" > list_versions.md
echo "|:---:|---|" >> list_versions.md
for directory in `ls -rd */ | cut -f1 -d'/'`
do
  diagrams=""
  for diagram in `ls $directory/api_*.svg | cut -f2 -d'/'`
  do
    name=`echo "$diagram" | tr _ " " | cut -f1 -d'.' | sed -r 's/^api/API/g'`
    diagrams="$diagrams<br>[$name]($directory/$diagram)"
  done
  echo "| $directory | [API documentation]($directory)$diagrams |" >> list_versions.md
done

echo "Computed all versions:"
cat list_versions.md

cd ..

echo "Local docs update finished."



