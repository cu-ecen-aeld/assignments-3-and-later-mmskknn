#!/bin/bash
if [ $# -lt 2 ]; then
	echo "usage: $0 <writefile> <writestr>"
	exit 1
fi

writefile="$1"
writestr="$2"

dirpath=$(dirname  "$writefile")
if [ ! -d "$dirpath" ]; then
	mkdir -p "$dirpath"
fi

echo "$writestr" > "$writefile"

if [ $? -ne 0 ]; then
	echo "Failed to create or write to the file '$writefile'"
	exit 1
fi

exit 0 

