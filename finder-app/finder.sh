#!/bin/sh
if [ $# -lt 2 ]; then
	echo "usage: $0 <filesdir> <searchstr>"
	exit 1
fi

filesdir="$1"
searchstr="$2"

if [ ! -d "$filesdir" ]; then
	echo "'$filesdir' does not exist or is not a directory"
	exit 1
fi

X=0
Y=0

for file in $(find "$filesdir" -type f); do
	X=$((X + 1))

	y=$(grep -c "$searchstr" "$file")
	Y=$((Y + y))
done

echo "The number of files are $X and the number of matching lines are $Y"
exit 0

