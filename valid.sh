#!/bin/bash
a=0
x=$(ls bin)
for i in $x
do
	b=$(cat bin/$i | grep fork | wc -l)
	a=$(($a+$b))
done
echo Validate Forks Found $a