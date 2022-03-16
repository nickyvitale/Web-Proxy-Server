#!/bin/bash
echo Starting Test
# Assume server already running
# numCurlsToRun port file websites...
p=3
c=( "$@" )
for i in $(eval echo "{1..$1}") 
do
	echo starting curl
	echo curl -o dout/$3$i -x 127.0.0.1:$2 ${c[$p]}
	curl -o dout/$3$i -x 127.0.0.1:$2 ${c[$p]} &
	p=$(($p+1)) 
done
sleep 1
x=300
val=$( ps -e | grep curl | wc -l )
while [ $x -gt 0 ]
do
  sleep 1
  echo $x
  let x=$(( $x - 1 ))
  let val=$( ps -e | grep curl | wc -l )
  if [ $val -eq 0 ]
	then
		break
	fi
done
x=$(( 300 - $x ))
echo Test took $x seconds
killall curl &> /dev/null
# Full points: diff is empty
# Half points: diff has content
# No points: no return file
for i in $(eval echo "{1..$1}") 
	do
		a=0
		n=$(ls dout | grep $3$i | wc -l)
		a=$(($a+$n))
		if [ $a -eq 0 ]
			then
				echo Test $i Grade: 0
			else
				b=0
				c=$(diff $i dout/$3$i | wc -l)
				b=$(($b+$c))
				if [ $b -gt 0 ]
					then
						echo Test $i Grade: 0.5
					else
						echo Test $i Grade: 1
				fi
		fi
	done
echo Done
rm dout/*