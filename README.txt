Nicholas Vitale nvitale 1683587

Files:

Makefile-> the makefile for the assignment. creates an executable binary, myproxy.

README.txt-> the file you are reading.

bin (directory)-> no files in it, but when make is run, the binary will be placed here.

./bin/myproxy-> this binary file is the executable for the proxy server. it is a multithreaded proxy server that converts http requests received from clients into https requests, and appropriately sends the received responses back to their respective clients.

doc (directory)-> the directory that contains the documentation file for the assignment.

./doc/documentation.txt -> this file's purpose is to describe the methodology of the assignment, as well as 5 test cases that were utilized.

src (directory)-> the directory that contains all the source code for the assignment.

./src/server.c-> the implementation of the proxy server. contains main and a variety of other functions that are called by main.
