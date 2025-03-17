#!/bin/bash
g++ -o test test.cpp other/GWABE.cpp other/LSSS.cpp other/utilities.cpp -lpbc -lgmp -fopenmp -lcrypto
./test

