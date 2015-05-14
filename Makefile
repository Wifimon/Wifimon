# WIFIMON MAKEFILE - wifi monitor, analyzer, utility tool
# Authors: Daniele Paolini  -> daniele.paolini@hotmail.it
#          Lorenzo Vannucci -> ucci.dibuti@gmail.com
#          Marco Venturini  -> alexander00@hotmail.it

# Install this software executing 'make install' or 'make all'
# Clean the work directory and unistall this softare executing 'make clean'

# This code is distributed under the GPL License. For more info check:
# http://www.gnu.org/copyleft/gpl.html

# variables
CC = gcc
CFLAGS = -Wall -pedantic -lpcap
OBJECTS = wifimon *.json *.txt
SHELL = /bin/bash

# fake targets
.PHONY : all
.PHONY : install
.PHONY : clean

all : wifimon

install : wifimon

# real target
wifimon : wifimon.c
	@echo "==> Installing wifimon..."
	@$(CC) wifimon.c -o wifimon $(CFLAGS)
	@echo "==> Done!"

# clean target
clean :
	@echo "==> Uninstalling wifimon and cleaning..."
	@rm -f $(OBJECTS)
	@echo "==> Done!"
