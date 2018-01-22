#!/bin/bash
DIRPATH=$1
if [ ! -d $DIRPATH/logs/ ]; then
	mkdir -p $DIRPATH/logs/
fi

while true; do
	nc -lkvp 3333 2> $DIRPATH/status 1> $DIRPATH/cowrie.json;
	ip=$(cat -A $DIRPATH/status | cut -d'[' -f 3 | cut -d']' -f 1);
	date=$(date '+%Y-%m-%d-%H:%M');
	if [ ! -d $DIRPATH/logs/"$(echo $ip)"_logs/ ]; then
	  mkdir -p $DIRPATH/logs/"$(echo $ip)"_logs/;
	fi
	mv $DIRPATH/cowrie.json $DIRPATH/logs/"$(echo $ip)"_logs/"$(echo $date)"_cowrie.json;
done