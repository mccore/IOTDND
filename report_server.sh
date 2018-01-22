#!/bin/bash
PATH=$1
if [ ! -d $PATH/logs/ ]; then
	mkdir -p $PATH/logs/
fi

while true; do
	nc -lvp 3333 2> $PATH/status 1> $PATH/cowrie.json;
	ip=$(cat -A status | cut -d'[' -f 3 | cut -d']' -f 1);
	date=$(date '+%Y-%m-%d-%H:%M');
	if [ ! -d $PATH/logs/"$(echo $ip)"_logs/ ]; then
	  mkdir -p $PATH/logs/"$(echo $ip)"_logs/;
	fi
	mv $PATH/cowrie.json $PATH/logs/"$(echo $ip)"_logs/"$(echo $date)"_cowrie.json;
done