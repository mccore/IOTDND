#!/bin/bash
nc -lvp 3333 2> status 1> cowrie.json
ip=$(cat -A status | cut -d'[' -f 3 | cut -d']' -f 1)
date=$(date '+%Y-%m-%d-%H:%M')
if [ ! -d ./logs/"$(echo $ip)"_logs/ ]; then
  mkdir -p ./logs/"$(echo $ip)"_logs/;
else
	mv ./cowrie.json ./logs/"$(echo $ip)"_logs/"$(echo $date)"_cowrie.json
fi
#mv cowrie.json "$(echo $ip)"_"$(echo $date)"_cowrie.json