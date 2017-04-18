#!/bin/bash

# A script to check if being port scanned. Creates appropriate rule for banning the ip.
# Written by Adam Flickema
# github.com/aflick2486
# aflickem@emich.edu

iptablesLog() {
	iptables-save | grep -- "-A INPUT -j LOG --log-prefix \"Log: \""
	if [ $? != 0 ]; then
		iptables -A INPUT -p tcp -j LOG --log-prefix "Log: "
	else
		:
	fi
	cmd=`sudo cat /var/log/messages | /bin/grep "Log: " | awk '{print $10}' | sed s/SRC=// > /root/ips.txt`
	declare -A ips
	file='/root/ips.txt'
	while read line; do
		ip=$(echo "$line" | cut -f1)
		if test "${ips[$ip]+isset}" ; then
			((ips[$ip]++))
		else
			ips[$ip]=1
		fi
	done < ${file}
	for key in "${!ips[@]}"; do
		if [ ${ips[$key]} -ge '20' ] ; then
			iptables-save | grep -- "-A INPUT -s $key -j DROP" &> /dev/null
			if [ $? != 0 ]; then
				iptables -A INPUT -s $key -j DROP
			else
				:
			fi
		else
			return
		fi
	done
}

firewalldLog(){
	firewall-cmd --list-all | grep -- "rule family=\"ipv4\" source NOT address=\"0.0.0.0\" log prefix=\"Log: \" accept" &> /dev/null
	if [ $? != 0 ]; then
		firewall-cmd --add-rich-rule='rule family="ipv4" source address="0.0.0.0" log prefix="Log: " accept'
	else
		:
	fi
	cmd=`sudo cat /var/log/messages | grep "Log: " |awk '{print $10}' | sed s/SRC=// > /root/ips.txt`
	declare -A ips
	file='/root/ips.txt'
	while read line; do
		ip=$(echo "$line" | cut -f1)
		if test "${ips[$ip]+isset}" ; then
			((ips[$ip]++))
		else
			ips[$ip]=1
		fi
	done < ${file}
	for key in "${!ips[@]}"; do
		if [ ${ips[$key]} -ge '20' ] ; then
			firewall-cmd --add-rich-rule="rule family='ipv4' source address="$key" drop"
		else
			:
		fi
	done
}


# Determine which firewall installed
if [ $(which iptables) ]; then
	echo "" > /root/ips.txt
	iptablesLog
elif [ $(which firewalld) ]; then
	echo "" > /root/ips.txt
	firewalldLog
else
	echo "No supported firewall. Exiting."
	exit 0
fi
