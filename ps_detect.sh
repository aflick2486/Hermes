#!/bin/bash

# A script to check if being port scanned. Creates appropriate rule for banning the ip using firewalld or iptables.
# Written by Adam Flickema
# github.com/aflick2486
# aflickem@emich.edu

iptablesLog() {
	iptables -C INPUT -p tcp -j LOG --log-prefix "Log: " &> /dev/null	#Checks if rule in iptables already
	if [ $? != 0 ]; then
		iptables -A INPUT -p tcp -j LOG --log-prefix "Log: "		#If not then add it
	else
		:								#Else do nothing
	fi
	#Grab all ips from /var/log/messages
	cmd=`sudo cat /var/log/messages | /bin/grep "Log: " | awk '{print $10}' | sed s/SRC=// > /root/ips.txt`
	declare -A ips								#Declares an associative array
	file='/root/ips.txt'
	while read line; do
		ip=$(echo "$line" | cut -f1)					#Parses each line in /root/ips.txt
		if test "${ips[$ip]+isset}" ; then
			((ips[$ip]++))						#If already in the associative array, increase the value by 1 for each seen
		else
			ips[$ip]=1						#If first time seen, add ip as a key
		fi
	done < ${file}								#Close the file
	for key in "${!ips[@]}"; do
		if [ ${ips[$key]} -ge '20' ] ; then				#If the value for the ip is more than 20
			iptables -C INPUT -s $key -j DROP &> /dev/null		#Check if the ip is already banned
			if [ $? != 0 ]; then
				iptables -A INPUT -s $key -j DROP		#If not then ban it
			else
				:
			fi
		else
			:
		fi
	done
	dt=`date '+%Y-%m-%d %H:%M:%S'`						#Grab the date and time to put in the log file
	echo "$dt" >> /root/ps.log
	for domain in ${!ips[@]}; do
		echo "##################" >> /root/ps.log
		echo "$domain" >> /root/ps.log					#Put each ip into the log file
		`whois $domain >> /root/ps.log`					#Do a whois lookup on ip and put into the log file
		echo "##################" >> /root/ps.log
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
	dt=`date '+%Y-%m-%d %H%M%S'`
	echo "$dt" >> /root/ps.log
	for domain in ${!ips[@]}; do
		echo "##################" >> /root/ps.log
		echo "$domain" >> /root/ps.log
		`whois $domain >> /root/ps.log`					#Do a whois lookup on ip and put into the log file
		echo "##################" >> /root/ps.log
	done
}

# Determine which firewall installed, if both are installed uses iptables
if [ $(which iptables) ]; then							#Checks if iptables is installed
	echo "" > /root/ips.txt							#Clear the ips file
	iptablesLog								#Execute the iptables subroutine
elif [ $(which firewalld) ]; then						#Check if firewalld is installed
	echo "" > /root/ips.txt							#Clear ips file
	firewalldLog								#Execute the firewalld subroutine
else
	echo "No supported firewall. Exiting."
	exit 0
fi
