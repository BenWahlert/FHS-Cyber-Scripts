#!/bin/bash
#
# "Copyright 2019 Canonical Limited. All rights reserved."
#
#--------------------------------------------------------

tmp_rule_file=$(mktemp --suffix _CIS)

function parseFirewallRules {
	declare i pp proto multiport allports FWrules=$1 version=$2

	# netstat output has a "6" added to protocol to indicate ipv6.
	# But ip6tables does not add a "6" to protocol. So in order to
	# properly match with netstat output, add a "6" to protocol for
	# ip6tables output.
	if [ "$version" != "6" ]; then
		version=""
	fi

	while read line; do
		echo $line | grep -E '^.+ACCEPT.*dpt:\w+\s+state\s+NEW' 2>&1 > /dev/null
		result=$?
		if [ $result -ne 0 ]; then
			#see if its a multiport entry
			echo $line | grep -E '^.+ACCEPT.*multiport\s+dports.*state\s+NEW' 2>&1 >/dev/null
			result=$?
			if [ $result -eq 0 ]; then
				# separate out the ports in the multiport
				proto="$(echo "$line" | awk '{print $4}')"
				if [ "$version" != "6" ]; then
					multiport="$(echo "$line" | awk '{print $12}')"
				else
					multiport="$(echo "$line" | awk '{print $11}')"
				fi
				allports=""
				for i in $(tr ',' ' ' <<< "$multiport"); do
					if [[ "$i" == *:* ]]; then
						pp=$(seq -s ' ' $(sed -n 's#\([0-9]\+\):\([0-9]\+\).*#\1 \2#p' <<< "$i"))
					else
						pp="$i"
					fi
					allports="$allports $pp"
				done
				# add each separated port to the database
				# for ipv6 add a "6" so we can distinguish what
				# came from ipv6 firewall...
				for i in $allports; do
					echo "$proto$version $i" >> $tmp_rule_file
				done
			fi
		else
			if [ "$version" != "6" ]; then
				port="$(echo "$line" | awk '{print $11}' | awk -F: '{print $NF}')"
			else
				port="$(echo "$line" | awk '{print $10}' | awk -F: '{print $NF}')"
			fi

			proto="$(echo "$line" | awk '{print $4}')"
			echo "$proto$version $port" >> $tmp_rule_file
		fi
	done <<< "$FWrules"
}

function do_Match {
	declare ip_port_combo local_ip local_port proto op=$1

	while read line; do
		ip_port_combo="$(echo $line | awk '{print $2}')"
		local_ip=${ip_port_combo%:*}
		local_port=${ip_port_combo##*:}
		proto="$(echo $line | awk '{print $1}')"

		if [ "$local_ip" = "::1" ] || [[ $local_ip =~ ^127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
			continue
		else
			# Search for a matching firewall rule
			grep  "^$proto $local_port" $tmp_rule_file 2>&1 > /dev/null
			result=$?
			if [ $result -ne 0 ]; then
				# See if it matches against "all" for protocol
				grep "^all $local_port" $tmp_rule_file 2>&1 > /dev/null
				result=$?
				if [ $result -ne 0 ]; then
					# no match found for the open port
					rm -rf $tmp_rule_file
					exit $XCCDF_RESULT_FAIL
				fi
			fi
		fi
	done <<< "$op"
}

# Get list of open ports
# If open_ports is empty, assume there were no socktes in LISTEN state
open_ports="$(netstat -ln | grep -E '\bLISTEN\b' | awk '//{print $1, $4}')"

# if there are no open ports, then Pass.
if [ -z "$open_ports" ]; then
	rm -rf $tmp_rule_file
	exit $XCCDF_RESULT_PASS
fi

# get input rules for ipv4 and ipv6
# if ip(6)tables_log is empty, assume the grep failed because there were
# no "ACCEPT" rules.
iptables_log="$(iptables -L INPUT -v -n | grep -E '^\s+\S+\s+\S+\s+ACCEPT.*')"

# get input rules for ipv6
ip6tables_log="$(ip6tables -L INPUT -v -n | grep -E '^\s+\S+\s+\S+\s+ACCEPT.*')"

# create database of rules to look at....
if [ -n "${iptables_log}" ]; then
	parseFirewallRules "$iptables_log" "4"
fi

if [ -n "${ip6tables_log}" ]; then
	parseFirewallRules "$ip6tables_log" "6"
fi

# if there are open ports but no firewall rules, then Fail.
if [ ! -s $tmp_rule_file ]; then
	rm -rf $tmp_rule_file
	exit $XCCDF_RESULT_FAIL
fi

# match open ports to firewall rules
do_Match "$open_ports"

# if we get here, all open ports were matched with a firewall rule
rm -rf $tmp_rule_file
exit $XCCDF_RESULT_PASS
