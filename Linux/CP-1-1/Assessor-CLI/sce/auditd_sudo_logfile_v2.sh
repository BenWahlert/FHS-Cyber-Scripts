#!/usr/bin/env sh

#
# CIS-CAT Script Check Engine
# 
# Name       Date       Description
# -------------------------------------------------------------------
# E. Pinnell  12/27/19   check auditd running config and /etc/audit/rules.d/*.rules for sudo logfile audit
#

LOGFILE="$(grep -r logfile /etc/sudoers* | sed -e 's/.*logfile=//;s/,? .*//' | tr -d \")"

if [ -n "$LOGFILE" ] ; then
	REGEXCK="^\s*-w\s+$(echo "$LOGFILE" | sed "s+/+\\\/+g;s+\.+\\\.+g")\s+-p wa\s+-k\s+actions\s*$"
	RULE="-w $LOGFILE -p wa -k actions"
	auditctl -l | grep -Eq "$REGEXCK" && grep -Eq "$REGEXCK" /etc/audit/rules.d/* && passing="true"
fi

# If the regex matched, output would be generated.  If so, we pass
if [ "$passing" = "true" ] ; then
	echo "Audit rule \"$RULE\" exists in the running config and an audit rules file"
	exit "${XCCDF_RESULT_PASS:-101}"
else
	# print the reason why we are failing
	[ -z "$LOGFILE" ] && echo "logfile not set in a file in the /etc/sudoers/ directory"
	! auditctl -l | grep -Eq "$REGEXCK" && echo "Audit rule $RULE not in the running auditd config"
	! grep -Eq "$REGEXCK" /etc/audit/rules.d/* && echo "Audit rule $RULE not in the a rule file in the /etc/audit/rules.d/ directory"
	exit "${XCCDF_RESULT_FAIL:-102}"
fi
