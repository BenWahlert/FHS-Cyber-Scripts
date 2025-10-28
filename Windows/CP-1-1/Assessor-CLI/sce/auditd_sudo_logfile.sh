#!/usr/bin/env sh

#
# CIS-CAT Script Check Engine
# 
# Name       Date       Description
# -------------------------------------------------------------------
# E. Pinnell  11/06/13   check auditd running config and /etc/audit/rules.d/*.rules for sudo logfile audit
# E. Pinnell  02/10/20   Updated to allow for any key value in the audit rule
#

LOGFILE="$(grep -r logfile /etc/sudoers* | sed -e 's/.*logfile=//;s/,? .*//' | tr -d \")"

if [ -n "$LOGFILE" ] ; then
	RULE="^\s*-w\s+$LOGFILE\s+-p\s+wa\s+-k\s+\S+ *$"
	[ -n "$(auditctl -l | grep -E "$RULE")" ] && [ -n "$(grep -E "$RULE" /etc/audit/rules.d/*)" ] && passing="true"
	acout=$(auditctl -l | grep -E "$RULE")
	fout1=$(grep -E "$RULE" /etc/audit/rules.d/* | cut -d: -f2)
	fout2=$(grep -E "$RULE" /etc/audit/rules.d/* | cut -d: -f1)
fi

# If the regex matched, output would be generated.  If so, we pass
if [ "$passing" = "true" ] ; then
	echo "Audit rule \"$acout\" exists in the running auditd config"
	echo "Audit rule \"$fout1\" exists in: \"$fout2\""
	exit "${XCCDF_RESULT_PASS:-101}"
else
	# print the reason why we are failing
	[ -z "$LOGFILE" ] && echo "logfile not set in a file in the /etc/sudoers/ directory"
	[ -z "$(auditctl -l | grep -E "$RULE")" ] && echo "Audit rule matching the REGEX: \"$RULE\" is not in the running auditd config"
	[ -z "$(grep -E "$RULE" /etc/audit/rules.d/*)" ] && "Audit rule matching the REGEX: \"$RULE\" is  not in the a rule file in the /etc/audit/rules.d/ directory"
	exit "${XCCDF_RESULT_FAIL:-102}"
fi
