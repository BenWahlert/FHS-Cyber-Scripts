#!/usr/bin/env sh

#
# CIS-CAT Script Check Engine
# 
# Name                Date       Description
# -------------------------------------------------------------------
# Edward Byrd		  09/18/20   Check audit record access

controlowner=$(
ls -le /etc/security/audit_control | awk '{print $3}' | grep -v 'root'
)

controlgroup=$(
ls -le /etc/security/audit_control | awk '{print $4}' | grep -v 'wheel'
)

auditowner=$(
ls -le /var/audit/ | awk '{print $3}' | grep -v 'root'
)

auditgroup=$(
ls -le /var/audit/ | awk '{print $4}' | grep -v 'wheel'
)

if [ $controlowner -n ] && [ $controlgroup -n ] && [ $auditowner -n ] && [ $auditgroup -n ]; then
  output=True
else
  output=False
fi

# If result returns 0 pass, otherwise fail.
if [ "$output" == True ] ; then
	echo "$output"
    exit "${XCCDF_RESULT_PASS:-101}"
else
    # print the reason why we are failing
    echo "$output"
    exit "${XCCDF_RESULT_FAIL:-102}"
fi
