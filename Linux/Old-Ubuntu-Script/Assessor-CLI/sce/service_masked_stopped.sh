#!/usr/bin/env sh

#
# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# E. Pinnell   03/23/20   Check that service is stopped and masked

passing=""

systemctl status "$XCCDF_VALUE_REGEX" | grep -qv "Active: active (running) " && systemctl is-enabled "$XCCDF_VALUE_REGEX" | grep -Eq masked && passing=true

# If the regex matched, output would be generated.  If so, we pass
if [ "$passing" = true ] ; then
	echo "Service $XCCDF_VALUE_REGEX is not running and masked"
    exit "${XCCDF_RESULT_PASS:-101}"
else
    # print the reason why we are failing
    echo "Service $XCCDF_VALUE_REGEX is running or not masked"
    exit "${XCCDF_RESULT_FAIL:-102}"
fi