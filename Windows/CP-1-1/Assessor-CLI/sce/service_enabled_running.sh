#!/usr/bin/env sh

#
# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# E. Pinnell   03/23/20   Check that service is running and not disabled or masked

passing=""

systemctl status "$XCCDF_VALUE_REGEX" | grep -q "Active: active (running) " && systemctl is-enabled "$XCCDF_VALUE_REGEX" | grep -q enabled && passing=true

# If the regex matched, output would be generated.  If so, we pass
if [ "$passing" = true ] ; then
	echo "Service $XCCDF_VALUE_REGEX is running and enabled"
    exit "${XCCDF_RESULT_PASS:-101}"
else
    # print the reason why we are failing
    echo "Service $XCCDF_VALUE_REGEX is not running or disabled"
    exit "${XCCDF_RESULT_FAIL:-102}"
fi