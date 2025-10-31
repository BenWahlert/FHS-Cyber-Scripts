#!/usr/bin/env sh

#
# CIS-CAT Script Check Engine
# 
# Name                Date       Description
# -------------------------------------------------------------------
# Edward Byrd         09/08/20   Ensure Location Services is enabled
# 

output="$(launchctl load /System/Library/LaunchDaemons/com.apple.locationd.plist 2>&1)"
echo "$output" | grep -q 'service already loaded' && passing=true

# If result returns 0 pass, otherwise fail.
if [ "$passing" = true ] ; then
	echo "PASSED: $output"
    exit "${XCCDF_RESULT_PASS:-101}"
else
    # print the reason why we are failing
    echo "FAILED: $output"
    exit "${XCCDF_RESULT_FAIL:-102}"
fi