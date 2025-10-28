#!/usr/bin/env sh

#
# CIS-CAT Script Check Engine
# 
# Name                Date       Description
# -------------------------------------------------------------------
# Edward Byrd         09/21/20   Disable File Sharing
# 

afpshare=$(
launchctl list | grep -e AppleFileServer
)

smbshare=$(
launchctl print-disabled system | grep com.apple.smbd
)

if [ $afpshare -n ] && [ $smbshare -n ]; then
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



if [ $wakelan -e 0 ] && [ $pnap -e 0 ]