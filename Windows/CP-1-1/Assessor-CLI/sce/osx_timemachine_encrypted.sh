#!/usr/bin/env sh

#
# CIS-CAT Script Check Engine
# 
# Name                Date       Description
# -------------------------------------------------------------------
# Sara Lynn Archacki  04/02/19   Ensure Time Machine Volumes Are Encrypted
# Eric Pinnell        04/23/20   Correct test error
# 

passing=""
output=$(defaults read /Library/Preferences/com.apple.TimeMachine.plist | grep LastKnownEncryptionState)
defaults read /Library/Preferences/com.apple.TimeMachine.plist | grep -q LastKnownEncryptionState && defaults read /Library/Preferences/com.apple.TimeMachine.plist | grep LastKnownEncryptionState | grep -vq NotEncrypted && passing=true



# If results returns pass, otherwise fail.
if [ "$passing" = true ] ; then
	echo "Passed: \"$output\""
	exit "${XCCDF_RESULT_PASS:-101}"
else
# print the reason why we are failing
	echo "Failed: \"$output\""
	exit "${XCCDF_RESULT_FAIL:-102}"
fi
#echo "$output"
#exit "${XCCDF_RESULT_PASS:-101}"