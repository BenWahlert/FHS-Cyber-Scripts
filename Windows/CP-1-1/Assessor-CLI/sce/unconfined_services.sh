#!/usr/bin/env sh

#
# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# E. Pinnell   10/23/19   Check unconfined services
# E. Pinnell   03/27/20   Script corrected

ps -eZ | grep -qv unconfined_service_t && passing=true

# If the regex matched, output would be generated.  If so, we pass
if [ "$passing" = true ] ; then
	echo "No unconfined services exist"
    exit "${XCCDF_RESULT_PASS:-101}"
else
    # print the reason why we are failing
    echo "Unconfined service(s): $(ps -eZ | grep unconfined_service_t) exist"
    exit "${XCCDF_RESULT_FAIL:-102}"
fi