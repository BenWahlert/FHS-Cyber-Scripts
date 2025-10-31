#!/bin/bash
#
# "Copyright 2019 Canonical Limited. All rights reserved."
#
#--------------------------------------------------------

loaded_profiles=$(/usr/sbin/aa-status --profiled)
if [ $loaded_profiles -eq 0 ]; then
	exit $XCCDF_RESULT_FAIL
fi

complain=$(/usr/sbin/aa-status --complaining)
if [ $complain -ne 0 ]; then
	exit $XCCDF_RESULT_FAIL
fi

confined=`/usr/sbin/aa-status | grep "processes are unconfined" | awk '{print $1;}'`
if [ $confined -ne 0 ]; then
	exit $XCCDF_RESULT_FAIL
fi

exit $XCCDF_RESULT_PASS
