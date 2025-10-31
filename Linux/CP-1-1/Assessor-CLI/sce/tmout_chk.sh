#!/usr/bin/env sh

# CIS-CAT Script Check Engine
#
# Name         Date       Description
# -------------------------------------------------------------------
# E. Pinnell   04/01/20   Check that TMOUT is configured

passing=""
test1=""
test2=""
output1=""
output2=""

[ -f /etc/bashrc ] && BRC="/etc/bashrc"
[ -f /etc/bash.bashrc ] && BRC="/etc/bash.bashrc"

for f in "$BRC" /etc/profile /etc/profile.d/*.sh ; do
	if [ -f "$f" ] ; then
		grep -Eq '(^|^[^#]*;)\s*(readonly|export(\s+[^$#;]+\s*)*)?\s*TMOUT=(900|[1-8][0-9][0-9]|[1-9][0-9]|[1-9])\b' "$f" && grep -Eq '(^|^[^#]*;)\s*readonly\s+TMOUT\b' "$f" && grep -Eq '(^|^[^#]*;)\s*export\s+([^$#;]+\s+)*TMOUT\b' "$f" && test1=y output1="$f"
	else
		break
	fi
done
! grep -Pq '(^|^[^#]*;)\s*TMOUT=(9[0-9][1-9]|0+|[1-9]\d{3,})\b' /etc/profile /etc/profile.d/*.sh "$BRC" && test2="y" || test2="n"
[ "$test2" = n ] && output2=$(grep -P '(^|^[^#]*;)\s*TMOUT=(9[0-9][1-9]|0+|[1-9]\d{3,})\b' /etc/profile /etc/profile.d/*.sh $BRC)
[ "$test1" = y ] && [ "$test2" = y ] && passing=true

# If the tests all pass, we pass
if [ "$passing" = true ] ; then
	echo "TMOUT is configured in: \"$output1\""
    exit "${XCCDF_RESULT_PASS:-101}"
else
    # print the reason why we are failing
    [ -z "$output1" ] && echo "TMOUT is not configured"
    [ "$test2" = n ] && echo "TMOUT is incorrectly configured in: \"$output2\""
    exit "${XCCDF_RESULT_FAIL:-102}"
fi