#!/bin/sh
#
# "Copyright 2019 Canonical Limited. All rights reserved."
#
#--------------------------------------------------------

# Global constants
#SYSCTLD_FILE=/etc/sysctl.d/Canonical_Ubuntu_CIS.conf
LIMITSD_FILE=/etc/security/limits.d/Canonical_Ubuntu_CIS.conf
BASHRC_FILE=/etc/bash.bashrc
PROFILE_FILE=/etc/profile

# Verify if PARAM_FILEPATH var exists, otherwise use a default value
# this is mostly to allow debug of individual modules
if [ -z "${PARAM_FILEPATH}" ]; then
    PARAM_FILEPATH=$(dirname ${BASH_SOURCE})/ruleset-params.conf
fi


# Based on argument, effectively calls the functions responsible for each rule
# This is used by the sourced files
function do_execute_rules()
{
    local rset=$@

    for rule in $rset; do
        echo "Execute rule $rule"
        rule-$rule
    done
}

function exec_error()
{
    echo "Error executing rule $1"
    exit 1
}

# Grabs parameters configured by the script user.
# IF parameter doesn't exist, return empty string.
function read_usr_param()
{
    # If CURRENT_DIR var exists, move there, since the path to the parameter file
    # can be a relative one.
    test -n "${CURRENT_DIR}" && pushd ${CURRENT_DIR} &>/dev/null

    sed '/^#.*/D' "${PARAM_FILEPATH}" | grep "$1=" | cut -d= -f2 | tr -d '\n'

    test -n "${CURRENT_DIR}" && popd &>/dev/null
} 

# Prints rule banner
function print_rule_banner()
{
    echo
    echo "$@"
}
