#!/bin/sh
#
# "Copyright 2019 Canonical Limited. All rights reserved."
#
#--------------------------------------------------------

. ./ruleset-tools.sh

########################## SUPPORT FUNCTIONS #################################
SSHD_CONF=/etc/ssh/sshd_config

fetch_usr_list()
{
    egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1
}

########################## RULE FUNCTIONS #################################


#5.1.1 Ensure cron daemon is enabled
rule-5.1.1()
{
    echo
    echo "Ensure cron daemon is enabled"
    dpkg -s cron || apt-get install cron -y
    systemctl enable cron
    systemctl start cron
}

#5.1.2-5.1.7 Cron file related permissions and ownership
rule-5.1.2-7()
{
    echo
    local cronfiles=("/etc/crontab" "/etc/cron.hourly" "/etc/cron.daily"\
        "/etc/cron.weekly" "/etc/cron.monthly" "/etc/cron.d")
    for file in ${cronfiles[@]}; do
        echo
        echo "Ensure permissions on $file are configured"
        chown root:root $file
        chmod og-rwx $file
    done
}

#5.1.8 Ensure at/cron is restricted to authorized users
rule-5.1.8()
{
    echo
    echo "Ensure at/cron is restricted to authorized users"
    rm -f /etc/cron.deny
    rm -f /etc/at.deny
    touch /etc/cron.allow
    touch /etc/at.allow
    chmod og-rwx /etc/cron.allow
    chmod og-rwx /etc/at.allow
    chown root:root /etc/cron.allow
    chown root:root /etc/at.allow
}

#5.2.1 Ensure permissions on /etc/ssh/sshd_config are configured
rule-5.2.1()
{
    echo
    echo "Ensure permissions on /etc/ssh/sshd_config are configured"
    chown root:root /etc/ssh/sshd_config
    chmod og-rwx /etc/ssh/sshd_config
}

#5.2.2 Ensure SSH Protocol is set to 2
rule-5.2.2()
{
    echo
    echo "Ensure SSH Protocol is set to 2"
    if grep -q "^Protocol\b" $SSHD_CONF; then
        sed -i "s/^Protocol\s\+[0-9]$/Protocol 2/" $SSHD_CONF
    else
        echo "Protocol 2" >> $SSHD_CONF
    fi
}

#5.2.3 Ensure SSH LogLevel is set to INFO
rule-5.2.3()
{
    echo
    echo "Ensure SSH LogLevel is set to INFO"
    if grep -q "^LogLevel\b" $SSHD_CONF; then
        sed -i "s/^LogLevel\b.*$/LogLevel INFO/" $SSHD_CONF
    else
        echo "LogLevel INFO" >> $SSHD_CONF
    fi
}

#5.2.4 Ensure SSH X11 forwarding is disabled
rule-5.2.4()
{
    echo
    echo "Ensure SSH X11 forwarding is disabled"
    if grep -q "^X11Forwarding\b" $SSHD_CONF; then
        sed -i "s/^X11Forwarding\b.*$/X11Forwarding no/" $SSHD_CONF
    else
        echo "X11Forwarding no" >> $SSHD_CONF
    fi
}

#5.2.5 Ensure SSH MaxAuthTries is set to 4 or less
rule-5.2.5()
{
    echo
    echo "Ensure SSH MaxAuthTries is set to 4 or less"
    local num=$(grep -Po "(?<=^MaxAuthTries )\d+" $SSHD_CONF)
    if [ -n "$num" ]; then
        if [ $num -gt 4 ]; then
            sed -i "s/^MaxAuthTries\b.*$/MaxAuthTries 4/" $SSHD_CONF
        fi
    else
        echo "MaxAuthTries 4" >> $SSHD_CONF
    fi
}

#5.2.6 Ensure SSH IgnoreRhosts is enabled
rule-5.2.6()
{
    echo
    echo "Ensure SSH IgnoreRhosts is enabled"
    if grep -q "^IgnoreRhosts\b" $SSHD_CONF; then
        sed -i "s/^IgnoreRhosts\b.*$/IgnoreRhosts yes/" $SSHD_CONF
    else
        echo "IgnoreRhosts yes" >> $SSHD_CONF
    fi
}

#5.2.7 Ensure SSH HostbasedAuthentication is disabled
rule-5.2.7()
{
    echo
    echo "Ensure SSH HostbasedAuthentication is disabled"
    if grep -q "^HostbasedAuthentication\b" $SSHD_CONF; then
        sed -i "s/^HostbasedAuthentication\b.*$/HostbasedAuthentication no/" $SSHD_CONF
    else
        echo "HostbasedAuthentication no" >> $SSHD_CONF
    fi
}

#5.2.8 Ensure SSH root login is disabled
rule-5.2.8()
{
    echo
    echo "Ensure SSH root login is disabled"
    if grep -q "^PermitRootLogin\b" $SSHD_CONF; then
        sed -i "s/^PermitRootLogin\b.*$/PermitRootLogin no/" $SSHD_CONF
    else
        echo "PermitRootLogin no" >> $SSHD_CONF
    fi
}

#5.2.9 Ensure SSH PermitEmptyPasswords is disabled
rule-5.2.9()
{
    echo
    echo "Ensure SSH PermitEmptyPasswords is disabled"
    if grep -q "^PermitEmptyPasswords\b" $SSHD_CONF; then
        sed -i "s/^PermitEmptyPasswords\b.*$/PermitEmptyPasswords no/" $SSHD_CONF
    else
        echo "PermitEmptyPasswords no" >> $SSHD_CONF
    fi
}

#5.2.10 Ensure SSH PermitUserEnvironment is disabled
rule-5.2.10()
{
    echo
    echo "Ensure SSH PermitUserEnvironment is disabled"
    if grep -q "^PermitUserEnvironment\b" $SSHD_CONF; then
        sed -i "s/^PermitUserEnvironment\b.*$/PermitUserEnvironment no/" $SSHD_CONF
    else
        echo "PermitUserEnvironment no" >> $SSHD_CONF
    fi
}

#5.2.11 Ensure only approved MAC algorithms are used
rule-5.2.11()
{
    local maclist="hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256"
    echo
    echo "Ensure only approved MAC algorithms are used"
    if grep -q "^MACs\b" $SSHD_CONF; then
        sed -i "s/^MACs\b.*$/MACs $maclist/" $SSHD_CONF
    else
        echo "MACs $maclist" >> $SSHD_CONF
    fi
}

#5.2.12 Ensure SSH Idle Timeout Interval is configured
rule-5.2.12()
{
    echo
    echo "Ensure SSH Idle Timeout Interval is configured"
    if grep -q "^ClientAliveInterval\b" $SSHD_CONF; then
        sed -i "s/^ClientAliveInterval\b.*$/ClientAliveInterval 300/" $SSHD_CONF
    else
        echo "ClientAliveInterval 300" >> $SSHD_CONF
    fi
    if grep -q "^ClientAliveCountMax\b" $SSHD_CONF; then
        sed -i "s/^ClientAliveCountMax\b.*$/ClientAliveCountMax 0/" $SSHD_CONF
    else
        echo "ClientAliveCountMax 0" >> $SSHD_CONF
    fi
}

#5.2.13 Ensure SSH LoginGraceTime is set to one minute or less
rule-5.2.13()
{
    echo
    echo "Ensure SSH LoginGraceTime is set to one minute or less"
    local num=$(grep -Po "(?<=^LoginGraceTime )\d+" $SSHD_CONF)
    if [ -n "$num" ]; then
        if [ $num -gt 60 ]; then
            sed -i "s/^LoginGraceTime\b.*$/LoginGraceTime 60/" $SSHD_CONF
        fi
    else
        echo "LoginGraceTime 60" >> $SSHD_CONF
    fi
}

#5.2.14 Ensure SSH access is limited
rule-5.2.14()
{
    # Grab information from global list of parameters filled by user
    echo
    echo "Ensure SSH access is limited"
    local params="AllowUsers AllowGroups DenyUsers DenyGroups"
    for p in $params; do
        local value=`read_usr_param "$p"`

        if [ -z "${value}" ]; then
            continue
        fi

        if grep -q "^$p\b" $SSHD_CONF; then
            sed -i "s/^$p\b.*$/$p $value/" $SSHD_CONF
        else
            echo "$p $value" >> $SSHD_CONF
        fi
    done
}

#5.2.15 Ensure SSH warning banner is configured
rule-5.2.15()
{
    echo
    echo "Ensure SSH warning banner is configured"
    if grep -q "^Banner\b" $SSHD_CONF; then
        sed -i "s@^Banner\b.*\$@Banner /etc/issue.net@" $SSHD_CONF
    else
        echo "Banner /etc/issue.net" >> $SSHD_CONF
    fi
}

#5.3.1 Ensure password creation requirements are configured
rule-5.3.1()
{
    echo
    echo "Ensure password creation requirements are configured"
    
    # already sets /etc/pam.d/common-password with sane value
    apt-get install libpam-pwquality -y


    # Sets /etc/security/pwquality.conf parameters from user defined ones
    local params="minlen dcredit ucredit ocredit lcredit"
    local pwqual=/etc/security/pwquality.conf
	echo "password requisite pam_pwquality.so retry=3" >>  /etc/pam.d/common-password
    for p in $params; do
        local value=`read_usr_param "$p"`
        if grep -q "^$p\s*=" $pwqual; then
            sed -i "s/^$p\s*=.*$/$p = $value/" $pwqual
        else
            echo "$p = $value" >> $pwqual
        fi
    done
}

# 1.5.3 Ensure authentication required for single user mode
echo "Set root password and lock account"
passwd root 
usermod -L root

#5.3.2 Ensure lockout for failed password attempts is configured
rule-5.3.2()
{
    echo
    echo "Ensure lockout for failed password attempts is configured"
    egrep -q 'pam_tally2.so.* deny=5 unlock_time=900' /etc/pam.d/common-auth
    if [ $? -gt 0 ]; then
        sed -i "1i # CIS rule 5.3.2\nauth required pam_tally2.so onerr=fail audit silent deny=5 unlock_time=900" /etc/pam.d/common-auth
        sed -i -E '/account\srequisite\s+pam_deny.so/a # CIS rule 5.3.2\naccount required\t\t\tpam_tally2.so' /etc/pam.d/common-account
    fi
}

#5.3.3 Ensure password reuse is limited
rule-5.3.3()
{
    echo
    echo "Ensure password reuse is limited"
    local pamstr=`grep '^password required pam_pwhistory.so\b.*\bremember=' /etc/pam.d/common-password`
    if [ -z "$pamstr" ]; then
        echo "password required pam_pwhistory.so remember=5" >> /etc/pam.d/common-password
    else
        local rememb_val=`echo -n "$pamstr" | egrep -o '\bremember=[0-9]+' | cut -d '=' -f 2`
        if [ ${rememb_val} -lt 5 ]; then
            sed -E -i "s/(^password required pam_pwhistory.so\b.*\bremember=)[0-9]+/\15/" /etc/pam.d/common-password
        fi
    fi
}

#5.3.4 Ensure password hashing algorithm is SHA-512
rule-5.3.4()
{
    echo
    echo "Ensure password hashing algorithm is SHA-512"
    grep '^password\s\+.*\bpam_unix\.so\b.*\bsha512\b' /etc/pam.d/common-password ||\
        sed -i 's/\(password\b.*\bpam_unix\.so\b.*\)$/\1 sha512 minlen=14/' /etc/pam.d/common-password
}

#5.4.1.1 Ensure password expiration is 365 days or less
rule-5.4.1.1()
{
    local usrlist=`fetch_usr_list`
    echo
    echo "Ensure password expiration is 365 days or less"
    sed -i -E 's/^(PASS_MAX_DAYS\s+)[0-9]+/\190/' /etc/login.defs
    for usr in $usrlist; do
        chage --maxdays 90 $usr
    done
}

#5.4.1.2 Ensure minimum days between password changes is 7 or more
rule-5.4.1.2()
{
    local usrlist=`fetch_usr_list`
    echo
    echo "Ensure minimum days between password changes is 7 or more"
    sed -i -E 's/^(PASS_MIN_DAYS\s+)[-]?[0-9]+/\17/' /etc/login.defs
    for usr in $usrlist; do
        chage --mindays 7 $usr
    done
}

#5.4.1.3 Ensure password expiration warning days is 7 or more
rule-5.4.1.3()
{
    local usrlist=`fetch_usr_list`
    echo
    echo "Ensure password expiration warning days is 7 or more"
    sed -i -E 's/^(PASS_WARN_AGE\s+)[-]?[0-9]+/\17/' /etc/login.defs
    for usr in $usrlist; do
        chage --warndays 7 $usr
    done
}

#5.4.1.4 Ensure inactive password lock is 30 days or less
rule-5.4.1.4()
{
    local usrlist=`fetch_usr_list`
    echo
    echo "Ensure inactive password lock is 30 days or less"
    useradd -D -f 30
    for usr in $usrlist; do
        chage --inactive 30 $usr
    done
}

#5.4.1.5 Ensure all users last password change date is in the past
rule-5.4.1.5()
{
    echo
    echo "Ensure all users last password change date is in the past"
    echo "Ensure all users last password change date is in the past - requires manual configuration"
}

#5.4.2 Ensure system accounts are non-login
rule-5.4.2()
{
    echo
    echo "Ensure system accounts are non-login"
    for user in `awk -F: '($3 < 1000) {print $1 }' /etc/passwd`; do
        if [ $user != "root" ]; then
            usermod -L $user
            if [ $user != "sync" ] && [ $user != "shutdown" ] && [ $user != "halt" ]; then
                usermod -s /usr/sbin/nologin $user
            fi
        fi
    done
}

#5.4.3 Ensure default group for the root account is GID 0
rule-5.4.3()
{
    echo
    echo "Ensure default group for the root account is GID 0"
    usermod -g 0 root
}

#5.4.4 Ensure default user umask is 027 or more restrictive
rule-5.4.4()
{
    local umask_cmd='umask 027'
    echo
    echo "Ensure default user umask is 027 or more restrictive"
    echo $umask_cmd > /etc/profile.d/CIS-5.4.4.sh
    echo $umask_cmd >> /etc/bash.bashrc
    echo $umask_cmd >> /etc/profile
    
    

    grep -q "^umask\b" $BASHRC_FILE
    if [ $? -eq 0 ]; then
        sed -E -i "s/^umask\s+.*/${umask_cmd}/" $BASHRC_FILE
    else
        echo $umask_cmd >> $BASHRC_FILE
    fi
}

#5.4.5 Ensure default user shell timeout is 900 seconds or less
rule-5.4.5()
{
    local tmout='TMOUT=600'
    echo
    echo "Ensure default user shell timeout is 900 seconds or less"
    echo $tmout > /etc/profile.d/CIS-5.4.5.sh

    # SCAP benchmark requires this
    grep -q "^TMOUT\b" $PROFILE_FILE
    if [ $? -eq 0 ]; then
        sed -E -i "s/^TMOUT\s+.*/${tmout}/" $PROFILE_FILE
    else
        echo $tmout >> $PROFILE_FILE
    fi

    grep -q "^TMOUT\b" $BASHRC_FILE
    if [ $? -eq 0 ]; then
        sed -E -i "s/^TMOUT\s+.*/${tmout}/" $BASHRC_FILE
    else
        echo $tmout >> $BASHRC_FILE
    fi
}

#5.5 Ensure root login is restricted to system console (Not Scored)

#5.6 Ensure access to the su command is restricted
rule-5.6()
{
    echo
    echo "Ensure access to the su command is restricted"
    groupadd sugroup
    echo "auth required pam_wheel.so use_uid group=sugroup" >> /etc/pam.d/su
   
    local sudo_memb=`read_usr_param sudo_member`

    grep -q ^sudo:[^:]*:[^:]*:[^:]* /etc/group
    if [ $? -ne 0 ]; then
        #echo "wheel:x:10:root" >> /etc/group
        groupadd sugroup
        echo "auth required pam_wheel.so use_uid group=sugroup" >> /etc/pam.d/su
    fi
    usermod -a -G sudo root
    for usr in $sudo_memb; do
        usermod -a -G sudo $usr
    done
}




execute_ruleset-5()
{
    local -A rulehash
    local common="5.1.1 5.1.2-7 5.1.8 5.2.1 5.2.2 5.2.3 5.2.4 5.2.5 5.2.6\
        5.2.7 5.2.8 5.2.9 5.2.10 5.2.11 5.2.12 5.2.13 5.2.14 5.2.15 5.3.1\
        5.3.2 5.3.3 5.3.4 5.4.1.1 5.4.1.2 5.4.1.3 5.4.1.4 5.4.1.5 5.4.2 5.4.3\
        5.4.4 5.6 "
    rulehash[lvl1_server]=$common
    rulehash[lvl2_server]="${rulehash[lvl1_server]}"" 5.4.5"
    rulehash[lvl1_workstation]=$common
    rulehash[lvl2_workstation]="${rulehash[lvl1_workstation]}"" 5.4.5"

    do_execute_rules ${rulehash[$1]}
}
