#!/bin/sh
#
# "Copyright 2019 Canonical Limited. All rights reserved."
#
#--------------------------------------------------------

. ./ruleset-tools.sh

########################## SUPPORT FUNCTIONS #################################

# Disable a inetd/xinetd service
disable_inetd_service()
{
    local svcname=$1

    sed -i -E "s/^$svcname/#$svcname/" /etc/inetd.d/$svcname
    sed -i -E 's/(disable[[:space:]]*=[[:space:]]*)no/\1yes/' /etc/xinetd.d/$svcname
}

# Validate ntp service
validate_ntp_service()
{
    local svcname=`read_usr_param time_sync_svc`
    test -z "$svcname" && return 0
    if [ "$svcname" == ntp ] || [ "$svcname" == chrony ]; then
        echo -n "$svcname"
    fi
}


########################## RULE FUNCTIONS #################################

# Execute rules 2.1.1 to 2.1.9 to disable xinetd/inetd services
# All rules are Scored and apply for both lvl1 Server and Workstation
# associative array here is just use to clarify code about which rules we are following
rule-2.1.1-9()
{
    local -A svaa
    svaa=( [2.1.1]=chargen [2.1.2]=daytime [2.1.3]=discard [2.1.4]=echo [2.1.5]=time )
    for svc in ${svaa[*]}; do
        echo
        echo "Ensure $svc services are not enabled"
        disable_inetd_service $svc
    done

    svaa=( [2.1.6]=rsh [2.1.7]=talk [2.1.8]=telnet [2.1.9]=tftp )
    for svc in ${svaa[*]}; do
        echo
        echo "Ensure $svc server is not enabled"
        disable_inetd_service $svc
    done
}

# 2.1.10 Ensure xinetd is not enabled (Scored)
rule-2.1.10()
{
    echo
    echo "Ensure xinetd is not enabled"
    systemctl disable xinetd
    systemctl stop xined
}

# 2.1.11 Ensure openbsd-inetd is not installed (Scored)
rule-2.1.11()
{
    echo
    echo "Ensure openbsd-inetd is not installed"
    apt-get remove openbsd-inetd -y
}

# 2.2.1.1 Ensure time synchronization is in use (Not Scored)
rule-2.2.1.1()
{
    local svc=`validate_ntp_service`
    echo
    echo "Ensure time synchronization is in use"
    if [ -z "$svc" ]; then
        echo "No time synchronization package chosen. None will be installed"
    else
        apt-get install $svc -y
    fi
    #    echo "Ensure time synchronization is in use - requires manual configuration"
}

# 2.2.1.2 Ensure ntp is configured (Scored)
rule-2.2.1.2()
{
    local svc=`validate_ntp_service`
    local addr=`read_usr_param time_sync_addr`
    echo
    echo "Ensure ntp is configured"
    if [ "$svc" == ntp ]; then
        sed -i 's/^\(RUNASUSER=\).*$/\1ntp/' /etc/init.d/ntp
        egrep "restrict -4 default kod notrap nomodify nopeer noquery" /etc/ntp.conf
        if [ $? -ne 0 ]; then
            sed -i 's/^\(restrict -4.*\)$/#\1\nrestrict -4 default kod notrap nomodify nopeer noquery/' /etc/ntp.conf
        fi
        egrep "restrict -6 default kod notrap nomodify nopeer noquery" /etc/ntp.conf
        if [ $? -ne 0 ]; then
            sed -i 's/^\(restrict -6.*\)$/#\1\nrestrict -6 default kod notrap nomodify nopeer noquery/' /etc/ntp.conf
        fi
        egrep "^(server|pool)" /etc/ntp.conf
        if [ $? -ne 0 ]; then
             echo "pool $addr" >> /etc/ntp.conf
        fi
    else
        echo "ntp not selected for configuration"
    fi
}

# 2.2.1.3 Ensure chrony is configured (Scored)
rule-2.2.1.3()
{
    local svc=`validate_ntp_service`
    local addr=`read_usr_param time_sync_addr`
    echo
    echo "Ensure chrony is configured"
    if [ "$svc" == chrony ]; then
        egrep "^(server|pool)" /etc/chrony/chrony.conf
        if [ $? -ne 0 ]; then
           echo "pool $addr" >> /etc/chrony/chrony.conf
        fi
    else
        echo "chrony not selected for configuration"
    fi
    #echo "Ensure chrony is configured - requires manual configuration"
}

# 2.2.2 Ensure X Window System is not installed (Scored)
rule-2.2.2()
{
    echo
    echo "Ensure X Window System is not installed"
    apt-get remove xserver-xorg -y
}

# 2.2.3 Ensure Avahi Server is not enabled (Scored)
rule-2.2.3()
{
    echo
    echo "Ensure Avahi Server is not enabled"
    systemctl disable avahi-daemon
    systemctl stop avahi-daemon
}

# 2.2.4 Ensure CUPS is not enabled (Scored)
rule-2.2.4()
{
    echo
    echo "Ensure CUPS is not enabled"
    systemctl disable cups
    systemctl stop cups
}

# 2.2.5 Ensure DHCP Server is not enabled (Scored)
rule-2.2.5()
{
    echo
    echo "Ensure DHCP Server is not enabled"
    systemctl disable isc-dhcp-server isc-dhcp-server6
    systemctl stop isc-dhcp-server isc-dhcp-server6
}

# 2.2.6 Ensure LDAP server is not enabled (Scored)
rule-2.2.6()
{
    echo
    echo "Ensure LDAP server is not enabled"
    systemctl disable slapd
    systemctl stop slapd
}

# 2.2.7 Ensure NFS and RPC are not enabled (Scored)
rule-2.2.7()
{
    echo
    echo "Ensure NFS and RPC are not enabled"
    systemctl disable nfs-server rpcbind
    systemctl stop nfs-server rpcbind
}

# 2.2.8 Ensure DNS Server is not enabled (Scored)
rule-2.2.8()
{
    echo
    echo "Ensure DNS Server is not enabled"
    systemctl disable bind9
    systemctl stop bind9
}

# 2.2.9 Ensure FTP Server is not enabled (Scored)
rule-2.2.9()
{
    echo
    echo "Ensure FTP Server is not enabled"
    systemctl disable vsftpd
    systemctl stop vsftpd
}

# 2.2.10 Ensure HTTP server is not enabled (Scored)
rule-2.2.10()
{
    echo
    echo "Ensure HTTP server is not enabled"
    systemctl disable apache2
    systemctl stop apache2
}

# 2.2.11 Ensure IMAP and POP3 server is not enabled (Scored)
rule-2.2.11()
{
    echo
    echo "Ensure IMAP and POP3 server is not enabled"
    systemctl disable dovecot
    systemctl stop dovecot
}

# 2.2.12 Ensure Samba is not enabled (Scored)
rule-2.2.12()
{
    echo
    echo "Ensure Samba is not enabled"
    systemctl disable smbd
    systemctl stop smbd
}

# 2.2.13 Ensure HTTP Proxy Server is not enabled (Scored)
rule-2.2.13()
{
    echo
    echo "Ensure HTTP Proxy Server is not enabled"
    systemctl disable squid
    systemctl stop squid
}

# 2.2.14 Ensure SNMP Server is not enabled (Scored)
rule-2.2.14()
{
    echo
    echo "Ensure SNMP Server is not enabled"
    systemctl disable snmpd
    systemctl stop snmpd
}

#2.2.15 Ensure mail transfer agent is configured for local-only mode (Scored)
rule-2.2.15()
{
    echo
    echo "Ensure mail transfer agent is configured for local-only mode"
    sed -i "s/\("inet_interfaces" *= *\).*/\1"loopback-only"/" /etc/postfix/main.cf
    systemctl restart postfix
}

# 2.2.16 Ensure rsync service is not enabled (Scored)
rule-2.2.16()
{
    echo
    echo "Ensure rsync service is not enabled"
    systemctl disable rsync
    systemctl stop rsync
}

# 2.2.17 Ensure NIS Server is not enabled (Scored)
rule-2.2.17()
{
    echo
    echo "Ensure NIS Server is not enabled"
    systemctl disable nis
    systemctl stop nis
}

# 2.3.1 Ensure NIS Client is not installed
rule-2.3.1()
{
    echo
    echo "Ensure NIS Client is not installed"
    apt-get remove nis -y
}

# 2.3.2 Ensure rsh client is not installed (Scored)
rule-2.3.2()
{
    echo
    echo "Ensure rsh client is not installed"
    apt-get remove rsh-client rsh-redone-client -y
}

# 2.3.3 Ensure talk client is not installed (Scored)
rule-2.3.3()
{
    echo
    echo "Ensure talk client is not installed"
    apt-get remove talk -y
}

# 2.3.4 Ensure telnet client is not installed (Scored)
rule-2.3.4()
{
    echo
    echo "Ensure telnet client is not installed"
    dpkg -s telnet && apt-get remove telnet -y
    apt purge telnet -y
}

# 2.3.5 Ensure LDAP client is not installed (Scored)
rule-2.3.5()
{
    echo
    echo "Ensure LDAP client is not installed"
    apt-get remove ldap-utils -y
}

execute_ruleset-2()
{
    local -A rulehash
    local common="2.1.1-9 2.1.10 2.1.11 2.2.1.2 2.2.1.3 2.2.3 2.2.4 2.2.5\
        2.2.6 2.2.7 2.2.8 2.2.9 2.2.10 2.2.11 2.2.12 2.2.13 2.2.14 2.2.15\
        2.2.16 2.2.17 2.3.1 2.3.2 2.3.3 2.3.4 2.3.5"
    rulehash[lvl1_server]=$common" 2.2.2"
    rulehash[lvl2_server]="${rulehash[lvl1_server]}"
    rulehash[lvl1_workstation]=$common
    rulehash[lvl2_workstation]="${rulehash[lvl1_workstation]}"

    do_execute_rules ${rulehash[$1]}
}
