#!/bin/sh
#
# "Copyright 2019 Canonical Limited. All rights reserved."
#
#--------------------------------------------------------

. ./ruleset-tools.sh

# Global vars
SYSCTLD_SET1_FILE=/etc/sysctl.d/Canonical_Ubuntu_CIS_SET1.conf

########################## SUPPORT FUNCTIONS #################################

# Disable a filesystem by removing module and blocking module load on modprobe.d
# filesystem module name is passed as 1st parameter
disable_fs()
{
    local fsmod=$1
    echo "install $fsmod /bin/true" >> /etc/modprobe.d/CIS.conf
    lsmod | grep $fsmod && rmmod $fsmod
}

# Add new mount options into /etc/fstab file
# 1st argument is the mountpoint to be modified
# 2nd argument is the list of options
add_fstab_opts()
{
    if [ $# -lt 2 ]; then
        return 1
    fi

    local mpoint=$1
    shift
    local opt_list=$@

    result=$(grep $mpoint /etc/fstab)
    # Only modify if the line exists. Otherwise, do nothing
    if [ -z "$result" ]; then
        return 1
    fi
    # Loop over options adding if needed
    for opt in $opt_list; do
        # see if it has opt if not, add it.
        if [[ $result != *"$opt"* ]]; then
            awk '$2 == "'$mpoint'" {$4=$4",'$opt'"}1' /etc/fstab > /etc/fstab.CIS
            mv /etc/fstab.CIS /etc/fstab
            mount -o remount,$opt $mpoint
        fi
    done
}

# generic function to ensure mount option on mount point
# 1st argument is mountpoint, second is option
ensure_opt_mountpoint()
{
    local mpoint=$1
    local mopt=$2

    echo
    echo "Ensure $mopt option set on $mpoint partition"
    result=$(grep $mpoint /etc/fstab)
    if [ -n "$result" ]; then
        add_fstab_opts $mpoint $mopt
    else
        echo "No $mpoint partition present"
    fi
}

########################## RULE FUNCTIONS #################################

# disable filesystems according to rules 1.1.1.1 - 1.1.1.6 (Scored)
# associative array here is just use to clarify code about which rules are we following
rule-1.1.1.x()
{
    local -A fsvaa
    fsvaa=( [1.1.1.1]=cramfs [1.1.1.2]=freevxfs [1.1.1.3]=jffs2 [1.1.1.4]=hfs [1.1.1.5]=hfsplus [1.1.1.6]=squashfs [1.1.1.7]=udf )
    # Remove old conf file
    rm -f /etc/modprobe.d/CIS.conf
    for fs in ${fsvaa[*]}; do
        echo
        echo "Ensure mounting of $fs filesystems is disabled"
        disable_fs $fs
    done
}

# 1.1.2 Ensure separate partition exists for /tmp (Scored)
rule-1.1.2()
{
    echo
    echo "Ensure separate partition exists for /tmp"
    echo "Ensure separate partition exists for /tmp - requires manual configuration"
    Echo " Ensure /tmp is configured"
    echo "tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0" >> /etc/fstab
    systemctl unmask tmp.mount

    systemctl enable tmp.mount 
}

# 1.1.3 Ensure nodev option set on /tmp partition (Scored)
rule-1.1.3()
{
    ensure_opt_mountpoint /tmp nodev
}

# 1.1.4 Ensure nosuid option set on /tmp partition (Scored)
rule-1.1.4()
{
    ensure_opt_mountpoint /tmp nosuid
}

# 1.1.5 Ensure separate partition exists for /var (Scored)
rule-1.1.5()
{
    echo
    echo "Ensure separate partition exists for /var"
    echo "Ensure separate partition exists for /var - requires manual configuration"
}

# 1.1.6 Ensure separate partition exists for /var/tmp (Scored)
rule-1.1.6()
{
    echo
    echo "Ensure separate partition exists for /var/tmp"
    echo "Ensure separate partition exists for /var/tmp - requires manual configuration"
}

# 1.1.7 Ensure nodev option set on /var/tmp partition (Scored)
rule-1.1.7()
{
    ensure_opt_mountpoint /var/tmp nodev
}

# 1.1.8 Ensure nosuid option set on /var/tmp partition (Scored)
rule-1.1.8()
{
    ensure_opt_mountpoint /var/tmp nosuid
}

# 1.1.9 Ensure noexec option set on /var/tmp partition (Scored)
rule-1.1.9()
{
    ensure_opt_mountpoint /var/tmp noexec 
}

# 1.1.10 Ensure separate partition exists for /var/log (Scored)
rule-1.1.10()
{
    echo
    echo "Ensure separate partition exists for /var/log"
    echo "Ensure separate partition exists for /var/log - requires manual configuration"
}

# 1.1.11 Ensure separate partition exists for /var/log/audit (Scored)
rule-1.1.11()
{
    echo
    echo "Ensure separate partition exists for /var/log/audit"
    echo "Ensure separate partition exists for /var/log/audit - requires manual configuration"
}

# 1.1.12 Ensure separate partition exists for /home (Scored)
rule-1.1.12()
{
    echo
    echo "Ensure separate partition exists for /home"
    echo "Ensure separate partition exists for /home - requires manual configuration"
}

# 1.1.13 Ensure nodev option set on /home partition (Scored)
rule-1.1.13()
{
    # If there is a /home partition, make sure nodev option is set
    # If not, DO NOT change anything.
    ensure_opt_mountpoint /home nodev
}

# 1.1.14 Ensure nodev option set on /dev/shm partition (Scored)
rule-1.1.14()
{
    echo
    echo "Ensure nodev option set on /dev/shm partition"
    result=$(grep /dev/shm /etc/fstab)
    if [ -n "$result" ]; then
        add_fstab_opts /dev/shm nodev
    else
        echo "tmpfs /dev/shm tmpfs rw,nosuid,nodev,noexec 0 0" >> /etc/fstab
        mount -o remount,nosuid,nodev,noexec /dev/shm
    fi
}

#1.1.15 Ensure nosuid option set on /dev/shm partition (Scored)
rule-1.1.15()
{
    echo
    echo "Ensure nosuid option set on /dev/shm partition"
    result=$(grep /dev/shm /etc/fstab)
    if [ -n "$result" ]; then
        add_fstab_opts /dev/shm nosuid
    else
        echo "tmpfs /dev/shm tmpfs rw,nosuid,nodev,noexec 0 0" >> /etc/fstab
        mount -o remount,nosuid,nodev,noexec /dev/shm
    fi
}

#1.1.16 Ensure noexec option set on /dev/shm partition (Scored)
rule-1.1.16()
{
    echo
    echo "Ensure noexec option set on /dev/shm partition"
    result=$(grep /dev/shm /etc/fstab)
    if [ -n "$result" ]; then
        add_fstab_opts /dev/shm noexec
    else
        echo "tmpfs /dev/shm tmpfs rw,nosuid,nodev,noexec 0 0" >> /etc/fstab
        mount -o remount,nosuid,nodev,noexec /dev/shm
    fi
}

#1.1.17-1.1.19 not scored (removable media related)
echo "install usb-storage /bin/true " >> /etc/modprobe.d/usb_storage.conf
rmmod usb-storage 
#1.1.20 Ensure sticky bit on world-writable directories (Scored)
rule-1.1.20()
{
    echo
    echo "Ensure sticky bit on world-writable directories"
    df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev
-type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null | xargs -I '{}' chmod
a+t '{}'
}

#1.1.21 Disable Automounting (Scored)
rule-1.1.21()
{
    echo
    echo "Disable Automounting"
    systemctl disable autofs.service
}

# Rules 1.2.1 and 1.2.2 are not scored

#1.3.1 Ensure AIDE is installed (Scored)
rule-1.3.1()
{
    echo
    echo "Ensure AIDE is installed"
    echo "****** Note this rule installs postfix as well, which requires additional MANUAL configuration ******"
    debconf-set-selections <<< "postfix postfix/mailname string your.hostname.com"
    debconf-set-selections <<< "postfix postfix/main_mailer_type string 'No configuration'"
    apt-get install -y postfix
    apt-get install aide aide-common -y
}
echo
    echo "Ensure sudo is installed and has logs"
    echo -e 'Defaults use_pty\nDefaults logfile="/var/log/sudo.log"' >> /etc/sudoers
#1.3.2 Ensure filesystem integrity is regularly checked (Scored)
rule-1.3.2()
{
    local ctab_line="0 5 * * * root /usr/bin/aide --config /etc/aide/aide.conf --check"
    echo
    echo "Ensure filesystem integrity is regularly checked"
    if ! grep -q "$ctab_line" /etc/crontab; then
        echo -e "# Line added by CIS hardening scripts\n""$ctab_line" >> /etc/crontab
        echo "****** /etc/crontab was changed to enable AIDE periodical checks ******"
    fi
}

#1.4.1 Ensure permissions on bootloader config are configured (Scored)
rule-1.4.1()
{
    local cfg="/boot/grub/grub.cfg"

    echo
    echo "Ensure permissions on bootloader config are configured"
    chown root:root $cfg
    chmod 400 $cfg
}

#1.4.2 Ensure bootloader password is set (Scored)
rule-1.4.2()
{
    local arch=$(uname -m)
    echo
    echo "Ensure bootloader password is set"

    if [[ "$arch" == 's390x' ]]; then
        echo "zipl does not support bootloader password"
        return
    fi
    local hash=`read_usr_param grub_hash`
    local user=`read_usr_param grub_user`
    local hdrconf=/etc/grub.d/00_header
    local linuxconf=/etc/grub.d/10_linux
   
    if [ -z "$user" ] || [ -z "$hash" ]; then
        echo "Ensure bootloader password is set - requires manual configuration!"
        return
    fi

    # --unrestricted flag to allow boot without password
    # Note this still protects against unauthorized entry editing
    egrep '^CLASS=".* --unrestricted( .*)?"' ${linuxconf}
    if [ $? -ne 0 ]; then
        sed -i -E 's/^(CLASS="[^"]*)/\1 --unrestricted/' ${linuxconf}
    fi

    egrep "^set superusers=\"[^\"]*\"" $hdrconf && egrep "^password_pbkdf2 $user grub\.pbkdf2.*" $hdrconf
    if [ $? -eq 0 ]; then
        sed -i -E "s/(set superusers=)\"[^\"]+\"/\1\"$user\"/" $hdrconf
        sed -i -E "s/(password_pbkdf2 $user )grub\.pbkdf2.*$/\1$hash/" $hdrconf
    else
        echo "cat <<EOF" >> $hdrconf
        echo "set superusers=\"$user\"" >> $hdrconf
        echo "password_pbkdf2 $user $hash" >> $hdrconf
        echo -n "EOF" >> $hdrconf
    fi
    grub-mkconfig -o /boot/grub/grub.cfg
    #update-grub
}

#1.4.3 Ensure authentication required for single user mode (Scored)
rule-1.4.3()
{
    echo
    echo "Ensure authentication required for single user mode"
    echo "Ensure authentication required for single user mode - requires manual configuration!"
}

#1.5.1 Ensure core dumps are restricted (Scored)
rule-1.5.1()
{
    echo
    echo "Ensure core dumps are restricted"
    echo "* hard core 0" >> $LIMITSD_FILE
    echo 'fs.suid_dumpable=0' >> $SYSCTLD_SET1_FILE
    sysctl -w fs.suid_dumpable=0
    # Hack. Disable pesky apport to prevent it from setting
    # suid_dumpable flag
    systemctl disable apport
}

# 1.5.2 Ensure XD/NX support is enabled (Not Scored)


#1.5.3 Ensure address space layout randomization (ASLR) is enabled (Scored)
rule-1.5.3()
{
    echo
    echo "Ensure address space layout randomization (ASLR) is enabled"
    echo "kernel.randomize_va_space=2" >> $SYSCTLD_SET1_FILE
    sysctl -w kernel.randomize_va_space=2
}

# 1.5.4 Ensure prelink is disabled
rule-1.5.4()
{
    echo
    echo "Ensure prelink is disabled"
    prelink -ua 2>/dev/null
    apt-get remove prelink 2>/dev/null
}

# 1.6.1.x is SELinux specific

#1.6.2.1 Ensure AppArmor is not disabled
rule-1.6.2.1()
{
    echo
    echo "Ensure AppArmor is enabled in the bootloader configuration"	
    echo 'GRUB_CMDLINE_LINUX="apparmor=1 security=apparmor ipv6.disable=1 audit=1 audit_backlog_limit=8192"' >> /etc/default/grub
    update-grub
}

#1.6.2.2 Ensure all AppArmor profiles are enforcing
rule-1.6.2.2()
{
    echo
    echo "Ensure all AppArmor Profiles are enforcing"
    aa-enforce /etc/apparmor.d/* 
}

# 1.6.3 Ensure AppArmor is installed
rule-1.6.3()
{
    echo
    echo "Ensure SELinux or AppArmor are installed"
    apt-get install apparmor -y
}

# 1.7.1.1 Ensure message of the day is configured properly (Scored)
rule-1.7.1.1()
{
    echo
    echo "Ensure message of the day is configured properly"
    sed -i -E 's/(\\s|\\v|\\m|\\r)//g' /etc/motd
}

# 1.7.1.2 Ensure local login warning banner is configured properly (Scored)
rule-1.7.1.2()
{
    echo
    echo "Ensure local login warning banner is configured properly"
    echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue
}

# 1.7.1.3 Ensure remote login warning banner is configured properly (Scored)
rule-1.7.1.3()
{
    echo
    echo "Ensure remote login warning banner is configured properly"
    echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue.net
}

# 1.7.1.4 Ensure permissions on /etc/motd are configured (Scored)
rule-1.7.1.4()
{
    echo
    echo "Ensure permissions on /etc/motd are configured"
    chown root:root /etc/motd
    chmod 644 /etc/motd
}

# 1.7.1.5 Ensure permissions on /etc/issue are configured (Scored)
rule-1.7.1.5()
{
    echo
    echo "Ensure permissions on /etc/issue are configured"
    chown root:root /etc/issue
    chmod 644 /etc/issue
}

# 1.7.1.6 Ensure permissions on /etc/issue.net are configured (Scored)
rule-1.7.1.6()
{
    echo
    echo "Ensure permissions on /etc/issue.net are configured"
    chown root:root /etc/issue.net
    chmod 644 /etc/issue.net
}

# 1.7.2 Ensure GDM login banner is configured (Scored)
rule-1.7.2()
{
    echo
    echo "Ensure GDM login banner is configured"
    echo -e "[org/gnome/login-screen]\nbanner-message-enable=true\nbanner-message-text='Authorized uses only. All activity may be monitored and reported.'" > /etc/gdm3/greeter.dconf-defaults
}

# 1.8 Ensure updates, patches, and additional security software are installed (Not scored)

# Execute ruleset, based on level and profile provided.
# Argument 1 the chosen profile
execute_ruleset-1()
{
    local -A rulehash
    local common="1.1.1.x 1.1.3 1.1.4 1.1.7 1.1.8 1.1.9 1.1.13 1.1.14 1.1.15\
        1.1.16 1.1.20 1.3.1 1.3.2 1.4.1 1.4.2 1.4.3 1.5.1 1.5.3 1.5.4 1.7.1.1\
        1.7.1.2 1.7.1.3 1.7.1.4 1.7.1.5 1.7.1.6 1.7.2"
    rulehash[lvl1_server]=$common" 1.1.21"
    rulehash[lvl2_server]="${rulehash[lvl1_server]}"" 1.1.2 1.1.5 1.1.6\
        1.1.10 1.1.11 1.1.12 1.6.2.1 1.6.2.2 1.6.3"
    rulehash[lvl1_workstation]=$common
    rulehash[lvl2_workstation]="${rulehash[lvl1_workstation]}"" 1.1.2 1.1.5\
        1.1.6 1.1.10 1.1.11 1.1.12 1.1.21 1.6.2.1 1.6.2.2 1.6.3"

    # remove old $LIMITSD_FILE and $SYSCTLD_FILE
    rm -f $LIMITSD_FILE $SYSCTLD_SET1_FILE

    # Make sure apparmor-utils is installed
    apt-get install apparmor-utils -y

    do_execute_rules ${rulehash[$1]}
}
