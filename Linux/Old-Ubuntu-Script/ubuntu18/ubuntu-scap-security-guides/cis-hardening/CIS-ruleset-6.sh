#!/bin/sh
#
# "Copyright 2019 Canonical Limited. All rights reserved."
#
#--------------------------------------------------------

. ./ruleset-tools.sh

# Global vars

########################## SUPPORT FUNCTIONS #################################

# Return user name and their respective home directory, separated by a single " "
fetch_users_and_homedir()
{
    cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' |\
     awk -F: '($7 != "/usr/sbin/nologin" && $7 != "/bin/false" && $3 >= 1000)\
     { print $1 " " $6 }'
}

########################## RULE FUNCTIONS #################################



#6.1.1 Audit system file permissions (Not Scored)

#6.1.2 Ensure permissions on /etc/passwd are configured
rule-6.1.2()
{
    echo
    echo "Ensure permissions on /etc/passwd are configured"
    chown root:root /etc/passwd
    chmod 644 /etc/passwd
}

#6.1.3 Ensure permissions on /etc/shadow are configured
rule-6.1.3()
{
    echo
    echo "Ensure permissions on /etc/shadow are configured"
    chown root:shadow /etc/shadow
    chmod 640 /etc/shadow
}

#6.1.4 Ensure permissions on /etc/group are configured
rule-6.1.4()
{
    echo
    echo "Ensure permissions on /etc/group are configured"
    chown root:root /etc/group
    chmod 644 /etc/group
}

#6.1.5 Ensure permissions on /etc/gshadow are configured
rule-6.1.5()
{
    echo
    echo "Ensure permissions on /etc/gshadow are configured"
    chown root:shadow /etc/gshadow
    chmod 640 /etc/gshadow
}

#6.1.6 Ensure permissions on /etc/passwd- are configured
rule-6.1.6()
{
    echo
    echo "Ensure permissions on /etc/passwd- are configured"
    chown root:root /etc/passwd- 
    chmod 600 /etc/passwd-
}

#6.1.7 Ensure permissions on /etc/shadow- are configured
rule-6.1.7()
{
    echo
    echo "Ensure permissions on /etc/shadow- are configured"
    chown root:shadow /etc/shadow-
    chmod 600 /etc/shadow- 
}

#6.1.8 Ensure permissions on /etc/group- are configured
rule-6.1.8()
{
    echo
    echo "Ensure permissions on /etc/group- are configured"
    chown root:root /etc/group-
    chmod 644 /etc/group-
}

#6.1.9 Ensure permissions on /etc/gshadow- are configured
rule-6.1.9()
{
    echo
    echo "Ensure permissions on /etc/gshadow- are configured"
    chown root:shadow /etc/gshadow-
    chmod 640 /etc/gshadow-
}

#6.1.10 Ensure no world writable files exist
rule-6.1.10()
{
    echo
    echo "Ensure no world writable files exist"
    df --local -P | awk {'if (NR!=1) print $6'} | while read mnt; do
        find ${mnt} -xdev -type f -perm -0002 -execdir chmod o-w '{}' \; 2>/dev/null
    done
}

#6.1.11 Ensure no unowned files or directories exist
rule-6.1.11()
{
    echo
    echo "Ensure no unowned files or directories exist"
    local user=`read_usr_param unowned_user`
    df --local -P | awk {'if (NR!=1) print $6'} | while read mnt; do
        find ${mnt} -xdev -nouser -execdir chown $user '{}' \; 2>/dev/null
    done
}

#6.1.12 Ensure no ungrouped files or directories exist 
rule-6.1.12()
{
    echo
    echo "Ensure no ungrouped files or directories exist"
    local group=`read_usr_param unowned_group`
    df --local -P | awk {'if (NR!=1) print $6'} | while read mnt; do
        find ${mnt} -xdev -nogroup -execdir chown :$group '{}' \; 2>/dev/null
    done
}

#6.1.13 Audit SUID executables (Not Scored)

#6.1.14 Audit SGID executables (Not Scored)

#6.2.1 Ensure password fields are not empty
rule-6.2.1()
{
    echo
    echo "Ensure password fields are not empty"
    for usr in `cat /etc/shadow | awk -F: '($2 == "" ) { print $1}'`; do
        passwd -l $usr
    done
}

#6.2.2 Ensure no legacy "+" entries exist in /etc/passwd
#6.2.3 Ensure no legacy "+" entries exist in /etc/shadow
#6.2.4 Ensure no legacy "+" entries exist in /etc/group
rule-6.2.2-4()
{
    local files="/etc/passwd /etc/shadow /etc/group"
    for f in $files; do
        echo
        echo "Ensure no legacy \"+\" entries exist in $f"
        sed -i '/^+:/d' $f
    done
}

#6.2.5 Ensure root is the only UID 0 account
rule-6.2.5()
{
    echo
    echo "Ensure root is the only UID 0 account"
    local uid0_usr=`grep -v '^root:' /etc/passwd |\
        awk -F: '($3 == 0) { print $1 }'`
    for usr in uid0_usr; do
        sed -i "/$usr/d" /etc/passwd
    done
}

#6.2.6 Ensure root PATH Integrity
rule-6.2.6()
{
    echo
    echo "Ensure root PATH Integrity"

    local issue_found=0
    if [ "`echo $PATH | grep :: `" != "" ]; then
       echo "Empty Directory in PATH (::)"
       issue_found=1
    fi

    if [ "`echo $PATH | grep :$`"  != "" ]; then
        echo "Trailing : in PATH"
        issue_found=1
    fi

    p=`echo $PATH | sed -e 's/::/:/' -e 's/:$//' -e 's/:/ /g'`
    set -- $p
    while [ "$1" != "" ]; do
        if [ "$1" = "." ]; then
            echo "PATH contains ."
            issue_found=1
            shift
            continue
        fi
        if [ -d $1 ]; then
            dirperm=`ls -ldH $1 | cut -f1 -d" "`
            if [ `echo $dirperm | cut -c6 ` != "-" ]; then
                issue_found=1
                echo "Group Write permission set on directory $1"
            fi
            if [ `echo $dirperm | cut -c9 ` != "-" ]; then
                issue_found=1
                echo "Other Write permission set on directory $1"
            fi
            dirown=`ls -ldH $1 | awk '{print $3}'`
            if [ "$dirown" != "root" ] ; then
                echo $1 is not owned by root
                issue_found=1
            fi
        else
            echo $1 is not a directory
            issue_found=1
        fi
        shift
    done

    if [ "$issue_found" -eq 1 ]; then
        echo "Ensure root PATH Integrity - requires manual configuration"
    fi
}

#6.2.7 Ensure all users' home directories exist
rule-6.2.7()
{
    echo
    echo "Ensure all users' home directories exist"

    fetch_users_and_homedir |\
    while read user dir; do
        pushd /
        mkdir -p $dir
        popd
    done
}

#6.2.8 Ensure users' home directories permissions are 750 or more restrictive
rule-6.2.8()
{
    local adduser_conf=/etc/adduser.conf
    local useradd_conf=/etc/login.defs
    echo
    echo "Ensure users' home directories permissions are 750 or more restrictive"

    fetch_users_and_homedir |\
    while read user dir; do
        chmod o-wrx,g-w $dir
    done

    # For users added through adduser
    grep -q '^DIR_MODE=' $adduser_conf
    if [ $? -eq 0 ]; then
        sed -E -i 's/(^DIR_MODE=).*$/\10750/g' $adduser_conf
    else
        echo 'DIR_MODE=0750' >> $adduser_conf
    fi

    # For users added through useradd
    egrep -q '^UMASK\b' $useradd_conf
    if [ $? -eq 0 ]; then
        sed -E -i 's/(^UMASK\s+).*$/\1027/g' $useradd_conf
    else
        echo 'UMASK           027' >> $useradd_conf
    fi
}

#6.2.9 Ensure users own their home directories
rule-6.2.9()
{
    echo
    echo "Ensure users own their home directories"
    
    fetch_users_and_homedir |\
    while read user dir; do
        chown $user $dir
    done
}

#6.2.10 Ensure users' dot files are not group or world writable
rule-6.2.10()
{
    echo
    echo "Ensure users' dot files are not group or world writable"
    fetch_users_and_homedir |\
    while read user dir; do
        find $dir -iname '.*' -type f -execdir chmod o-wx,g-w {} \;
    done
}

#6.2.11 Ensure no users have .forward files
rule-6.2.11()
{
    local del_files=`read_usr_param delete_user_files`
    echo
    echo "Ensure no users have .forward files"
    fetch_users_and_homedir |\
    while read user dir; do
        if [ -f $dir/.forward ]; then
            if "$del_files"; then
                rm -f $dir/.forward
            else
                echo ".forward file found in $user homedir. Manual fix required."
            fi
        fi
    done
}

#6.2.12 Ensure no users have .netrc files
rule-6.2.12()
{
    local del_files=`read_usr_param delete_user_files`
    echo
    echo "Ensure no users have .netrc files"
    fetch_users_and_homedir |\
    while read user dir; do
        if [ -f $dir/.netrc ]; then
            if "$del_files"; then
                rm -f $dir/.netrc
            else
                echo ".netrc file found in $user homedir. Manual fix required."
            fi
        fi
    done
}

#6.2.13 Ensure users' .netrc Files are not group or world accessible
rule-6.2.13()
{
    echo
    echo "Ensure users' .netrc Files are not group or world accessible"
    fetch_users_and_homedir |\
    while read user dir; do
        chmod -f og-rwx $dir/.netrc
    done
}

#6.2.14 Ensure no users have .rhosts files
rule-6.2.14()
{
    local del_files=`read_usr_param delete_user_files`
    echo
    echo "Ensure no users have .rhosts files"
    fetch_users_and_homedir |\
    while read user dir; do
        if [ -f $dir/.rhosts ]; then
            if "$del_files"; then
                rm -f $dir/.rhosts
            else
                echo ".rhosts file found in $user homedir. Manual fix required."
            fi
        fi
    done
}

#6.2.15 Ensure all groups in /etc/passwd exist in /etc/group
rule-6.2.15()
{
    echo
    echo "Ensure all groups in /etc/passwd exist in /etc/group"
    for i in $(cut -s -d: -f4 /etc/passwd | sort -u ); do
        grep -q -P "^.*?:[^:]*:$i:" /etc/group
        if [ $? -ne 0 ]; then
            groupadd $i
        fi
    done
}

#6.2.16 Ensure no duplicate UIDs exist
rule-6.2.16()
{
    echo
    echo "Ensure no duplicate UIDs exist"

    local flagfile="/tmp/.$FUNCNAME"
    cat /etc/passwd | cut -f3 -d":" | sort -n | uniq -c | while read x ; do
    [ -z "${x}" ] && break
    set - $x
    if [ $1 -gt 1 ]; then
        users=`awk -F: '($3 == n) { print $1 }' n=$2 /etc/passwd | xargs`
        echo "Duplicate UID ($2): ${users}"
        touch $flagfile
    fi
    done

    if [ -e $flagfile ]; then
        echo "Duplicate UIDs exist! Manual fix required."
        rm $flagfile
    fi
}

#6.2.17 Ensure no duplicate GIDs exist
rule-6.2.17()
{
    echo
    echo "Ensure no duplicate GIDs exist"

    local flagfile="/tmp/.$FUNCNAME"
    cat /etc/group | cut -f3 -d":" | sort -n | uniq -c | while read x ; do
    [ -z "${x}" ] && break
        set - $x
        if [ $1 -gt 1 ]; then
            groups=`awk -F: '($3 == n) { print $1 }' n=$2 /etc/group | xargs`
            touch $flagfile
            echo "Duplicate GID ($2): ${groups}"
        fi
    done

    if [ -e $flagfile ]; then
        echo "Duplicate GIDs exist! Manual fix required."
        rm $flagfile
    fi
}

#6.2.18 Ensure no duplicate user names exist
rule-6.2.18()
{
    echo
    echo "Ensure no duplicate user names exist"

    local flagfile="/tmp/.$FUNCNAME"
    cat /etc/passwd | cut -f1 -d":" | sort -n | uniq -c | while read x ; do
    [ -z "${x}" ] && break
        set - $x
        if [ $1 -gt 1 ]; then
            uids=`awk -F: '($1 == n) { print $3 }' n=$2 /etc/passwd | xargs`
            echo "Duplicate User Name ($2): ${uids}"
            touch $flagfile
        fi
    done

    if [ -e $flagfile ]; then
        echo "Duplicate user names exist! Manual fix required."
        rm $flagfile
    fi
}

#6.2.19 Ensure no duplicate group names exist
rule-6.2.19()
{
    echo
    echo "Ensure no duplicate group names exist"

    local flagfile="/tmp/.$FUNCNAME"
    cat /etc/group | cut -f1 -d":" | sort -n | uniq -c | while read x ; do
    [ -z "${x}" ] && break
        set - $x
        if [ $1 -gt 1 ]; then
            gids=`awk -F: '($1 == n) { print $3 }' n=$2 /etc/group | xargs`
            echo "Duplicate Group Name ($2): ${gids}"
            touch $flagfile
        fi
    done

    if [ -e $flagfile ]; then
        echo "Duplicate group names exist! Manual fix required."
        rm $flagfile
    fi
}

#6.2.20 Ensure shadow group is empty
rule-6.2.20()
{
    echo
    echo "Ensure shadow group is empty"

    local shadow_gid=`grep shadow /etc/group | cut -d: -f3`
    local usr_from_group=`grep ^shadow:[^:]*:[^:]*:[^:]+ /etc/group`
    local grp_from_users=`awk -F: '($4 == '$shadow_gid') { print }' /etc/passwd`
    if [ -n "$usr_from_group"  ] ||\
       [ -n "$grp_from_users" ]; then
       echo "Shadow group is not empty! Manual fix required."
    fi
}

execute_ruleset-6()
{
    local -A rulehash
    local common="6.1.2 6.1.3 6.1.4 6.1.5 6.1.6 6.1.7 6.1.8 6.1.9 6.1.10\
        6.1.11 6.1.12 6.2.1 6.2.2-4 6.2.5 6.2.6 6.2.7 6.2.8 6.2.9\
        6.2.10 6.2.11 6.2.12 6.2.13 6.2.14 6.2.15 6.2.16 6.2.17 6.2.18 6.2.19\
        6.2.20"
    rulehash[lvl1_server]=$common
    rulehash[lvl2_server]="${rulehash[lvl1_server]}"" "
    rulehash[lvl1_workstation]=$common
    rulehash[lvl2_workstation]="${rulehash[lvl1_workstation]}"" "

    do_execute_rules ${rulehash[$1]}
}
