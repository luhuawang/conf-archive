#!/bin/bash
#
# GPL-2.0-only
# Author: Louis Wang <wluhua@gmail.com>
# Description: script to archive status for a running Linux system, and find differences between two archive file.
#
# DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
#
# Copyright (C) 2011 Louis Wang <wluhua@gmail.com>
#

##############################################################################
# How this scirpt works?
#    With -a|--archive flag, it will create a archive file (tar.bz2) with following contents:
#        1.0 - discover all the modified files (text):
#            1.1. run 'rpm -v' to verify installed rpm files, and find out all the modified config files
#            1.2. use 'find' and 'rpm -qf' to find all txet files which not included on any rpm package
#            1.3. find other well known files which is not included on any rpm package
#        2.0 - discover the running status
#            2.1. kernel parameters at runtime ('uname -r', 'sysctl -a' and 'lsmod')
#            2.2. ksplice patch (/usr/lib/uptrack/ksplice-view and 'uptrack-uname -r')
#            2.3. rpm list ('rpm -qa' and 'package-update -list')
#            2.4. service ('chkconfig --list' and 'service --status-all')
#            2.5. file and folder permissions (find -P / -maxdepth 6 -printf "%p (%y, %m, %U, %G, %s, %TY-%Tm-%Td %TH:%TM:%TS)\n)
#            2.6. disk layout (df -hP, fdisk -l, mdadm --detail --scan --verbose, lvscan, ddcli -listall)
#            2.7. hardware raid config (megacli)
#            2.8. dmidecode, ilom config, biosconfig
#            2.9. network adapter statistics, including LSO/TSO info ('ethtool -k' and 'ethtool -S')
#            2.10. and some other running status.
#        3.0 - and system log (/var/log and oswbb log)
#        Note: the size is 400K only if no syslog flag for archive
#    With -d|--diff flag, it will do:
#        run 'diff -Npru' for all the file pair in two archive files (tar.bz2)
#           

##############################################################################
# Exmaple of the Usage: 
# 
#            Create one OS Status Archive File for a running Linux system:
#            # cd /var/tmp/
#            # wget --no-proxy -O conf-archive.sh https://raw.githubusercontent.com/luhuawang/conf-archive/master/conf-archive.sh
#            # chmod 540 conf-archive.sh
#
#            Archiving (-a) a Linux system, including all the well known files (-f) and logs (-l):
#            # ./conf-archive.sh -a -f -l
#
#            To diff 2 systems, we run it on each system with -a (--archive) flag, and copy the tar.bz2 file over and run the compare command (-d).
#            Comparing two archived files (-d), and keep the uncompressed files (-k):
#            # ./conf-archive.sh -d before.tar.bz2 after.tar.bz2 -k -v 
#
#            Please run './conf-archive.sh -h' to get more info about the usage.

##############################################################################
# Know isue: 
#     rpm -V need 1.7 GB free RAM, otherwize, it can can cause domU creashed. ( I will add this to pre-check item before run rpm -V ).
#   

########################################
# Variables
#
## Variables for the program
PATH=/opt/exalogic.tools/tools:/opt/MegaRAID/MegaCli:/usr/local/pdit/bin:/usr/local/git/bin/:/usr/local/bin:/usr/local/sbin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH:./
export PATH
PROG="`basename $0`"
PROG_HOME="$(dirname $(readlink -f $0))"
WORK_DIR=$(pwd)
minute=`date +'%y.%m.%d.%H%M'`
hostn=`hostname`
typeset=os-stat
# TMP_FILE_REP="${hostn}_${typeset}_${minute}.txt"
TMP_FILE_REP="${hostn}_${typeset}.log"
TMP_FILE=`echo /tmp/$$.${typeset}.tmp`
TMP_DIR_STAT=/tmp/0STAT
FILE_SELECTED=${TMP_DIR_STAT}/selected_files-list
DIFF_REP=os-stat-diff_summary.txt
shopt -s expand_aliases
alias TimeFormat="date -u +'%Y-%m-%d %H:%M:%S.%3N'"

########################################
## User's Variables - Start

# CONFIG_FILES_DIR
#  The program search the CONFIG_FILES_DIR to find the text files which not a part of any RPM package
CONFIG_FILES_DIR="/boot
/etc
/usr
/var
/opt
/OVS
/xen
/root
/conf
/config/etc
/config/conf"

# WELL_KNOWN_FILES
#  The program search the text file listed on WELL_KNOWN_FILES.  
#  If a file is a part of any RPM package, and passed the 'rpm -V' check, then, it will be bypassed.
#  If '--force_archive' flag is used, all the text file listed on the WELL_KNOWN_FILES will be archived nomater it is modified or not.
#  The program will also archive the folder and files' mode listed on WELL_KNOWN_FILES
WELL_KNOWN_FILES="/boot/grub/grub.conf
/boot/grub2/grub.cfg
/etc/aide.conf
/etc/anacrontab
/etc/at.allow
/etc/at.deny
/etc/audit/audit.key
/etc/avahi/avahi-daemon.conf
/etc/cron.allow
/etc/cron.d
/etc/cron.daily
/etc/cron.deny
/etc/cron.hourly
/etc/cron.monthly
/etc/crontab
/etc/cron.weekly
/etc/csh.cshrc
/etc/csh.login
/etc/fstab
/etc/group
/etc/gshadow
/etc/hosts
/etc/hostname
/etc/idmapd.conf
/etc/infiniband/openib.conf
/etc/rdma/rdma.conf
/etc/init/control-alt-delete.conf
/etc/init.d/functions
/etc/init.d/ovs-agent
/etc/inittab
/etc/issue
/etc/issue.*
/etc/issue.net
/etc/kdump.conf
/etc/ldap.conf
/etc/libsdp.conf
/etc/login.defs
/etc/logrotate.conf
/etc/lvm/lvm.conf
/etc/mail/sendmail.cf
/etc/mail/sendmail.mc
/etc/mdadm.conf
/etc/modprobe.conf
/etc/modprobe.d
/etc/modprobe.d/*
/etc/modprobe.d/blacklist.conf
/etc/modprobe.d/disableipv6
/etc/modprobe.d/disableipv6.conf
/etc/modprobe.d/ixgbe_LRO
/etc/modprobe.d/rpc_slot
/etc/modprobe.d/rpc_slot.conf
/etc/motd
/etc/mtab
/etc/nisswitch.conf
/etc/nsswitch.conf
/etc/ntp.conf
/etc/openldap/ldap.conf
/etc/*-Release
/etc/*-release
/etc/ovs-info
/etc/pam.d/login
/etc/pam.d/su
/etc/pam.d/system-auth
/etc/passwd
/etc/pb.settings
/etc/ldap.conf
/etc/nslcd.conf
/etc/pam_ldap.conf
/etc/sssd/sssd.conf
/etc/rc.d/init.d
/etc/rc.d/init.d/sunrpcsysctl
/etc/rc.d/rc.local
/etc/resolv.conf
/etc/rsyncd.conf
/etc/securetty
/etc/security/limits.conf
/etc/security/limits.d/*.conf
/etc/security/opasswd
/etc/selinux
/etc/selinux/*
/etc/selinux/config
/etc/shadow
/etc/shells
/etc/smartd.conf
/etc/ssh/ssh_config
/etc/ssh/sshd_config
/etc/sudoers
/etc/sysconfig/harddisks
/etc/sysconfig/network
/etc/sysconfig/network-scripts/ifcfg-*
/etc/sysconfig/nfs
/etc/sysconfig/selinux
/etc/sysconfig/sysstat
/etc/sysconfig/xendomains
/etc/sysctl.conf
/etc/syslog.conf
/etc/udev/rules.d/70-persistent-net.rules
/etc/xen/scripts/network-nop
/etc/xen/xend-config.sxp
/etc/ocfs2/cluster.conf
/root/anaconda-ks.cfg
/usr/lib/init-exalogic-node/.image_id
/usr/lib/init-exalogic-node/.template_version
/usr/local/git/etc/machine_timezone.conf
/usr/local/git/etc/mkks-iso-version
/usr/local/git/etc/package-update.cc
/usr/local/git/etc/rpm-remove-firstboot
/usr/local/git/etc/ssh_config
/usr/local/git/etc/tapeserv.conf
/var/lib/aide/*
/var/lib/aide/aide.db.gz
/var/lib/aide/aide.db.new.gz
/var/log/init-exalogic-node/.image_history
/var/spool/cron/*
/root/.bash_history
/root/.bash_logout
/root/.bash_profile
/root/.bashrc
/root/.ssh
/root/.vnc
/sys/class/infiniband/mlx4_0/fw_ver
/sys/class/infiniband/mlx4_0/node_desc
/sys/class/net/ib0/mode
/sys/class/net/ib1/mode"

PROC_FILE_SYSTEM="/proc/cmdline /proc/meminfo /proc/net/bonding/* /proc/partitions /proc/self/mounts"

# REGEX_XXX
#  Define the regex filter (-regextype posix-extended) for 'find' program: e.g.: find / -regextype posix-extended -type f -regex '^/abc/.*'
#  Any file with following suffix will not be archived:
regex_suf="! -regex '.*\.([a-z]|[0-9]|png|mo|o|htm|html|hpp|ch|3p|pm|idl|3x|out|vim|de|3gl|sv|svg|3pm|gz|am|el|al|cs|jp|jpg|as|en|ad|ps|in|3ssl|3stap|es|afm|st|swg|1p|boot|ap|ent|css|desktop|ar|ac|debug|ico|icon|dsl|log|info|se|ipp|dir|1x|ms|au|def|3tiff|is|me|pfb|msg|it|server|decTest|pbm|gml|bash|img|cset|direct|defs|lang|cache)$'"

# Any file in following folders will not be archived:
regex_sys="! -regex '^/(lib|lib64|media|src|tmp|home|root|etc/gconf|etc/sgml|lvm/cache|opt/oc4j/j2ee|opt/jdk6/jre)/.*'"
regex_var="! -regex '^/var/(lock|tmp|run|cache|spool|log|mpi-selector|lib/scrollkeeper|lib/alternatives|lib/rpm|lib/yum|lib/Pegasus|opt/sun/xvm/OCDoctor)/.*'"
regex_usr="! -regex '^/usr/(share|src|lib64|lib|include|local/oracle)/.*'"
regex_opt="! -regex '^/opt/(fvwm_local|jdev_local|microfocus|.*/share|.*/j2ee|.*/jdk|.*/jre|.*/demo|.*/lib|.*/lang|.*/src)/.*'"
regex_doc="! -regex '.*(/doc/|/docs/|/man/|/gcc/|/src/|/lang/|\.bak\.).*'"

# Any file with following well knows suffix will not be archived:
regex_bak="! -regex '.*\.(lock|old|OLD|bak|rpm|rpmsave|rpmnew|save|orig|new|pid|log|db|png)$'"

# Any file in NFS shares will not be archived:
# regex_nfs=$(
   # wc=$( (mount -l -t nfs && mount -l -t nfs4) |wc -l )
   # if [ $wc -gt 0 ]
   # then
       # (mount -l -t nfs && mount -l -t nfs4) |awk '{print $3}' |while read line
       # do
           # printf "$line/.*|"
       # done | sed "s/|$//g; s/^/! -regex '^\(/g;s/$/\)'/g"
   # fi
# )

regex_prune=$(
    local="/net /proc /sys /dev /lib64 /lib /usr/lib /usr/lib64 /usr/local/solaris /usr/local/ade /usr/local/bin /usr/local/common /usr/local/games /usr/local/git /usr/local/image /usr/local/lib64 /usr/local/libexec /usr/local/nde /usr/local/packages /usr/local/redhat /usr/local/remote /usr/local/sbin /usr/local/share /usr/local/sol_bin /usr/local/sol_packages /usr/local/solaris /usr/local/src /usr/local/writeable"
    nfs="`(mount -l -t nfs && mount -l -t nfs4) |awk '{print $3}' |tr '\n' ' '`"
    autofs="`cat /etc/auto.master |sed 's/#.*//g' |grep "/" |awk  '{print $1}' |tr '\n' ' '`"
    echo "$autofs $nfs $local" |tr ' ' '\n' |sed '/^$/d' |while read line
    do
        printf "$line|"
    done | sed "s/|$//g; s/^/-regex '^\(/g;s/$/\)'/g"
)

# Test:
# eval find -P / -maxdepth 8 -regextype posix-extended -type d $regex_prune -prune -o -type f -name ldap.conf


## User's Variables - End
########################################

##
# variables for flock lock
LOCKFILE="/tmp/`basename $0`.lock"
LOCKFD=99
 
########################################
#
# Subroutines
#
error() {
   echo "ERROR: $1" 
   exit 1;
}

warn() {
   echo "WARN: $1" ;
}

info() {
   echo "INFO: $1" ;
}

debug() {
   # print the output as stderr
   [ -n "$DEBUG" ] && echo -e "\nDEBUG: $@" 1>&2;
}

usage() {

help_msg="
-E- Missing option
Usage: 
  ./$PROG <options>

Options:
  -a, --archive
         Generate a OS Status Archive File for the running Linux system
  -d SOURCE.TAR.BZ2 TARGET.TAR.BZ2, --diff SOURCE.TAR.BZ2 TARGET.TAR.BZ2 
         Find differences between two OS Status Archive Files
         e.g.: ./$PROG -d before.tar.bz2 after.tar.bz2   
  -r ARCHIVE.TAR.BZ2, --report ARCHIVE.TAR.BZ2
         Generate the summary of the status for one OS Status Archive File
  -l, --log
         Tells '--archive' flag to archive /var/log and oswbb archive
  -f, --force_archive
         Tells '--archive' flag to archive all the well known configuration files even though it not modified.
  --noperm
         Don't scan the file permission list
  -v     Tells '--diff' flag to be verbose and display detailed information about the differences.
         All the filename will be displaed on report.
  -vv    Tells '--diff' flag to be very verbose and display even more information
         The content of the file which found only on TARGET.TAR.BZ2 will be displaed on the report
  --diff-file-tree   Tells '--diff' flag to diff the soft link tree and file tree    
  --sort Tells '--diff' flag to sort files before run diff
         If the tag 'sort' enabled, the script will run diff without any option, instead of 'diff -Npru',
         and skip all the line leading by \"#\".
  -k, --keep-temp-files
         Tells '--diff' flag to keep the uncompressed files on the work folder.
         As design, the program don't do diff for files with '-' as suffix. e.g. filesystem_permission_tree-mtime.out-
         You can use '-k' flag to keep the uncompressed files and run diff manually for file with name '.out-' as suffix.
  --debug
Example: 
  #  Archiving (-a) a Linux system, including all the well known files (-f), logs (/var/log and oswbb) (-l):
     ./$PROG -a -f -l
  #  Archiving (-a) a Linux system, including all the well known files (-f), without logs:
     ./$PROG -a -f
  #  Archiving (-a) a Linux system, including all the well known files (-f), without logs or file permission list:
     ./$PROG -a -f --noperm
  #  Comparing two archived files (-d), including file tree, and keep the uncompressed files (-k):
     ./$PROG -d before.tar.bz2 after.tar.bz2 --diff-file-tree -k -v 
  #  Comparing two archived files (-d) without the file tree, sort files before run diff
     ./$PROG -d before.tar.bz2 after.tar.bz2 --sort -v
"

printf "%s\n" "$help_msg" |more -d

        
exit 1
}


              
########################################
# function for flock lock
_lock()             { flock -$1 $LOCKFD; }
_no_more_locking()  { _lock u; _lock xn && rm -f $LOCKFILE; trap_clean_up;}
_prepare_locking()  { eval "exec $LOCKFD>\"$LOCKFILE\""; trap _no_more_locking EXIT; }
_prepare_locking
exlock_now()        { _lock xn; }  # obtain an exclusive lock immediately or fail
exlock()            { _lock x; }   # obtain an exclusive lock
shlock()            { _lock s; }   # obtain a shared lock
unlock()            { _lock u; }   # drop a lock
########################################

trap_clean_up() {
    # set trap/clean up procedure, run by root check
    # this func is called by _no_more_locking
    echo ${TMP_DIR_STAT} | grep -q "tmp" \
        && [ -d ${TMP_DIR_STAT} ] \
        && rm -rf ${TMP_DIR_STAT}
}

generate_rpm_config_files_list () {
    # Verifying installed files
    # The format of the output is a string of 8 characters, a possible attribute marker: 
    # S file Size differs
    # M Mode differs (includes permissions and file type)
    # 5 MD5 sum differs
    # D Device major/minor number mismatch
    # L readLink(2) path mismatch
    # U User ownership differs
    # G Group ownership differs
    # T mTime differs 
    #
    # c %config configuration file.
    # d %doc documentation file.
    # g %ghost file (i.e. the file contents are not included in the package payload).
    # l %license license file.
    # r %readme readme file. 
    #
    # Note: Verify Options - http://www.rpm.org/max-rpm-snapshot/rpm.8.html

    ###
    # Two output: 
    #   1) packages_rpm-verify.out
    #   2) rpm config files which failed on 'rpm -V' check

    info "run 'rpm -V' to verify installed rpm files (print the failed item to screen) ..."
    PKGS=`rpm -qa --qf '%{n}-%{v}-%{r}.%{arch}\n' |sort`

    for pkg in ${PKGS}; do
        /bin/rpm -V $pkg 2>&1 | /bin/egrep -vw 'man|doc|info|locale' | \
            /bin/grep -v '^\.\.\.\.[L.][U.][G.][T.]' | \
            /bin/grep -v '^\.M\.\.\.\.\.\.    ' | \
            /bin/grep -v ' /conf/' | \
            /bin/grep -v ' /config/conf/'  | \
            /bin/grep -v ' /lib/modules/2\.6\.27\.13-nm2/modules\.' |\
            /bin/grep -v 'dependencies has changed since prelinking' |\
            /bin/grep -v 'Unsatisfied dependencies for ' \
                2>&1 >${TMP_FILE}.pkgV

        if [ -n "$(cat ${TMP_FILE}.pkgV)" ] ; 
        then
            printf "\n"      
            printf "%s\n"  "* Package $pkg:" 
            cat ${TMP_FILE}.pkgV    
        else
            echo -n .
        fi
    done | tee -a packages_rpm-verify.out
    rm -f ${TMP_FILE}.pkgV 2>&1 >/dev/null
     
    ## Added to archive_list
    if :
    then
        T=CONF_IN_RPM_EXCEPTIONS
        exec_add_comm "start" "${T}" "Text File in RPM failed on 'rpm -V' check" 
        cat packages_rpm-verify.out |awk -F" c " '{print $2}' |sed '/^$/d' |sort |uniq |sed 's/$/ # Text File in RPM failed on "rpm -V" check/g'
        exec_add_comm "end" "${T}" "" 
    fi >> ${FILE_SELECTED}
    cat packages_rpm-verify.out |grep missing |awk -F" c " '{print $2}' |sed '/^$/d' |sort |uniq > filesystem_removed_files.out
}

exec_add_comm () {
    # exec_add_comm "$_OPS" "$T" "$_NOTE"
    _OPS="$(echo "$1" |tr '[:lower:]' '[:upper:]')"; 
    T="$(echo "$2" |tr '[:lower:]' '[:upper:]')"; 
    _NOTE="$3"
    printf "# %s\n"        "zzz *** - ${_OPS} ARCHIVE FILE LIST: ${T}" 
    [ "${_OPS}" = "START" ] && printf "# %s\n"        "Note: ${_NOTE}"
}


generate_nonrpm_text_files_list() {
    echo ""
    info "Prepare the text file list which not included in any RPM"

    for mydir in $CONFIG_FILES_DIR
    do
    [ -d $mydir ] && eval "find -P $mydir -maxdepth 8 -regextype posix-extended -type d $regex_prune -prune -o -type f $regex_sys $regex_var $regex_usr $regex_opt $regex_doc $regex_suf $regex_bak  -exec file {} \;" | \
        grep text | sed '/bin\/.*executable/d' | \
        cut -d ':' -f1 | \
        while read NF
        do
            if `rpm -qf $NF >/dev/null 2>&1`; then
            echo -n .
                NFRC=NO
            else
                [ -n "$NFRC" ] && echo ""
                echo $NF | tee -a non-rpm-files.ls
                unset NFRC
            fi
        done
    done

     ## Added to archive_list
     if :
     then
          T=TEXT_NOT_IN_RPM
         exec_add_comm "start" "${T}" "Text File not included in any RPM" 
         cat non-rpm-files.ls |sed '/^$/d' |sort |uniq |sed 's/$/ # Text File not included in any RPM/g'
         rm -f non-rpm-files.ls
         exec_add_comm "end" "${T}" "" 
     fi >>  "${FILE_SELECTED}"

}


generate_wellknown_files_list () {
    # Other files
    echo ""
    info "Prepare the well known files (text type only) ..."
    _WELL_KNOWN_FILES=$(file $WELL_KNOWN_FILES |sed '/cannot open/d'|grep "text\|empty" |awk -F: '{print $1}' |sort |uniq )

    ##   if the file is not text or empty, skip
    ##   If the file is already listed on ${FILE_SELECTED}, skip
    ##   FORCE_ARCHIVE_ENABLE is not set:
    ##      If the file is a part a a rpm, skip (No change in the rpm)
    ##      if the file is not a rpm, add it to list with tag: Text_File_Not_Owned_by_RPM
    ##   FORCE_ARCHIVE_ENABLE is not set:
    ##      If the file is a part a a rpm,  ad it to list with tab: No Changed Text File in RPM 
    ##      if the file is not a rpm, add it to list with tag: Text_File_Not_Owned_by_RPM

    for N in $_WELL_KNOWN_FILES
    do
        if `grep -qw ${N} ${FILE_SELECTED}*`; then
            if [ "${VERBOSE:0:1}" = "v" ] 
            then
                [ -n "$RC" ] && printf "\n"; unset RC;
                printf "%-45s  %s\n" "$N" "Skipped. Already listed on FILE_SELECTED" 
            else
                printf "%s" "."; RC=NO
            fi
        else      
            if `rpm -qf $N >/dev/null 2>&1`; 
            then
                if [ "$FORCE_ARCHIVE_ENABLE" = "FORCE_ARCHIVE_ENABLE" ] 
                then
                    echo "$N" >> ${FILE_SELECTED}.wellknown.rpm
                    [ -n "$RC" ] && printf "\n"; unset RC;
                    printf "%-45s  %s\n" "${N}" "Added. Text File in in RPM, No Change. (FORCE_ARCHIVE_ENABLE flag)" 
                else
                    if [ "${VERBOSE:0:1}" = "v" ] 
                    then
                        [ -n "$RC" ] && printf "\n"; unset RC;
                        printf "%-45s  %s\n" "${N}"   "Skipped. Text File in RPM, No Change." 
                    fi 
                fi 
            else
                echo "$N" >> ${FILE_SELECTED}.wellknown     
                [ -n "$RC" ] && printf "\n"; unset RC;
                printf "%-45s  %s\n" "${N}"   "Added. Text File not in any RPM"                           
            fi
        fi
        
       
        
    done
    
    # tarball the proc file system    
    for PROC_FILE in `ls $PROC_FILE_SYSTEM`
    do
        PROC_FILE_OUT=$(echo $PROC_FILE |sed 's/[^a-zA-Z0-9_-]/_/g;s/^_//g')
        cat $PROC_FILE > $PROC_FILE_OUT.out
    done

    if [ -f ${FILE_SELECTED}.wellknown ]
    then
        T=OTHER_TEXT_NOT_IN_RPM
        exec_add_comm "start" "${T}" "Text File - Other Well known files (Non RPM)" 
        cat ${FILE_SELECTED}.wellknown |sed '/^$/d' |sort |uniq |sed 's/$/ # Text File - Other Well known files (Non RPM)/g' 
        rm -f ${FILE_SELECTED}.wellknown
        exec_add_comm "end" "${T}" "" 
    fi >> ${FILE_SELECTED}


    if [ -f ${FILE_SELECTED}.wellknown.rpm ]
    then
        T=OTHER_TEXT_IN_RPM
        exec_add_comm "start" "${T}" "Text File in RPM, No Change" 
        cat ${FILE_SELECTED}.wellknown.rpm |sed '/^$/d' |sort |uniq |sed 's/$/ # Text File in RPM, No Change/g' 
        rm -f ${FILE_SELECTED}.wellknown.rpm
        exec_add_comm "end" "${T}" "" 
    fi >> ${FILE_SELECTED}
	
	local _WELL_KNOWN_FILES="$(echo $WELL_KNOWN_FILES |tr '\n' ' ')"
	eval "find -P $_WELL_KNOWN_FILES -maxdepth 2 -regextype posix-extended -type d $regex_prune -prune  -o -printf \"%p (%y, %m, %U, %G, %s)\n\" 2>/dev/null >filesystem_permission_wellknown_files.out "
    sort filesystem_permission_wellknown_files.out -o filesystem_permission_wellknown_files.out
}

execute_running_stat () {
    echo ""
    info "prepare system status to ${TMP_DIR_STAT}"
    #upper_nodetype=`echo $nodetype |tr [:lower:] [:upper:]`
    upper_nodetype=CN
    sed -ne '/-BEGIN '"$upper_nodetype"' CHECKLIST-/,/-END '"$upper_nodetype"' CHECKLIST-/p' $PROG_HOME/$PROG | sed 's/^ * //g;s/^ //g; /^#/d;/^$/d' | 
    while read ExecLine
    do
        _filename=$(echo "$ExecLine" |awk -F"report_file:" '{print $2}' |sed 's|^/||g;s/^ * //g;s/^ //g;s/#.*//g; s/ * $//g;s| |_|g;s|/|_|g;s|\||_|g;s|"||g')
        [ -z "$_filename" ] && _filename=$(echo "$ExecLine" |awk -F"|" '{print $1}' |sed 's|^/||g;s/^ * //g;s/^ //g;s/#.*//g; s/ * $//g;s| |_|g;s|/|_|g;s|\||_|g;s|"||g')
        _ExecLine=$(echo "$ExecLine" |sed 's/#.*//g;s/ * $//g')
        _prog=`echo "$_ExecLine" | awk '{print $1}'`
        info "Try: $_ExecLine"
        
        if `which $_prog >/dev/null 2>&1`; 
        then
            echo "#-------- $_ExecLine ----------" 
            eval "$_ExecLine" 2>&1  
        fi  | grep -v "File descriptor.*/var/lock\|Unable to connect to xend\|No such file or directory" >> $_filename
                
        if [ -f "$_filename" ]
        then
            wc=$( cat $_filename |wc -l )         
            [ $wc -le 1 ] && rm -f $_filename
        fi
    done
    
    if :
    then
        echo "#-------- arguments for conf-archive.sh ----------" 
        echo "$ARGUMENTS" 
    fi > conf-archive.sh.arguments.out
}

generate_gtar_archive() {
    ## Tar
    # log
    if [ "$LOG_ENABLE" = "LOG_ENABLE" ]
    then
		if [[ "$free_tmpspace_tag" != failed ]]
		then
			# system log: system_log.tar.bz2
			info "Create system_log.tar.bz2 ...."
			TAR_NAME=$TMP_DIR_STAT/system_log.tar; 
			touch $TAR_NAME;
			eval "find -P /var/log -maxdepth 8 -regextype posix-extended  -type d $regex_prune -prune -o -type f  ! -regex '.*(os-watcher|oswbb|oswatcher|os-watcher)/.*' | xargs gtar -rvf $TAR_NAME >/dev/null 2>&1; "
			[ -/usr/bin/bzip2 ] && /usr/bin/bzip2 -f $TAR_NAME
			 
			## oswatcher archive: oswbb_archive.tar.bz2
			info "Create oswbb_archive.tar.bz2 ...."
			# Location of the OSWatcher Archive
			TAR_NAME=$TMP_DIR_STAT/oswbb_archive.tar; 
			touch $TAR_NAME
			eval "find -P /var /opt /u03 -maxdepth 8 -regextype posix-extended -type f -regex '.*(oswbb|oswatcher|os-watcher).*archive/.*' 2>/dev/null| xargs gtar -rvf $TAR_NAME >/dev/null 2>&1; "
			[ -/usr/bin/bzip2 ] && /usr/bin/bzip2 -f $TAR_NAME
		else
			echo "WARN: skip archive the logs since no enough free space on /tmp"
		fi
    fi 

    ##
    # os
    info "Create tar for selected os files ..."
    TAR_NAME="$WORK_DIR/${hostn}_$(get_os_release)_${minute}.tar"    
    if [ "${VERBOSE:0:1}" = "v" ] 
    then
        info "Selected files:"
        cat ${FILE_SELECTED}
    fi                    
    touch $TAR_NAME
    cat ${FILE_SELECTED} | awk -F"#" '{print $1}' |sed '/#/d; /^$/d' | xargs gtar -rvf $TAR_NAME >/dev/null 2>&1; 

    ##
    # Running Status
    info "Create tar for selected the output of the running status ..."
    cd $(dirname $TMP_DIR_STAT)
    if [ "${VERBOSE:0:1}" = "v" ] 
    then
        info "Selected the output of the running status:"
        find -P $(basename $TMP_DIR_STAT) -maxdepth 8 -regextype posix-extended  -type f |sort |sed '/CmdTool.log/d' 
    fi    
    find -P $(basename $TMP_DIR_STAT) -maxdepth 8 -regextype posix-extended  -type f |sed '/CmdTool.log/d'  | xargs gtar -rvf $TAR_NAME >/dev/null 2>&1; 
    [ -f /usr/bin/bzip2 ] && /usr/bin/bzip2 -f $TAR_NAME       
    cd $WORK_DIR

    tar_size=`ls -lh ${TAR_NAME}* |awk '{print $5}' |head -1`
    tar_name=`ls ${TAR_NAME}* |head -1`
    info "archived file: $(hostname):$tar_name (size: $tar_size)"
}

execute_diff() {  
    unset _DIFF_PATH _DIFF_TARGET _DIFF_TARGET_STRING _DIFF_FILTER _DIFF_FILTER1 _DIFF_FILTER_STRING NoteA NoteB
    _DIFF_PATH="$1"
    _DIFF_TARGET="$2"
    _DIFF_FILTER="$3"
    _ONE_FILE_TAG="$4"
    [ -n "$_DIFF_TARGET" ] && _DIFF_TARGET_STRING="|egrep \"$_DIFF_TARGET\""
    [ -n "$_DIFF_FILTER" ] && _DIFF_FILTER1="$(echo "$_DIFF_FILTER"|sed 's/[,; ]/|/g;s/||*/|/g;s/^|//g;s/|$//g')" && _DIFF_FILTER_STRING="|egrep -v \"$_DIFF_FILTER1\""
    # Path:
    [ -z "$_DIFF_PATH" ] && _DIFF_PATH="./a"
    if [ "$_DIFF_PATH" = "./a" ]
    then 
        TARGET_TAG=SOURCE
    else
        TARGET_TAG=TARGET
    fi

    debug "find -L $_DIFF_PATH -type f $_DIFF_TARGET_STRING $_DIFF_FILTER_STRING |sort"
    eval "find -L $_DIFF_PATH -type f $_DIFF_TARGET_STRING $_DIFF_FILTER_STRING" |sort |while read _FILE1
        do
            _FILE2=`echo $_FILE1 |sed 's/\.\/a\//\.\/b\//'`    
            if [ "${VERBOSE:0:1}" = "v" ] 
            then
                _SELECTED_LIST=$_DIFF_PATH/$(basename ${TMP_DIR_STAT})/$(basename ${FILE_SELECTED})    
                FILE_NOTES=$(grep -w "$(echo $_FILE1| sed 's|\.\/a\/|\/|g; s|\.\/b\/|\/|g')" $_SELECTED_LIST | awk -F"#" '{print "#"$2}' |head -1)
            fi
            
            if [ ! -f $_FILE2 ]; then
                if [ "${VERBOSE:0:2}" != "vv" ] 
                then
                    echo "FILE ONLY IN $TARGET_TAG: $_FILE1 $FILE_NOTES"
                else
                    echo ""
                    echo "---------------------------------------------------------------------------"
                    echo "FILE ONLY IN $TARGET_TAG: $_FILE1 $FILE_NOTES"
                    cat $_FILE1     
                    echo ""
                fi
            else
                [ "$_ONE_FILE_TAG" != "ISOLATED" ] && \
                if [ "` diff $_FILE1 $_FILE2 2>&1 |sed '/zzz \*\*\*/d;/^[0-9]/d' |wc -l`" -ne "0" ]; 
                then
                    # Skip the diff for known_hosts, .log, .bak, .old, orig, .*-, tar.bz2
                    if [ "$DIFF_TREE" = "DIFF_TREE" ]; then
                        _FILTER="known_hosts|\.log$|oraem.*log|oraem.*emd|00\.dat$|\.bak$|\.old$|backup$|orig$|\-$|_key|shadow$|tar\.bz2|bash_history"
                    else
                        _FILTER="known_hosts|\.log$|oraem.*log|oraem.*emd|00\.dat$|\.bak$|\.old$|backup$|orig$|\-$|_key|shadow$|tar\.bz2|bash_history|filesystem_permission_symbolic|filesystem_permission_tree"
                    fi
                    [ "$ENABLE_SORT" = "ENABLE_SORT" ] && _FILTER="$_FILTER|packages_rpm-verify.out" 
                    
                    # echo ${_FILE1} |egrep -q "known_hosts|\.log$|oraem.*log|oraem.*emd|00\.dat$|\.bak$|\.old$|backup$|orig$|\-$|_key|shadow|tar\.bz2"
                    echo ${_FILE1} |egrep -q "$_FILTER"
                    RC=$?                     
                    if [ $RC = 0 ]; then
                        printf "SKIP: "
                        printf "diff $_FILE1 $_FILE2 $NoteB"
                        printf "\n"
                        
                    else
                        echo ""
                        echo "---------------------------------------------------------------------------"
                        if [ "$ENABLE_SORT" = "ENABLE_SORT" ] \
                            &&  [[ "$_FILE1" != *"rc.local" ]] \
                            &&  [[ "$_FILE1" != *"hw_lspci.out" ]]  \
                            &&  [[ "$_FILE1" != *"grub.conf" ]] ;
                        then 
                            echo "diff --ignore-all-space $_FILE1 $_FILE2 (Sorted) $NoteB"
                            sort -b -f -i -o $_FILE1 $_FILE1
                            sort -b -f -i -o $_FILE2 $_FILE2
                            sed -i '/^#/d;/^ *#/d;/^$/d' $_FILE1
                            sed -i '/^#/d;/^ *#/d;/^$/d' $_FILE2
                            diff --ignore-all-space $_FILE1 $_FILE2
                        else
                            echo "diff -Npru --ignore-all-space $_FILE1 $_FILE2 $NoteB"
                            #diff -Npru $_FILE1 $_FILE2
                            diff -Npru --ignore-all-space $_FILE1 $_FILE2    
                        fi
                        echo ""
                    fi
                else
                    if [ "${VERBOSE:0:1}" = "v" ] 
                    then
                        echo "---------------------------------------------------------------------------"
                        echo "SAME: diff -Npru $_FILE1 $_FILE2 $NoteB"
                    fi
                fi
            fi 
        done 
}

function execute_diff_tar (){
    TAR_FILE1=$1
    TAR_FILE2=$2
    cd $WORK_DIR
    [ -n $TAR_FILE1 ] || error "Usage $0 -d os_config_old.tar.bz2 os_config_new.tar.bz2"
    [ -n $TAR_FILE2 ] || error "Usage $0 -d os_config_old.tar.bz2 os_config_new.tar.bz2"
    [ -f $TAR_FILE1 ] || error "can not find file $TAR_FILE1"
    [ -f $TAR_FILE2 ] || error "can not find file $TAR_FILE2"
    
    info "uncompress archive files with gtar ..."
    # Remvoe old files:
    dir_a=$(basename $TAR_FILE1 |sed 's/.tar.bz2$//g; s/.tar$//g; ')
    dir_b=$(basename $TAR_FILE2 |sed 's/.tar.bz2$//g; s/.tar$//g; ')
    if [ -L a ] || [ -f a ] || [ -d a ]; then
        rm -rf a
    fi
    if [ -L b ] || [ -f b ] || [ -d d ]; then
        rm -rf b
    fi
    [ -d "$dir_a" ] && rm -rf $dir_a
    [ -d "$dir_b" ] && rm -rf $dir_b

    # untar
    mkdir -p $dir_a
    mkdir -p $dir_b    
    
    if `file $TAR_FILE1 |awk -F: '{print $2}' |grep -q bzip2`; then gtar -jxvf $TAR_FILE1 -C $dir_a >/dev/null 2>&1; else gtar -xvf $TAR_FILE1 -C $dir_a >/dev/null 2>&1;  fi
    if `file $TAR_FILE2 |awk -F: '{print $2}' |grep -q bzip2`; then gtar -jxvf $TAR_FILE2 -C $dir_b >/dev/null 2>&1; else gtar -xvf $TAR_FILE2 -C $dir_b >/dev/null 2>&1;  fi

    ln -s $dir_a a
    ln -s $dir_b b
    # ListA=./a/$(basename ${TMP_DIR_STAT})/$(basename ${FILE_SELECTED})
    # ListB=./b/$(basename ${TMP_DIR_STAT})/$(basename ${FILE_SELECTED})
   
    if :
    then
        echo "#  Generated by conf-archive.sh at `hostname --fqdn`:$PROG_HOME/$PROG" 
        echo "#  $(grep "^#.*Revision" $PROG_HOME/$PROG |awk -F$ '{print $TAR_FILE2}')"
        echo "#  "
        echo "#  Date: `TZ=US/Pacific date` " 
        echo "#  Arguments: $ARGUMENTS" 
        echo "#  Source: `find -L ./a -type f |wc -l` files ($TAR_FILE1)" 
        echo "#  Target: `find -L ./b -type f |wc -l` files ($TAR_FILE2)" 
        echo ""  
        echo "#  Note: As design, the program don't diff the files with '-' as name suffix. e.g. filesystem_permission_tree-mtime.out-"
        echo "#        Please use '-k' to keep the uncompressed files and run diff manually for files with '-' as name suffix"
        echo "#  Note: Only when the '-v' flag is used, the report will list the Source and Target file name which are same."
        echo "#  Note: If the '--sort' tag is enabled, the line number report by diff is not the original file's line number."
        echo "# "          
    fi > ${DIFF_REP}
 
    ## Step 1 - os, kernel and package info
    info "Start the diff for os, kernel and package info ..."
    DIFF_TARGET_LIST="release$ release.out$ sysctl.conf limits.conf rpm-name lsmod sysctl.out"    
    for i in $DIFF_TARGET_LIST
    do
        DIFF_PATH="./a"
        DIFF_TARGET="$i"
        DIFF_FILTER=""
        execute_diff "$DIFF_PATH" "$DIFF_TARGET" "$DIFF_FILTER"
    done

    ## Step 2 - /root/.bashrc /root/.bash_logout /root/.bash_profile 
    info "Start the diff for .bashrc, .bash_logout and .bash_profile ..."
    DIFF_TARGET_LIST="/root/.bashrc /root/.bash_logout /root/.bash_profile /home/oracle/.bashrc /home/oracle/.bash_logout /home/oracle/.bash_profile "    
    for i in $DIFF_TARGET_LIST
    do
        DIFF_PATH="./a"
        DIFF_TARGET="$i"
        DIFF_FILTER=""
        execute_diff "$DIFF_PATH" "$DIFF_TARGET" "$DIFF_FILTER"
    done

    ## Step 3 - Other files
    info "Start the diff for other files ..."
    DIFF_PATH="./a"
    DIFF_TARGET=""
    DIFF_FILTER="release$ release.out$ sysctl.conf limits.conf rpm-name lsmod sysctl.out filesystem_permission tar.bz2$ /root/.bashrc /root/.bash_logout /root/.bash_profile /home/oracle/.bashrc /home/oracle/.bash_logout /home/oracle/.bash_profile"
    execute_diff "$DIFF_PATH" "$DIFF_TARGET" "$DIFF_FILTER"

    # Step 3 - filesystem_permission_tree, and tar.bz2$
    info "Start the diff for filesystem_permission* ..."
    DIFF_TARGET_LIST="filesystem_permission_root filesystem_permission_wellknown filesystem_permission_dir filesystem_permission_symbolic filesystem_permission_tree tar.bz2$"    
    
    for i in $DIFF_TARGET_LIST
    do
        DIFF_PATH="./a"
        DIFF_TARGET="$i"
        DIFF_FILTER=""
        execute_diff "$DIFF_PATH" "$DIFF_TARGET" "$DIFF_FILTER"
    done

    # Step 4 Files not in ./a
    info "Start the find the files not in ./a but in ./b ..."
    DIFF_PATH="./b"
    DIFF_TARGET=""
    DIFF_FILTER=""
    execute_diff "$DIFF_PATH" "$DIFF_TARGET" "$DIFF_FILTER" "ISOLATED"
    
    if [ "$KEEP_TEMP_ENABLE" = "KEEP_TEMP_ENABLE" ]
    then
    :
    else
        # Remove the uncompressed files
        info "Remove the uncompressed files ..."
        if [ -L a ] || [ -f a ] || [ -d a ]; then
            rm -rf a
        fi
        if [ -L b ] || [ -f b ] || [ -d d ]; then
            rm -rf b
        fi
        [ -d "$dir_a" ] && rm -rf $dir_a
        [ -d "$dir_b" ] && rm -rf $dir_b
    fi
}

function rotating_file() {
    local FILENAME="$1"  
    if [ -f "$FILENAME" ]; 
    then  
        # local mtime=`stat -c %y "${FILENAME}" | awk -F. '{print $1}'|sed 's/[ :.-]//g'`
        mtime=$(find ${FILENAME} -printf "%TY.%Tm.%Td.%TH%TM%TS")
    	mv -f "${FILENAME}" "${FILENAME}.bak.${mtime}.old"; 
        warn "Rename old file ${FILENAME} to ${FILENAME}.bak.${mtime}.old"; 
    fi  
}

get_os_release() {
    local T=$typeset
    local _PREFIX=""
    
    if  [ -f /usr/local/bin/version ] && /usr/local/bin/version |grep -q ^SUN ; then
        _PREFIX=IBSW;
    elif [ -f /usr/lib/init-exalogic-node/.image_id ]; then
        _PREFIX=`cat /usr/lib/init-exalogic-node/.image_id |grep "exalogic_version=" |sed -n "s/.*=/Exalogic/g;s/['.]//g;/^Exalogic/p"`
    elif `rpm -q bda >/dev/null 2>&1`; then
        _PREFIX=`rpm -q bda |awk -F"-" '{print $1,$2}' |sed 's/[ .]//g'`
    elif [ -f /etc/ap-release ]; then
        _PREFIX=`cat /etc/ap-release |sed 's/ //g'`
        [ -z "_PREFIX" ] && _PREFIX=APOL
    elif [ -f /etc/OSCC-Release ]; then
        _PREFIX=`cat /etc/OSCC-Release | grep OSCC| sed 's/ /_/g'`
        [ -z "_PREFIX" ] && _PREFIX=OSCC
    fi
    

    if  [ -f /usr/local/bin/version ] && /usr/local/bin/version |grep -q ^SUN ; then
        T=IBSW;
        elif [ -f /etc/ovs-release ]; then
            T=`cat /etc/ovs-release |head -1 | sed 's/.*release /ovs/g'`
        elif `grep -q "Oracle VM server" /etc/enterprise-release 2>/dev/null`; then
            T=`cat /etc/enterprise-release |head -1 | sed 's/.*release /ovs/g'`
        elif [ -f /etc/oracle-release ]; then
            T=`cat /etc/oracle-release |head -1 | sed 's/.*release /ol/g'`
        elif [ -f /etc/enterprise-release ]; then
            T=`cat /etc/enterprise-release |head -1 | sed 's/.*release /el/g'`
        elif [ -f /etc/redhat-release ]; then
            T=`cat /etc/redhat-release | head -1 | sed 's/.*release /el/g'`
    fi
    
    [ -f /etc/ovs-info ] && ovs_build=$(grep "build:" /etc/ovs-info |awk '{print "_b"$2}')
   
    T="$T$ovs_build"    
    if [ -n "$_PREFIX" ]
    then
        printf "%s_%s" "$T" "$_PREFIX" |awk '{printf $1}'
    else
        printf "%s"  "$T" |awk '{printf $1}'
    fi
}


filesystem_tree () {
    ## print the root file system
    info "Create the root file system permission list ..."
    eval "find -P / -maxdepth 1 -regextype posix-extended -printf \"%p (%y, %m, %U, %G, %s)\n\" 2>/dev/null" |sort >filesystem_permission_root.out

    
    if [ -n "$NOPERM" ]; then
        info "Skip to scan the full file tree with the mtime"
    else
        ## print the full directory without the mtime (type d)
        info "Create the directory permission list ..."
        eval "find -P / -maxdepth 6 -regextype posix-extended  -type d $regex_prune -prune -o -type d $regex_sys -printf \"%p (%y, %m, %U, %G, %s)\n\" 2>/dev/null" > filesystem_permission_directory.out
        sort filesystem_permission_directory.out -o filesystem_permission_directory.out
        #    
        ## print the symbolic link (type l)
        info "Create the symbolic link list ..."
        eval "find -P / -maxdepth 6 -regextype posix-extended  -type d $regex_prune -prune -o -type l $regex_sys -printf \"%p (%y, %m, %U, %G, %s)\n\" 2>/dev/null" > filesystem_permission_symbolic_link.out
        sort filesystem_permission_symbolic_link.out -o filesystem_permission_symbolic_link.out
        #
        
        ## print the full tree without the mtime (type f)
        info "Create the file permission list list (without mtime) ..."
        eval "find -P / -maxdepth 6 -regextype posix-extended  -type d $regex_prune -prune -o -type f $regex_sys $regex_var $regex_usr $regex_doc $regex_bak  -printf \"%p (%y, %m, %U, %G, %s)\n\" 2>/dev/null" > filesystem_permission_tree.out
        sort filesystem_permission_tree.out -o filesystem_permission_tree.out
        #
        
        ## print the full tree with the mtime (type f)
        info "Create the file permission list list (with mtime) ..."
        eval "find -P / -maxdepth 6 -regextype posix-extended  -type d $regex_prune -prune -o -type f $regex_sys $regex_var $regex_usr $regex_doc $regex_bak  -printf \"%p (%y, %m, %U, %G, %s, %TY-%Tm-%Td %TH:%TM:%TS)\n\" 2>/dev/null" > filesystem_permission_tree-mtime.out-
        sort filesystem_permission_tree-mtime.out- -o filesystem_permission_tree-mtime.out-
    fi
}


ethtool_statistics () {

    # Check LSO/TSO -- if we disabled LSO/TSO everywhere, we were able to get the same performance on switched and routed paths for NFS.
    info "Get network adapter's LSO/TSO status ..." 
    info "Check network LSO/TSO"
    for nic in $NETDEVIC;  
    do 
        if :
        then
            echo "=== ethtool -k $nic ==="; 
            ethtool -k $nic; 
        fi > network_show_offload_$nic.out
    # done | grep -Ee "==|tcp.*offload|generic.*offload|generic.*offload|large.*offload" |egrep ":|=" 2>&1 > network_LSO_TSO.out
    done

    # Show adapter statistics  
    info "Get network adapter statistics ..."    
    for DEVNAME in $NETDEVIC;
    do
        ethtool -S $DEVNAME >>ethtool_${DEVNAME}.out.1
    done
    sleep 3

    for DEVNAME in $NETDEVIC;
    do
        ethtool -S $DEVNAME >>ethtool_${DEVNAME}.out.2
        echo "# Show adapter statistics: ethtool -S $DEVNAME, 3 sec"
        diff -Npru ethtool_${DEVNAME}.out.1 ethtool_${DEVNAME}.out.2 
        rm -f ethtool_${DEVNAME}.out.1 ethtool_${DEVNAME}.out.2 
    done > network_adapter_stat.out-

}


########################################
#
# Main
#
# obtain an exclusive lock with flock to avoid running multiple instances of script.
exlock_now || error "Aborted. Another one instance of the script is running. Exit 1."

if [ -z "$1" ]; 
    then usage; 
fi

## Parse the arguments:

cd ${PROG_HOME}
ARGUMENTS="$@"
unset OPS
while [ $# -gt 0 ]
do
  case "$1" in	
    -d|--diff)     OPS="DIFF"; TAR1="$2"; TAR2="$3";  [ "${2:0:1}" = "-" ] && usage; [ "${3:0:1}" = "-" ] && usage;  shift 2;;     
    -a|--archive)  OPS="ARCHIVE";                                                shift 0;; 
    -r|--report)   OPS="REPORT";    TAR1="$2"; [ "${2:0:1}" = "-" ] && usage;    shift;;             
    -l|--log)      LOG_ENABLE="LOG_ENABLE";                                      shift 0;; 
    -f|--force_archive) FORCE_ARCHIVE_ENABLE="FORCE_ARCHIVE_ENABLE";             shift 0;; 
    -k|--keep-temp-files)  KEEP_TEMP_ENABLE="KEEP_TEMP_ENABLE";                  shift 0;; 
    --diff-file-tree)   DIFF_TREE="DIFF_TREE";                                   shift 0;; 
    --sort)   ENABLE_SORT="ENABLE_SORT";                                         shift 0;; 
    --noperm) NOPERM=NOPERM;                                                     shift 0;; 
    -v*)           VERBOSE="$(echo "${VERBOSE}$1" |sed 's/-//g')";               shift 0;; 
    --debug)       DEBUG="ON";                                                   shift 0;; 
    *) usage;;
  esac
  shift
done

########################################
free_ram=$(free -m | awk 'FNR == 2 {print $4}')
if [ -z "$free_ram" ]
then
	echo "WARN: Failed to get free ram. "
	free_ram_tag=failed
elif [ "$free_ram" -le 1700 ]
then
	echo "WARN: No enough free ram. ($free_ram < 1700M) "
	free_ram_tag=failed
fi 

########################################
free_tmpspace=$(df -kP /tmp |awk '{print $4}' |tail -1)
if [ -z "$free_tmpspace" ]
then
	echo "WARN: Failed to get size of free space for /tmp"
	free_tmpspace_tag=failed
elif [ "$free_tmpspace" -le 2 ]
then
	echo "WARN: No enough free space on /tmp. ($free_tmpspace < 2M) "
	free_tmpspace_tag=failed
fi 
	


	
########################################
NETDEVIC=$(
    if [ -f /sbin/ifconfig ]; 
    then 
        ifconfig |grep HWaddr |awk '{print $1}'; 
    else 
        ip add show |grep "^[0-9]" |awk -F"[ |:|@]" '{print $3}' ; 
    fi | egrep -wv "lo|usb0" |sed '/vif[0-9]*\.[0-9]*/d;/tap[0-9]*\.[0-9]*/d' |sed 's/:.*//g;s/@.*//g;s/\..*//g' |sort |uniq )

WELL_KNOWN_FILES=$(echo "$WELL_KNOWN_FILES"| sed 's/# */#/g' |tr ' ' '\n' |sed '/^#/d')

if :
then
     echo -e "zzz *** $(TimeFormat) - Start the process ... \n"
     info "Log file: $TMP_FILE_REP"
     case "$OPS" in	
        ARCHIVE)
            [ -d ${TMP_DIR_STAT} ] && rotating_file ${TMP_DIR_STAT}
            info "mkdir -p ${TMP_DIR_STAT}; cd ${TMP_DIR_STAT}"
            mkdir -p ${TMP_DIR_STAT}; cd ${TMP_DIR_STAT}   
			
			if [[ "$free_ram_tag" != failed ]]
			then
				generate_rpm_config_files_list    
			else
				echo "WARN: Skip generate_rpm_config_files_list  (not enough free ram for this action) "
			fi			
            generate_nonrpm_text_files_list
            generate_wellknown_files_list
            execute_running_stat
            # for ibd in `ls ${TMP_DIR_STAT}/ibdiagnet*`; do 
            # echo $ibd |tee -a ${FILE_SELECTED}.ibdiagnet
            # done
            ethtool_statistics # report_file: network_adapter_stat.out
            filesystem_tree
            generate_gtar_archive
            ;;    
        DIFF)
             [ -z "$TAR2" ] && usage             
             rotating_file ${DIFF_REP}
             debug "execute_diff_tar $TAR1 $TAR2"
             execute_diff_tar "$TAR1" "$TAR2"  | tee -a  ${DIFF_REP}
             info "Report file: ${DIFF_REP}"
            ;;
        REPORT)
            :
            echo "The -r|--report flag is a to-do item. exit"
            # execute_untar_and_report $TAR1 |tee -a tee.out
            ;;
    esac
fi 2>&1 | tee -a $TMP_FILE_REP

exit

#################################################
# Check List for execute_running_stat

# Please don't remove the list below:

#---------BEGIN CN CHECKLIST---------
# Format: 
#        cmd # report_file: outpout-file-name # Notes
# Note: if the outpout-file-name end with ".out-", the scirpt will skip it for diff ops.

## RPM/EPM PACKAGES
rpm -qa --qf '%{n}-%{v}-%{r}.%{arch}.rpm\\n' |sort # report_file: packages_rpm-version.txt
rpm -qa --qf '%{n}.%{arch}\\n' |sort               # report_file: packages_rpm-name.txt
package-update -list                               # report_file: packages_epm.out


# kernel parameters at runtime
cat  /proc/modules |sort | awk '{print $1,$3,$4}' # report_file: os_modules_lsmod_without-size.out
lsmod |sort                                 # report_file: os_modules_lsmod.out-
depmod -n                                   # report_file: os_modules_lsmod_depmod.out-
sysctl -a |sort                             # report_file: os_kernel_sysctl.out

## Ksplice Patch
#  ksplice-view lists the identification tags of all of the Ksplice updates that are currently present in the running kernel.
/usr/lib/uptrack/ksplice-view    # report_file: os_ksplice_updates.out
uname -r                         # report_file: os_kernel-release.out
uptrack-uname -r                 # report_file: os_ksplice_effective-kernel-release.out
dmesg | grep "^ksplice"          # report_file: os_ksplice_dmesg.out
# Other System Status
hostname                         # report_file: os_hostname.out
uptime                           # report_file: os_date_uptime.out-
last reboot                      # report_file: os_date_last-reboot.out-
date                             # report_file: os_date_date.out-
ntpq -np                         # report_file: os_date_ntpq.out-
ps -ef                           # report_file: os_processes_ps.out-
pstree -A -a -h -p -u            # report_file: os_processes_pstree.out-
grep oracle /etc/shadow          # report_file: shadow_oracle.out
grep root /etc/shadow            # report_file: shadow_root.out

## FILESYSTEM
# MegaCli
raidconfig list all             # report_file: filesystem_raidconfig_list_all.out
/opt/MegaRAID/MegaCli/MegaCli64 -adpallinfo -a0 |grep Version                           # report_file: filesystem_megacli_adpallinfo.out
/opt/MegaRAID/MegaCli/MegaCli64 -Pdlist -aAll | egrep "Slot|Firmware|Inquiry"        # report_file: filesystem_megacli_pdlist.out
/opt/MegaRAID/MegaCli/MegaCli64 -LdInfo -lAll -aAll | egrep "Size|State|Number"      # report_file: filesystem_megacli_ldinfo.out
df -hP                          # report_file: filesystem_partition_diskspace.out
fdisk -l                        # report_file: filesystem_partition.out
mounted.ocfs2 -d                # report_file: filesystem_ocfs2.out-
mdadm --detail --scan --verbose # report_file: filesystem_raid_mdadm.out
pvdisplay                       # report_file: filesystem_lvm_pvdisplay.out
vgdisplay                       # report_file: filesystem_lvm_vgdisplay.out
lvdisplay                       # report_file: filesystem_lvm_lvdisplay.out
lvscan                          # report_file: filesystem_lvm_lvscan.out
ddcli -listall                  # report_file: filesystem_flash_accelerator.out # verify that Flash which installed in Exalytics and some other engineering system

    
## OFED
ibstat              # report_file: ib_ibstat.out
mlx4_vnic_info -i   # report_file: ib_vnic.out
ibnetdiscover       # report_file: ib_ibnetdiscover.out-
ibdiagnet -r        # report_file: ib_ibdiagnet.out-
ofed_info           # report_file: ib_ofed.out
    
# Service list
chkconfig --list |sort # report_file: service_chkconfig.out
service --status-all   # report_file: service_status-all.out

systemctl --no-page list-unit-files # report_file: service_systemctl-list-unit-files.out
systemctl --no-page list-units      # report_file: service_systemctl-list-units.out
getenforce                          # report_file: service_getenforce.out
   
# network
ip link # report_file: network_ip-link.out
ip add  # report_file: network_ip-add.out
ip route show table all                # report_file: network_route_table.out-
ip rule show                           # report_file: network_rule.out-
ip route get to 140.85.170.202         # report_file: network_route-to-netdump-el.out-
ifconfig | sed '/ bytes/d;/ packets/d' # report_file: network_ifconfig.out-
iptables -nL --line-numbers            # report_file: network_iptables
brctl show                             # report_file: network_brctl_show.out

## HW
dmidecode                           # report_file: hw_dmidecode.out-
lspci -tv                           # report_file: hw_lspci.out-
kudzu -p -c network                 # report_file: hw_kudzu_network.out
# ILOM
ipmitool sunoem version                                                                             # report_file: hw_ilom_version.out
ipmitool sunoem cli 'show /SP system_identifier'                                                    # report_file: hw_ilom_system_identifier.out
ipmitool sunoem cli 'show /SP/network' | egrep -w "managementport|ipaddress|ipgateway|ipnetmask"    # report_file: hw_ilom_network.out-
ipmitool sunoem cli 'show faulty' |grep "fault\\."                                                   # report_file: hw_ilom_faulty.out-
ipmitool sunoem cli 'show /SP/alertmgmt/rules/ -level all' | egrep -vw 'disable' |egrep "rules|destination.*[123456789]|level"  # report_file: hw_ilom_asr.out
ipmitool sunoem cli 'show /SP/users/ -level all' |grep "keys/\\|embedded_comment.*@\\|algorithm.*ssh\\|fingerprint.*:.*:"  # report_file: hw_ilom_ssh_rsa-auth.out
ipmitool sdr type Temperature | grep -v Disabled | grep "|T_AMB"                                    # report_file: hw_ilom_temperature.out-
hwmgmtcli list all -d    # report_file: hw_ilom_hwmgmtcli.out

# biosconfig, /usr/sbin/ubiosconfig
# Know issue: Run biosconfig on OMMS 3.2.9 on X3-2 can cause server reboot.
ubiosconfig export all -y -U=root || biosconfig -get_bios_settings              # report_file: hw_ubiosconfig.out
# /usr/bin/biosconfig -get_bios_settings |sed -n '/Intel_R__C_STATE_tech/,/\\/Intel_R__C_STATE_tech/p' 
# /usr/bin/biosconfig -get_bios_settings |sed -n '/SR_IOV_Supported/,/\\/SR_IOV_Supported/p' 
# /usr/bin/biosconfig -get_bios_settings |sed -n '/Maximum_Payload_Size/,/\\/Maximum_Payload_Size/p' || biosconfig

# Exalogic status
imageinfo                                                                            # report_file: system_exa_imageinfo.out
imagehistory                                                                         # report_file: system_exa_imagehistory.out
#/opt/exalogic.tools/tools/CheckHWnFWProfile |egrep "Error|ERROR|FAILURE|unsupported" # report_file: system_exa_el_checkhwnfwprofile.out
/opt/exalogic.tools/tools/CheckHWnFWProfile  # report_file: system_exa_el_checkhwnfwprofile.out
/opt/exalogic.tools/tools/CheckSWProfile     # report_file: system_exa_el_checkswprofile.out


## VM List
xm list                 # report_file: ovs.vm_list.out
xm info                 # report_file: ovs.xm_info.out
xm dmesg                # report_file: ovs.xm_dmesg.out-
xenstore-ls             # report_file: ovs.xenstore_ls.out
xm info -n              # report_file: ovs.xm_info_n.out

## container
docker images -a       # report_file: docker_images.out
docker ps -a           # report_file: docker_ps.out
lxc-ls -la             # report_file: lxc-ls.out

## ocsf2
/etc/init.d/o2cb status   # report_file: ocfs2.o2cb_status.out
# find /sys/kernel/config
# find /dlm

dmsetup ls  # report_file: dmsetup_ls.out

#---------END CN CHECKLIST---------

# End
# Unpack os_config_*.tar.bz2 into a directory: cd ${TMP_DIR_STAT}/os_timestamp/; gtar -jxvf os_config_*.tar.bz2
