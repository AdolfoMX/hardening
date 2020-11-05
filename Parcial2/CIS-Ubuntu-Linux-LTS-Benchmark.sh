#!/bin/sh
#############################################################################################################################
#CIS Ubuntu Linux 20.04 LTS Benchmark v1.0.0                                                                                #
#############################################################################################################################
#Integrantes del equipo:                                                                                                    #
#-> Oscar Uriel Chalé                                                                                                       #
#-> Adolfo Tun Dzul                                                                                                         #
#############################################################################################################################
#1 Initial Setup                                                    #
#####################################################################
###############################
#1.1 Filesystem Configuration #
###############################
#1.1.1 Disable unused filesystems
#1.1.1.1 Ensure mounting of cramfs filesystems is disabled (Automated)
echo "install cramfs /bin/true" > /etc/modprobe.d/cramfs.conf
#1.1.1.2 Ensure mounting of freevxfs filesystems is disable (Automated)
echo "install freevxfs /bin/true" > /etc/modprobe.d/freevxfs.conf
#1.1.1.3 Ensure mounting of iffs2 filesystems is disabled (Automated)
echo "install jffs2 /bin/true" > /etc/modprobe.d/jffs2.conf
#1.1.1.4 Ensure mounting of hfs filesystems is disabled (Automated)
echo "install hfs /bin/true" > /etc/modprobe.d/hfs.conf
#1.1.1.5 Ensure mounting of hfsplus filesystems is disabled (Automated)
echo "install hfsplus /bin/true" > /etc/modprobe.d/hfsplus.conf
#1.1.1.6 Ensure mounting of udf filesystems is disabled (Automated)
echo "install udf /bin/true" > /etc/modprobe.d/udf.conf
#1.1.1.7 Ensure mounting of FAT filesystems is limited (Manual)
echo "install vfat /bin/true" > /etc/modprobe.d/vfat.conf
#1.1.2 Ensure /tmp is configured (Automated)
#1.1.3 Ensure nodev option set on /tmp partition (Automated)
#1.1.4 Ensure nosuid option set on /tmp partition (Automated)
#1.1.5 Ensure noexec option set on /tmp partition (Automated)
cp -v /usr/share/systemd/tmp.mount /etc/systemd/system/
systemctl daemon-reload | systemctl --now enable tmp.mount
echo "tmpfs           /tmp            tmpfs    defaults,rw,nosuid,nodev,noexec,relatime,rw,nosuid,nodev,noexec,relatime  0  0" >> /etc/fstab
#1.1.6 Ensure /dev/shm is configured (Automated)
#1.1.7 Ensure nodev option set on /dev/shm partition (Automated)
#1.1.8 Ensure nosuid option set on /dev/shm/ partition (Automated)
#1.1.9 Ensure noexec option set on /dev/shm partition (Automated)
echo "tmpfs           /dev/shm            tmpfs    defaults,noexec,nodev,nosuid  0  0" >> /etc/fstab
#1.1.10 Ensure separate partition exists for /var (Automated)
#1.1.11 Ensure separate partition exists for /var/tmp (Automated)
#1.1.12 Ensure nodev option set on /var/tmp/ partition (Automated)
#1.1.13 Ensure nosuid option set on /var/tmp/partition (Automated)
#1.1.14 Ensure noexec option set on /var/tmp partition (AUtomated)
mount -t ext4 /dev/sda3 /var/tmp
echo "ext4           /var/tmp            ext4   defaults,nosuid,nodev,noexec  0  0" >> /etc/fstab
#1.1.15 Ensure separate partition exists for /var/log (Automated)
#1.1.16 Ensure separate partition exists for /var/log/audit (Automated)
#1.1.17 Ensure separate partition exists for /home (Automated)
#1.1.18 Ensure nodev option set on /home partition (Automated)
echo "ext4           /home            ext4   defaults,nodev  0  0" >> /etc/fstab
#1.1.19 Ensure nodev option set on removable media partitions (Manual)
#1.1.20 Ensure nosuid option set on removable media partitions (Manual)
#1.1.21 Ensure noexec option set on removable media partitions (Manual)
#1.1.22 Ensure sticky bit is set on all world-writable directories (Automated)
df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null | xargs -I '{}' chmod a+t '{}'
#1.1.23 Disable Automouting (Automated)
apt purge autofs#1.1.24 Disable USB Storage (Automated)
modprobe -n -v usb-storage
echo "install usb-storage /bin/true" >> /etc/modprobe.d/usb_storage.fconf
#####################################################################
###############################
#1.2 Configure Software Update#
###############################
#1.2.1 Ensure package manager repositories are configured (Manual)
apt-cache policy
#1.2.2 Ensure GPG keys are configured (Manual)
apt-key list
#####################################################################
######################
#1.3 Configure sudo  #
######################
#1.3.1 Ensure sudo is installed (Automated)
dpkg -s sudo-ldap
apt install sudo
#1.3.2 Ensure sudo commands use pty (Automated)
grep -Ei '^\s*Defaults\s+([^#]+,\s*)?use_pty(,\s+\S+\s*)*(\s+#.*)?$'
echo "Defaults use_pty" >> /etc/sudoers
#1.3.3 Ensure sudo log file exists (Automated)
grep -Ei '^\s*Defaults\s+logfile=\S+' /etc/sudoers /etc/sudoers.d/*
echo "Defaults logfile=" /var/log/sudo.log"" >> /etc/sudoers
#####################################################################
#####################################
#1.4 Filesystem Integrity Checking  #
#####################################
#1.4.1 Ensure AIDE is installed (Automated)
dpkg -s aide | grep 'Status: install ok installed'
apt install aide-common
aideinit
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
#1.4.2 Ensure filesystem integrity is regularly checked (Automated)
crontab -u root -l | grep aide
find /etc/cron.* /etc/crontab -name 'aide' -type f
crontan -u root -e
#Add the followin line to the crontab:
0 5 * * * /usr/bin/aide.wrapper --config /etc/aide/aide.conf --check
#####################################################################
############################
#1.5 Secure Boot Settings  #
############################
#1.5.1 Ensure bootloader password is set (Automated)
grep "^set superusers" /boot/grub/grub.cfg
#create an encrypted password
grub-mkpasswd-pbkdf2
update-grub
#1.5.2 Ensure permissions on bootloader config are configured (Automated)
stat /boot/grub/grub.cfg
chown root:root /boot/grub/grub.cfg
chmod og-rwx /boot/grub/grub.cfg
#1.5.3 Ensure authentication required for single user mode (Automated)
grep ^root:[*\!]: /etc/shadow
password root
#####################################################################
####################################
#1.6 Additional Process Hardening  #
####################################
#1.6.1 Ensure XD/NX support is enabled (Automated)
journalctl | grep 'protection: active'
#1.6.2 Ensure address space layout randomization (ASLR) is enabled (Automated)
# journalctl | grep 'protection: active'
[[ -n $(grep noexec[0-9]*=off /proc/cmdline) || -z $(grep -E -i ' (pae|nx)
' /proc/cpuinfo) || -n $(grep '\sNX\s.*\sprotection:\s' /var/log/dmesg | grep
-v active) ]] && echo "NX Protection is not active"
#1.6.2 Ensure address space layout randomization (ASLR) is enabled
(Automated)
Run the following commands and verify output matches:
# sysctl kernel.randomize_va_space
kernel.randomize_va_space = 2
# grep "kernel\.randomize_va_space" /etc/sysctl.conf /etc/sysctl.d/*
kernel.randomize_va_space = 2
#Kernel parameter:
kernel.randomize_va_space = 2 |  sysctl -w kernel.randomize_va_space=2
#1.6.3 Ensure prelink is disabled (Automated)
#Verify prelink is not installed:
 dpkg -s prelink
Remediation:
# prelink -ua
#(Uninstall prelink using the appropriate package manager or manual installation)
 apt purge prelink
#1.6.4 Ensure core dumps are restricted (Automated)
#Run the following commands and verify output matches:
 grep -E '^(\*|\s).*hard.*core.*(\s+#.*)?$' /etc/security/limits.conf
/etc/security/limits.d/*
* hard core 0
 sysctl fs.suid_dumpable
fs.suid_dumpable = 0
 grep "fs.suid_dumpable" /etc/sysctl.conf /etc/sysctl.d/*
fs.suid_dumpable = 0
#check if systemd-coredump is installed:
systemctl is-enabled coredump.service
# to set the active kernel parameter:
 sysctl -w fs.suid_dumpable=0
##If systemd-coredump is installed:
edit /etc/systemd/coredump.conf and add/modify the following lines:
Storage=none
ProcessSizeMax=0
#RUN
systemctl daemon-reload
#####################################################################
##########################################
1.7 Mandatory Access Control             #
#########################################
1.7.1 Configure AppArmor            #
#####################################
1.7.1.1 Ensure AppArmor is installed (Automated)
#Verify that AppArmor is installed:
# dpkg -s apparmor
#Install AppArmor.
 apt install apparmor
#1.7.1.2 Ensure AppArmor is enabled in the bootloader configuration
(Automated)
#Run the following commands to verify that all linux lines have the apparmor=1 and
security=apparmor parameters set:
  grep "^\s*linux" /boot/grub/grub.cfg | grep -v "apparmor=1"
  grep "^\s*linux" /boot/grub/grub.cfg | grep -v "security=apparmor"
return:nothing
#Edit /etc/default/grub and add the appermor=1 and security=apparmor parameters to
# the GRUB_CMDLINE_LINUX= line

# GRUB_CMDLINE_LINUX="apparmor=1 security=apparmor"
# Run the following command to update the grub2 configuration:
# update-grub
#1.7.1.3 Ensure all AppArmor Profiles are in enforce or complain mode
(Automated)
#Verify that profiles are loaded, and are in either enforce or
complain mode:
  apparmor_status | grep profiles
#Verify no processes are unconfined
  apparmor_status | grep processes
#Set all profiles to enforce mode:
  aa-enforce /etc/apparmor.d/*
  aa-complain /etc/apparmor.d/*
#1.7.1.4 Ensure all AppArmor Profiles are enforcing (Automated)
#Verify that profiles are loaded and are not in complain
mode:
  apparmor_status | grep profiles
#Verify that no processes are unconfined:
  apparmor_status | grep processes
#Set all profiles to enforce mode:
  aa-enforce /etc/apparmor.d/*
#####################################################################
####################################
1.8 Warning Banners                #
####################################
#1.8.1.1 Ensure message of the day is configured properly (Automated)
#verify that the contents match site policy:
  cat /etc/motd
#verify no results are returned:
  grep -E -i "(\\\v|\\\r|\\\m|\\\s|$(grep '^ID=' /etc/os-release | cut -d= -
f2 | sed -e 's/"//g'))" /etc/motd
# Remove the motd file: (If the motd is not used, this file can be removed.)
  rm /etc/motd
#1.8.1.2 Ensure local login warning banner is configured properly
(Automated)
#Run the following command and verify that the contents match site policy:
 cat /etc/issue
verify no results are returned:
  grep -E -i "(\\\v|\\\r|\\\m|\\\s|$(grep '^ID=' /etc/os-release | cut -d= -
f2 | sed -e 's/"//g'))" /etc/issue
#1.8.1.3 Ensure remote login warning banner is configured properly (Automated)
#verify that the contents match site policy:
#  cat /etc/issue.net
#verify no results are returned:
grep -E -i "(\\\v|\\\r|\\\m|\\\s|$(grep '^ID=' /etc/os-release | cut -d = -f2 | sed -e 's/"//g'))" /etc/issue.net
##Edit the /etc/issue.net file with the appropriate contents according to your site policy,
#remove any instances of \m , \r , \s , \v or references to the OS platform
echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue.net
#1.8.1.4 Ensure permissions on /etc/motd are configured (Automated)
# Verify: Uid and Gid are both 0/root and Access is 644, or
# the file doesn't exist.
# stat /etc/motd
# Access: (0644/-rw-r--r--) Uid: ( 0/ root) Gid: ( 0/ root)
# set permissions on /etc/motd :
chown root:root /etc/motd
chmod u-x,go-wx /etc/motd
#Or remove the /etc/motd file:
rm /etc/motd
#1.8.1.5 Ensure permissions on /etc/issue are configured (Automated)
# Verify Uid and Gid are both 0/root and Access is 644 :
# stat /etc/issue
# Access: (0644/-rw-r--r--) Uid: ( 0/ root) Gid: ( 0/ root)
# set permissions on /etc/issue :
chown root:root /etc/issue
chmod u-x,go-wx /etc/issue
#1.8.1.6 Ensure permissions on /etc/issue.net are configured (Automated)
# verify Uid and Gid are both 0/root and Access is 644 : stat /etc/issue.net
# Access: (0644/-rw-r--r--) Uid: ( 0/ root) Gid: ( 0/ root)
# set permissions on /etc/issue.net :
chown root:root /etc/issue.net
chmod u-x,go-wx /etc/issue.net
#####################################################################
######################################################################
#1.9 Ensure updates, patches, and additional security software are   #
#installed (Manual)                                                  # 
######################################################################
#Verify there are no updates or patches to install:
apt -s upgrade	
apt dist-upgrade
#1.10 Ensure GDM is removed or login is configured (Automated)
# GDM is installed on the system verify that /etc/gdm3/greeter.dconf-defaults file
# exists and contains the following
# [org/gnome/login-screen]
# banner-message-enable=true
# banner-message-text='<banner message>'
# disable-user-list=true
#Run the following command to re-load GDM on the next login or reboot:
dpkg-reconfigure gdm3
#############################################################################################################################
#####################################################################
#2 Services                                                         #
#####################################################################
#2.1 Inetd Services        
#2.1.1 Ensure xinetd is no installed (Automated)
#2.1.2 Ensure openbsd-inetd is no installed (Automated)
apt purge xinetd | apt purge openbsd-inetd
#####################################################################
###############################
#2.2 Special Purpose Servi    #
###############################
#2.2.1 Time Synchronization
#2.2.1.1 Ensure time synchronization is in use (Automated)
systemctl is-enabled systemd-timesyncd
#  install chrony or NTP.
apt install chrony | apt install ntp
#2.2.1.2 Ensure systemd-timesyncd is configured (Manual)
apt purge ntp | apt purge chrony
# Run the following command to enable systemd-timesyncd
systemctl enable systemd-timesyncd.service
echo "NTP=0.debian.pool.ntp.org 1.debian.pool.ntp.org 
Accordence With Local Policy
FallbackNTP=2.debian.pool.ntp.org 3.debian.pool.ntp.org 
should be In Accordence With Local Policy
RootDistanceMax=1" >> /etc/systemd/timesyncd.conf
# Run the following command to enable systemd-timesyncd
systemctl start systemd-timesyncd.service
timedatectl set-ntp true  
#2.2.1.3 Ensure chrony is configured (Automated)
apt purge ntp |  systemctl --now mask systemd-timesyncd
# Configure chrony
echo "server <remote-server>" >> /etc/chrony/chrony.conf
echo "user _chrony" >> /etc/chrony/chrony.conf
#2.2.1.4 Ensure ntp is configured (Automated)
apt purge chrony |  systemctl --now mask systemd-timesyncd
# Configure ntp
echo "restrict -4 default kod nomodify notrap nopeer noquery
restrict -6 default kod nomodify notrap nopeer noquery" >>  /etc/ntp.conf
echo "server <remote-server>" >> /etc/ntp.conf
echo "RUNASUSER=ntp" >> /etc/init.d/ntp
#2.2.2 Ensure X Window System is not installed (Automated)
apt purge xserver-xorg*
#2.2.3 Ensure Avahi Server is not installed (Automated)
systemctl stop avahi-daaemon.service | systemctl stop avahi-daemon.socket
apt purge avahi-daemon
#2.2.4 Ensure CUPS is not installed (Automated)
apt purge cups
#2.2.5 Ensure DHCP Server is not installed (Automated)
# Run the following command to remove isc-dhcp-server
apt purge isc-dhcp-server
#2.2.6 Ensure LDAP server is not installed (Automated)
# Run one of the following commands to remove slapd
apt purge slapd
#2.2.7 Ensure NFS is not installed (Automated)
apt purge rpcbind
#2.2.8 Ensure DNS Server is not installed (Automated)
apt purge bind9
#2.2.9 Ensure FTP Server is not installed (Automated)
apt purge vsftpd
#2.2.10 Ensure HTTP server is not installed (Automated)
apt purge apache2
#2.2.11 Ensure IMAP and POP3 server are not installed (Automated)
# Run one of the following commands to remove dovecot-imapd and dovecot-pop3d
apt purge dovecot-imapd dovecot-pop3d
#2.2.12 Ensure Samba is not installed (Automated)
apt purge samba
#2.2.13 Ensure HTTP Proxy Server is not installed (Automated)
apt purge squid
#2.2.14 Ensure SNMP Server is not installed (Automated)
apt purge snmpd
#2.2.15 Ensure mail transfer agent is configured for local-only mode (Automated)
echo "dc_eximconfig_configtype='local'
dc_local_interfaces='127.0.0.1 ; ::1'
dc_readhost=''
dc_relay_domains=''
dc_minimaldns='false'
dc_relay_nets=''
dc_smarthost=''
dc_use_split_config='false'
dc_hide_mailname=''
dc_mailname_in_oh='true'
dc_localdelivery='mail_spool'" >> /etc/exim4/update-exim4.conf.conf
# Restart exim4
systemctl restart exim4
#2.2.16 Ensure rsync service is not installed (Automated)
apt purge rsync
#2.2.17 Ensure NIS Server is not installed (Automated)
apt purge nis
#####################################################################
####################################
2.3 Service Clients                #
####################################
#2.3.1 Ensure NIS Client is not installed (Automated)
#to provide the needed information:
 dpkg -s nis
#Uninstall nis:
 apt purge nis
#2.3.2 Ensure rsh client is not installed (Automated)
#Verify rsh-client is not installed
 dpkg -s rsh-client
#Uninstall rsh:
 apt purge rsh-client
#2.3.3 Ensure talk client is not installed (Automated)
#Verify talk is not installed
 dpkg -s talk
#Uninstall talk:
 apt purge talk
#2.3.4 Ensure telnet client is not installed (Automated)
#Verify telnet is not installed.
 dpkg -s telnet
#Uninstall telnet:
 apt purge telnet
#2.3.5 Ensure LDAP client is not installed (Automated)
#Verify that ldap-utils is not installed
 dpkg -s ldap-utils
#Uninstall ldap-utils:
 apt purge ldap-utils
#2.3.6 Ensure RPC is not installed (Automated)
#verify rpcbind is not installed
 dpkg -s rpcbind
#remove rpcbind:
 apt purge rpcbind
#2.4 Ensure nonessential services are removed or masked (Manual)
#Run the following command:
lsof -i -P -n | grep -v "(ESTABLISHED)"} 
#remove the package containing the service:
 apt purge <package_name>
###If required packages have a dependency:###
 systemctl --now mask <service_name>
#############################################################################################################################
#####################################
#3 Network Configuration            #
#####################################
#3.1 Disable unused network protocols and devices
#3.1.1 Disable IPv6 (Manual)
 grep "^\s*linux" /boot/grub/grub.cfg | grep -v "ipv6.disable=1"
#Edit /etc/default/grub and add ipv6.disable=1 to the GRUB_CMDLINE_LINUX parameters:
GRUB_CMDLINE_LINUX="ipv6.disable=1"
#update the grub2 configuration:
 update-grub
#3.1.2 Ensure wireless interfaces are disabled (Automated)
Profile Applicability:
#Run the following script to verify no wireless interfaces are active on the system:
 !/bin/bash
 if command -v nmcli >/dev/null 2>&1 ; then
  nmcli radio all | grep -Eq '\s*\S+\s+disabled\s+\S+\s+disabled\b' && echo
 "Wireless is not enabled" || nmcli radio all
 elif [ -n "$(find /sys/class/net/*/ -type d -name wireless)" ]; then
  t=0
  drivers=$(for driverdir in $(find /sys/class/net/*/ -type d -name wireless 
| xargs -0 dirname); do basename "$(readlink -f
 "$driverdir"/device/driver)";done | sort -u)
  for dm in $drivers; do
  if grep -Eq "^\s*install\s+$dm\s+/bin/(true|false)"
 /etc/modprobe.d/*.conf; then
  /bin/true
  else
  echo "$dm is not disabled"
  t=1
  fi
  done
 [[ $t -eq 0 ]] && echo "Wireless is not enabled"
else
 echo "Wireless is not enabled"
fi
#####################################################################
#####################################
#3.2 Network Parameters (Host Only) #
#####################################
#3.2.1 Ensure packet redirect sending is disabled (Automated)
#Run the following commands and verify output matches:
sysctl net.ipv4.conf.all.send_redirects
net.ipv4.conf.all.send_redirects = 0
sysctl net.ipv4.conf.default.send_redirects
net.ipv4.conf.default.send_redirects = 0
grep "net\.ipv4\.conf\.all\.send_redirects" /etc/sysctl.conf
/etc/sysctl.d/*
net.ipv4.conf.all.send_redirects = 0
grep "net\.ipv4\.conf\.default\.send_redirects" /etc/sysctl.conf
/etc/sysctl.d/*
net.ipv4.conf.default.send_redirects= 0
Set the following parameters in /etc/sysctl.conf or a /etc/sysctl.d/* file:
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
#Run the following commands to set the active kernel parameters:
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.default.send_redirects=0
sysctl -w net.ipv4.route.flush=1
#3.2.2 Ensure IP forwarding is disabled (Automated)
#Run the following command and verify output matches:
sysctl net.ipv4.ip_forward
net.ipv4.ip_forward = 0
grep -E -s "^\s*net\.ipv4\.ip_forward\s*=\s*1" /etc/sysctl.conf
etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /run/sysctl.d/*.conf
# No value should be returned
#####################################################################
##############################################
#3.3 Network Parameters (Host and Router)    #
##############################################
#3.3.1 Ensure source routed packets are not accepted (Automated)
echo "net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
# Run the following commands to set the active kernel parameters
sysctl -w net.ipv4.conf.all.accept_source_route=0
sysctl -w net.ipv4.conf.default.accept_source_route=0
sysctl -w net.ipv4.route.flush=1
# IF IPv6 is enabled
echo "net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
# Run the following commands to set the active kernel parameters
sysctl -w net.ipv6.conf.all.accept_source_route=0
sysctl -w net.ipv6.conf.default.accept_source_route=0
sysctl -w net.ipv6.route.flush=1
#3.3.2 Ensure ICMP redirects are not accepted (Automated)
echo "net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
# Run the following commands to set the active kernel parameters
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0
sysctl -w net.ipv4.route.flush=1
# IF IPv6 is enabled
echo " net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
sysctl -w net.ipv6.conf.all.accept_redirects=0
sysctl -w net.ipv6.conf.default.accept_redirects=0
sysctl -w net.ipv6.route.flush=1
#3.3.3 Ensure secure ICMP redirects are not accepted (Automated)
echo "net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.secure_redirects=0
sysctl -w net.ipv4.conf.default.secure_redirects=0
sysctl -w net.ipv4.route.flush=1
#3.3.4 Ensure suspicious packets are logged (Automated)
echo "net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1" >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.log_martians=1
sysctl -w net.ipv4.conf.default.log_martians=1
sysctl -w net.ipv4.route.flush=1
#3.3.5 Ensure broadcast ICMP requests are ignored (Automated)
echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf
# Run the following commands to set the active kernel parameters
sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
sysctl -w net.ipv4.route.flush=1
#3.3.6 Ensure bogus ICMP responses are ignored (Automated)
echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.conf 
# Run the following commands to set the active kernel parameters
sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
sysctl -w net.ipv4.route.flush=1
#3.3.7 Ensure Reverse Path Filtering is enabled (Automated)
echo "net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.conf 
sysctl -w net.ipv4.conf.all.rp_filter=1
sysctl -w net.ipv4.conf.default.rp_filter=1
sysctl -w net.ipv4.route.flush=1
#3.3.8 Ensure TCP SYN Cookies is enabled (Automated)
echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
sysctl -w net.ipv4.tcp_syncookies=1
sysctl -w net.ipv4.route.flush=1
#3.3.9 Ensure IPv6 router advertisements are not accepted (Automated)
echo "net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0" >> /etc/sysctl.conf
sysctl -w net.ipv6.conf.all.accept_ra=0
sysctl -w net.ipv6.conf.default.accept_ra=0
sysctl -w net.ipv6.route.flush=1