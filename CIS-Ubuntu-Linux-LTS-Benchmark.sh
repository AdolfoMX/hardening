#!/bin/sh
#############################################################################################################################
#CIS Ubuntu Linux 20.04 LTS Benchmark v1.0.0                                                                                #
#############################################################################################################################
#Integrantes del equipo:                                                                                                    #
#-> Oscar Uriel Chalé                                                                                                       #
#-> Adolfo Tun Dzul                                                                                                         #
#############################################################################################################################
#1 Initial Setup
#####################################################################

######################################################################
#1.1 Filesystem Configuration                                        #
######################################################################
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
#1.1.2 Ensure /tmp is configured (Automate)
#
