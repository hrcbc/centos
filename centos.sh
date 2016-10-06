#!/bin/bash

SUMMARY="
#########################################################################
#  Maintain tools for CentOS Linux server                               #
#  Create by GuoLiang                                                   #
#  2016-10-02                                                           #
#########################################################################
";

echo "$SUMMARY";


USAGE="
 DESCRIPTION
 	This script is used for install server componect.

 OPTIONS
 	--install Install server componect,include VPN(pptp,l2pt,ipsec),FTP(vsftpd)\
 	,Web server(Httpd),MySQL(mariadb)
";

############################### Read Args ###############################

# Define variables

action='';
options='';
mysql_root_password='guoliang.xie'
ssh_port='1036'


serverip=$(ip addr|grep -w "inet" | grep -v "127.0.0.1" |awk 'NR==1{print substr($2,1,index($2,"/")-1)}');
eth=$(ip addr |grep '^[0-9]\+:[[:blank:]]\+[[:alnum:]]\+' |grep -v 'lo' |awk 'NR==1{gsub(":","");print $2}');
shared_secret="1ms.im";
iprange="10.0.1";
vpn_username="guoliang";
vpn_password="xgl.1234";


ARGS=`getopt -o i -u -al install:,stop:,start: -- "$@"`
eval set -- '$ARGS'

while [ -n "$1" ]
do
	case "$1" in
		--install)
			action="$1";
			action=${action:2};
			options="$2";
			shift 2;;

		--stop)
			action="$1";
			action=${action:2};
			shift;;

		--start)
			action="$1";
			action=${action:2};			
			shift;;

		--)
			break;;

		*)
			echo $USAGE;
			break;;
	esac
done


function install()
{
	yum update -y;
	yum install -y epel-release;

	yum install -y gcc-c++ openssl-devel wget expect;

	setup_selinux;

	change_sshd_port;

	install_mysql;

	install_vpn;

}

function setup_selinux()
{
	if [[ $(sestatus |grep "disabled" | wc -| sestatus |grep "disabled" | wc -l) -eq 1 ]]; then
		echo "Setup selinux...";
		yum install -y policycoreutils policycoreutils-python selinux-policy selinux-policy-targeted libselinux-utils setroubleshoot-server setools setools-console mcstrans;

		# Enable selinux need restart
		reboot;
		exit 0;
	fi
}

function change_sshd_port()
{	
	echo "Change ssh port to : $ssh_port"
	$("
		# Add selinux port
		semanage port -a -t ssh_port_t -p tcp $ssh_port;
		# Add firewall port
		firewall-cmd --permanent --zone=public --add-port=$ssh_port/tcp;

		# Reload firewall
		firewall-cmd --reload

		# Change ssh port to 1036
		sed -i 's/\#*Port 22/Port $ssh_port/' /etc/ssh/sshd_config
	");

	systemctl restart sshd.service;
}

function install_mysql()
{
	echo "Setup mariadb..."
	yum install -y mariadb mariadb-server libpam-mysql mysql-client pam-devel mysql-devel;

	systemctl enable mariadb.service;

	systemctl restart mariadb.service;

	SECURE_MYSQL=$(expect -c "
		set timeout 10
		spawn mysql_secure_installation
		expect \"Enter current password for root (enter for none):\"
		send \"\r\"

		expect \"Set root password?\"
		send \"Y\r\"

		expect \"New password:\"
		send \"$mysql_root_password\r\"

		expect \"Re-enter new password: \"
		send \"$mysql_root_password\r\"

		expect \"Remove anonymous users?\"
		send \"Y\r\"

		expect \"Disallow root login remotely?\"
		send \"Y\r\"

		expect \"Remove test database and access to it?\"
		send \"Y\r\"

		expect \"Reload privilege tables now?\"
		send \"Y\r\"

		expect eof
	");

	echo "$SECURE_MYSQL"

}


function install_vpn()
{
	echo "Install VPN at : $serverip $eth";

	yum install -y openswan ppp pptpd xl2tpd;

	yes |mv /etc/ipsec.conf /etc/ipsec.conf.bak;

	cat >>/etc/ipsec.conf<<EOF
# /etc/ipsec.conf - Libreswan IPsec configuration file

# This file:  /etc/ipsec.conf
#
# Enable when using this configuration file with openswan instead of libreswan
#version 2
#
# Manual:     ipsec.conf.5

# basic configuration
config setup
    # NAT-TRAVERSAL support, see README.NAT-Traversal
    nat_traversal=yes

    # exclude networks used on server side by adding %v4:!a.b.c.0/24
    virtual_private=%v4:10.0.0.0/8,%v4:192.168.0.0/16,%v4:172.16.0.0/12

    # OE is now off by default. Uncomment and change to on, to enable.
    oe=off

    # which IPsec stack to use. auto will try netkey, then klips then mast
    protostack=netkey

    force_keepalive=yes
    keep_alive=1800

conn L2TP-PSK-NAT
    rightsubnet=vhost:%priv
    also=L2TP-PSK-noNAT

conn L2TP-PSK-noNAT
    authby=secret
    pfs=no
    auto=add
    keyingtries=3
    rekey=no
    ikelifetime=8h
    keylife=1h
    type=transport
    left=$serverip
    leftid=$serverip
    leftprotoport=17/1701
    right=%any
    rightprotoport=17/%any
    dpddelay=40
    dpdtimeout=130
    dpdaction=clear
    ike=3des-sha1,aes-sha1,aes256-sha1,aes256-sha2_256 
    phase2alg=3des-sha1,aes-sha1,aes256-sha1,aes256-sha2_256
    sha2-truncbug=yes
# For example connections, see your distribution's documentation directory,
# or the documentation which could be located at
#  /usr/share/docs/libreswan-3.*/ or look at https://www.libreswan.org/
#
# There is also a lot of information in the manual page, "man ipsec.conf"

# You may put your configuration (.conf) file in the "/etc/ipsec.d/" directory
# by uncommenting this line
#include /etc/ipsec.d/*.conf
EOF
	
	#设置预共享密钥配置文件
	yes |mv /etc/ipsec.secrets /etc/ipsec.secrets.bak;
	cat >>/etc/ipsec.secrets<<EOF
#include /etc/ipsec.d/*.secrets
$serverip %any: PSK "$shared_secret"
EOF


	#配置pptpd.conf配置文件
	yes |mv /etc/pptpd.conf /etc/pptpd.conf.bak;
	cat >>/etc/pptpd.conf<<EOF
#ppp /usr/sbin/pppd
option /etc/ppp/options.pptpd
#debug
# stimeout 10
#noipparam
logwtmp
#vrf test
#bcrelay eth1
#delegate
#connections 100
localip $iprange.2
remoteip $iprange.200-254

EOF

	#创建xl2tpd.conf配置文件
	mkdir -p /etc/xl2tpd
	if [ -f "/etc/xl2tpd/xl2tpd.conf" ]; then
		yes |mv /etc/xl2tpd/xl2tpd.conf /etc/xl2tpd/xl2tpd.conf.bak
	fi

	cat >>/etc/xl2tpd/xl2tpd.conf<<EOF
;
; This is a minimal sample xl2tpd configuration file for use
; with L2TP over IPsec.
;
; The idea is to provide an L2TP daemon to which remote Windows L2TP/IPsec
; clients connect. In this example, the internal (protected) network
; is 192.168.1.0/24.  A special IP range within this network is reserved
; for the remote clients: 192.168.1.128/25
; (i.e. 192.168.1.128 ... 192.168.1.254)
;
; The listen-addr parameter can be used if you want to bind the L2TP daemon
; to a specific IP address instead of to all interfaces. For instance,
; you could bind it to the interface of the internal LAN (e.g. 192.168.1.98
; in the example below). Yet another IP address (local ip, e.g. 192.168.1.99)
; will be used by xl2tpd as its address on pppX interfaces.
[global]
; ipsec saref = yes
listen-addr = $serverip
auth file = /etc/ppp/chap-secrets
port = 1701
[lns default]
ip range = $iprange.10-$iprange.199
local ip = $iprange.1
refuse chap = yes
refuse pap = yes
require authentication = yes
name = L2TPVPN
ppp debug = yes
pppoptfile = /etc/ppp/options.xl2tpd
length bit = yes
EOF

	#创建options.pptpd配置文件
	mkdir -p /etc/ppp
	if [ -f "/etc/ppp/options.pptpd" ]; then
		yes |mv /etc/ppp/options.pptpd /etc/ppp/options.pptpd.bak
	fi

	cat >>/etc/ppp/options.pptpd<<EOF
# Authentication
name pptpd
#chapms-strip-domain

# Encryption
# BSD licensed ppp-2.4.2 upstream with MPPE only, kernel module ppp_mppe.o
# {{{
refuse-pap
refuse-chap
refuse-mschap
# Require the peer to authenticate itself using MS-CHAPv2 [Microsoft
# Challenge Handshake Authentication Protocol, Version 2] authentication.
require-mschap-v2
# Require MPPE 128-bit encryption
# (note that MPPE requires the use of MSCHAP-V2 during authentication)
require-mppe-128
# }}}

# OpenSSL licensed ppp-2.4.1 fork with MPPE only, kernel module mppe.o
# {{{
#-chap
#-chapms
# Require the peer to authenticate itself using MS-CHAPv2 [Microsoft
# Challenge Handshake Authentication Protocol, Version 2] authentication.
#+chapms-v2
# Require MPPE encryption
# (note that MPPE requires the use of MSCHAP-V2 during authentication)
#mppe-40    # enable either 40-bit or 128-bit, not both
#mppe-128
#mppe-stateless
# }}}

ms-dns 8.8.8.8
ms-dns 8.8.4.4

#ms-wins 10.0.0.3
#ms-wins 10.0.0.4

proxyarp
#10.8.0.100

# Logging
#debug
#dump
lock
nobsdcomp 
novj
novjccomp
nologfd

EOF

	#创建options.xl2tpd配置文件
	if [ -f "/etc/ppp/options.xl2tpd" ]; then
		yes |mv /etc/ppp/options.xl2tpd /etc/ppp/options.xl2tpd.bak
	fi
	cat >>/etc/ppp/options.xl2tpd<<EOF
#require-pap
#require-chap
#require-mschap
ipcp-accept-local
ipcp-accept-remote
require-mschap-v2
ms-dns 8.8.8.8
ms-dns 8.8.4.4
asyncmap 0
auth
crtscts
lock
hide-password
modem
debug
name l2tpd
proxyarp
lcp-echo-interval 30
lcp-echo-failure 4
mtu 1400
noccp
connect-delay 5000
# To allow authentication against a Windows domain EXAMPLE, and require the
# user to be in a group "VPN Users". Requires the samba-winbind package
# require-mschap-v2
# plugin winbind.so
# ntlm_auth-helper '/usr/bin/ntlm_auth --helper-protocol=ntlm-server-1 --require-membership-of="EXAMPLE\VPN Users"'
# You need to join the domain on the server, for example using samba:
# http://rootmanager.com/ubuntu-ipsec-l2tp-windows-domain-auth/setting-up-openswan-xl2tpd-with-native-windows-clients-lucid.html
EOF

	#创建chap-secrets配置文件，即用户列表及密码
	if [ -f "/etc/ppp/chap-secrets" ]; then
		yes |mv /etc/ppp/chap-secrets /etc/ppp/chap-secrets.bak
	fi
	cat >>/etc/ppp/chap-secrets<<EOF
# Secrets for authentication using CHAP
# client     server     secret               IP addresses
$vpn_username          pptpd     $vpn_password               *
$vpn_username          l2tpd     $vpn_password               *
EOF

	#修改系统配置，允许IP转发
	sysctl -w net.ipv4.ip_forward=1
	sysctl -w net.ipv4.conf.all.rp_filter=0
	sysctl -w net.ipv4.conf.default.rp_filter=0
	sysctl -w net.ipv4.conf.$eth.rp_filter=0
	sysctl -w net.ipv4.conf.all.send_redirects=0
	sysctl -w net.ipv4.conf.default.send_redirects=0
	sysctl -w net.ipv4.conf.all.accept_redirects=0
	sysctl -w net.ipv4.conf.default.accept_redirects=0

	sed -i "/net.ipv4.ip_forward = 1/d" /etc/sysctl.conf
	sed -i "/net.ipv4.conf.all.rp_filter = 0/d" /etc/sysctl.conf
	sed -i "/net.ipv4.conf.default.rp_filter = 0/d" /etc/sysctl.conf
	sed -i "/net.ipv4.conf.$eth.rp_filter = 0/d" /etc/sysctl.conf
	sed -i "/net.ipv4.conf.all.send_redirects = 0/d" /etc/sysctl.conf
	sed -i "/net.ipv4.conf.default.send_redirects = 0/d" /etc/sysctl.conf
	sed -i "/net.ipv4.conf.all.accept_redirects = 0/d" /etc/sysctl.conf
	sed -i "/net.ipv4.conf.default.accept_redirects = 0/d" /etc/sysctl.conf

	sed -i "$ a net.ipv4.ip_forward = 1" /etc/sysctl.conf
	sed -i "$ a net.ipv4.conf.all.rp_filter = 0" /etc/sysctl.conf
	sed -i "$ a net.ipv4.conf.default.rp_filter = 0" /etc/sysctl.conf
	sed -i "$ a net.ipv4.conf.$eth.rp_filter = 0" /etc/sysctl.conf
	sed -i "$ a net.ipv4.conf.all.send_redirects = 0" /etc/sysctl.conf
	sed -i "$ a net.ipv4.conf.default.send_redirects = 0" /etc/sysctl.conf
	sed -i "$ a net.ipv4.conf.all.accept_redirects = 0" /etc/sysctl.conf
	sed -i "$ a net.ipv4.conf.default.accept_redirects = 0" /etc/sysctl.conf

	#允许防火墙端口
	cat >>/usr/lib/firewalld/services/pptpd.xml<<EOF
<?xml version="1.0" encoding="utf-8"?>
<service>
  <short>pptpd</short>
  <description>PPTP and Fuck the GFW</description>
  <port protocol="tcp" port="1723"/>
</service>
EOF

	cat >>/usr/lib/firewalld/services/l2tpd.xml<<EOF
<?xml version="1.0" encoding="utf-8"?>
<service>
  <short>l2tpd</short>
  <description>L2TP IPSec</description>
  <port protocol="udp" port="500"/>
  <port protocol="udp" port="4500"/>
  <port protocol="udp" port="1701"/>
</service>
EOF
	
	firewall-cmd --reload;
	firewall-cmd --permanent --add-service=pptpd;
	firewall-cmd --permanent --add-service=l2tpd;
	firewall-cmd --permanent --add-service=ipsec;
	firewall-cmd --permanent --add-masquerade;
	firewall-cmd --permanent --direct --add-rule ipv4 filter FORWARD 0 -p tcp -i ppp+ -j TCPMSS --syn --set-mss 1356;
	firewall-cmd --reload;

	systemctl enable pptpd.service ipsec.service xl2tpd.service;
	systemctl restart pptpd.service ipsec.service xl2tpd.service;

	echo "VPN install finish."
}


function install_ftp()
{
	echo "Instal vsftpd...";
	
	yum install -y vsftpd ftp;	
}


case $action in
	install)
		install;;
esac




