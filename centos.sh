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
 	--install    		    Install server componect,include:mysql,http,svn,vpn,ftp,tomcat,oracle,weblogic,cobbler,kvm
  --config-route
 	--host-name  		    Domain name for the host.
 	--http-proxy-tomcat     When the value is 1, set the HTTP reverse proxy to Tomcat,default 1
 	--oracle-password   	Specify the super user‘s password
 	--weblogic-password		Specify the Weblogic console user‘s password
 	--gitlab-port 			Define gitlab visit port,default 80
 	--mysql-password		  Specify mysql root user's password
  --vpn-username        VPN login user name
  --vpn-password        VPN login password
  --vpn-cert-password   Specifies the password for generate the client certificate
  --shared-secret
 	--config-route			  Automatically configure the  IP routing for multi network interfaces
 	--nat-forward			    Configure nat port forwarding
 	--skip-update
";


cur_path=$("pwd");

# 服务检测
function service_test()
{
	if [[ $(systemctl status $1 | grep "Loaded: loaded" | wc -l) -eq 1 ]]; then
		echo "1";
	else
		echo "0";
	fi
}

# 命令检测
function command_test()
{
	if [[ $($1 2>&1 | grep "command not found" | wc -l) -eq 1 ]]; then
		echo "0"
	else
		echo "1"
	fi
}


# 安装系统必备

if [[ $(echo $* |grep "skip-update" |wc -l) -eq 0 ]]; then
	yum update -y;
fi
yum install -y epel-release;

yum install -y gcc-c++ openssl-devel wget zip unzip expect net-tools;

source /etc/profile


# 配置Java环境

if [[ $(command_test "java") -eq 0 ]] || [[ $(java -version 2>&1 |grep -w "1.8" | wc -l) -eq 0 ]]; then
	 #wget -N --no-check-certificate --no-cookies --header "Cookie: oraclelicense=accept-securebackup-cookie" http://download.oracle.com/otn-pub/java/jdk/8u102-b14/jdk-8u102-linux-x64.tar.gz
	 if [[ ! -f "jdk-8u111-linux-x64.tar.gz" ]]; then
	 	wget -c http://xieguoliang.com/downloads/jdk-8u111-linux-x64.tar.gz
	 fi

	 # wget --no-check-certificate --no-cookies --header "Cookie: oraclelicense=accept-securebackup-cookie" http://download.oracle.com/otn-pub/java/jdk/8u102-b14/jdk-8u102-linux-x64.rpm

	 # curl -v -j -k -L -H "Cookie: oraclelicense=accept-securebackup-cookie" http://download.oracle.com/otn-pub/java/jdk/8u102-b14/jdk-8u102-linux-x64.rpm > jdk-8u102-linux-x64.rpm
	 # In all cases above, subst 'i586' for 'x64' to download the 32-bit build.
	# -j -> junk cookies
	# -k -> ignore certificates
	# -L -> follow redirects
	# -H [arg] -> headers
	# curl can be used in place of wget.


	tar xzvf ./jdk-8u111-linux-x64.tar.gz -C /var/local;

  rm -rf /var/local/jdk
	ln -s /var/local/jdk1.8.0_111 /var/local/jdk;

	#rm -rf ./jdk-8u102-linux-x64.tar.gz;

	#yum -y install java-1.8.0-openjdk*

	#export JAVA_HOME=/usr/lib/jvm/java-1.8.0-openjdk;
	export JAVA_HOME=/var/local/jdk;
	export JRE_HOME=$JAVA_HOME/jre;
	export CLASS_PATH=.:$JAVA_HOME/lib;
	export PATH=$PATH:$JAVA_HOME/bin;
	sed -i '/export JAVA_HOME=.*/d' /etc/profile
	sed -i '/export CLASS_PATH=.*/d' /etc/profile
	sed -i '/export JRE_HOME=.*/d' /etc/profile
	sed -i '/export PATH=\$PATH:\$JAVA_HOME\/bin/d' /etc/profile
	sed -i '$ a export JAVA_HOME=\/var\/local\/jdk' /etc/profile
	#sed -i '$ a export JAVA_HOME=\/usr\/lib\/jvm\/java-1.8.0-openjdk' /etc/profile
	sed -i '$ a export JRE_HOME=\$JAVA_HOME\/jre' /etc/profile
	sed -i '$ a export CLASS_PATH=\.\:\$JAVA_HOME\/lib' /etc/profile
	sed -i '$ a export PATH=\$PATH:\$JAVA_HOME\/bin' /etc/profile
	source /etc/profile;
fi

############################### Read Args ###############################

action='';
options='';


# SSH
ssh_port='1036'

# 域名
host_name=""
site_dir=""

# Tomcat
http_proxy_tomcat=1

# Oracle
oracle_password="";

# Weblogic
weblogic_password="abcd1234"

# Gitlab
gitlab_port="80"

# FTP
mysql_vsftpd_password=$(cat /dev/urandom | head -n 10 | md5sum | head -c 10);
ftp_username='hrcbc';
ftp_password='guoliang.xie';

# Mysql
mysql_root_password='guoliang.xie'

# VPN
shared_secret="1ms.im";
iprange="10.0.1";
vpn_username="guoliang";
vpn_password="xgl.1234";
vpn_cert_password="abcd1234"

ARGS=`getopt -o i -u -al skip-update,config-route,nat-forward:,install:,stop:,start:,ssh-port:,host-name:,http-proxy-tomcat:,oracle-password:,oracle-sid:,weblogic-password:,gitlab-port:,mysql-password:,vpn-username:,vpn-password:,vpn-cert-password:,shared-secret: -- "$@"`
eval set -- '$ARGS'

while [ -n "$1" ]
do
	case "$1" in
		--install)
			action="$1";
			action=${action:2};
			options="$2";
			shift 2;;

		--config-route)
			action="config-route";
			shift;;

		--nat-forward)
			action="nat-forward";
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

		--ssh-port)
			ssh_port="$2";
			shift 2;;

		--host-name)
			host_name="$2";
			shift 2;;

		--http-proxy-tomcat)
			http_proxy_tomcat="$2";
			shift 2;;

		--oracle-password)
			oracle_password="$2";
			shift 2;;

		--weblogic-password)
			weblogic_password="$2";
			shift 2;;

		--oracle-sid)
			oracle-sid="$2";
			shift 2;;

		--gitlab-port)
			gitlab_port="$2";
			shift 2;;

		--mysql-password)
			mysql_root_password="$2";
			shift 2;;

    --vpn-username)
			vpn_username="$2";
			shift 2;;

    --vpn-password)
			vpn_password="$2";
			shift 2;;

    --vpn-cert-password)
			vpn_cert_password="$2";
  		shift 2;;

    --shared-secret)
			shared_secret="$2";
			shift 2;;

		--skip-update)
			shift;;

		--)
			break;;

		*)
			echo "unrecognized option '$1'";
			echo "$USAGE";
			break;;
	esac
done

if [[ $action == "install" ]]; then
	if [ -n $options ]; then
        options=${options//+/|+};
        options=${options//-/|-};
        options=${options//,/|,};
	else
        options="all";
	fi

	options="|$options|";
fi

# 选项检测
function option_test()
{
        if [ $(echo "$options" | egrep "\|\-$1\|" |wc -l) -eq 1 ]; then
                echo "0"
        elif [ $(echo "$options" | egrep "(\|all\|)|(\|[+,]?$1\|)" |wc -l) -eq 1 ]; then
                echo "1"
        else
                echo "0"
        fi
}


# 获取网络信息
eth=$(ip addr |grep '^[0-9]\+:[[:blank:]]\+[[:alnum:]]\+' |grep -v 'state DOWN' |grep -v 'pfifo_fast master br'|grep -v 'lo' |awk 'NR==1{gsub(":","");print $2}');
serverip=$(ip addr show $eth|grep -w "inet" | grep -v "127.0.0.1" |awk 'NR==1{print substr($2,1,index($2,"/")-1)}');
gateway=$(ip route list |grep "$eth" |grep -w "via" |awk 'NR==1{print $3}');
netmask=$(ifconfig $eth |grep -w "netmask" |awk '{print $4}');
hwaddr=$(ip addr show $eth |grep "link/ether" |awk '{print $2}');


############################# Define variables #############################

# SVN
if [[ ! -f "sha1.jar" ]]; then
	wget -c http://xieguoliang.com/downloads/sha1.jar
fi

mysql_svn_password=$(cat /dev/urandom | head -n 10 | md5sum | head -c 10);
svn_username="guoliang";
svn_password=$(java -jar ./sha1.jar xgl.1234);
svn_dbname="svnserver";
svn_dbuser="svn";

o_mysql_state=$(option_test "mysql");
o_ftp_state=$(option_test "ftp");
o_vpn_state=$(option_test "vpn");
o_http_state=$(option_test "http");
o_svn_state=$(option_test "svn");
o_tomcat_state=$(option_test "tomcat");
o_oracle_state=$(option_test "oracle");
o_cobbler_state=$(option_test "cobbler");
o_weblogic_state=$(option_test "weblogic");
o_gitlab_state=$(option_test "gitlab");
o_kvm_state=$(option_test "kvm");



############################# Non-nullable parameter input #############################


# 域名输入
function input_host_name() {
	if [[ -z "$host_name" ]]; then
		printf "Please input \e[33mdomain name\e[0m for server,if dont't use domain let it blank:\n"
		read tmp;
		host_name="$tmp";
	fi
}

# Oracle超级密码输入
function input_oracle_password() {
	if [[ -z "$oracle_password" ]]; then
		while [[ -z "$oracle_password" ]]
		do
			printf "Please input \e[33moracle password\e[0m:\n"
			read tmp;
			oracle_password="$tmp";
		done
	fi
}


function install()
{

	sync_time;

	setup_selinux;

	change_sshd_port;

	install_mysql;

	#install_vpn;

  install_strongswan;

	install_ftp;

	install_httpd;

	install_svn;

	install_tomcat;

	#install_oracle12c;
	install_oracle11gr2;

	install_cobbler;

	install_weblogic12;

	install_gitlab;

	install_kvm;
}

function sync_time()
{
	if [[ $(service_test "chronyd") -eq 0 ]]; then
		yum install -y chrony;
		timedatectl set-timezone Asia/Shanghai
		timedatectl set-local-rtc 1
		systemctl enable chronyd
		systemctl start chronyd
	fi
}

function setup_selinux()
{
	if [[  $(command_test "semanage") -eq 0 ]]; then
		yum install -y policycoreutils policycoreutils-python selinux-policy selinux-policy-targeted libselinux-utils setroubleshoot-server setools setools-console mcstrans selinux-policy-devel;
	fi;

	if [[ $(sestatus |grep "disabled" | wc -l) -eq 1 ]]; then
		echo "Setup selinux...";

		sed -i "s/^SELINUX=disabled/SELINUX=enforcing/" /etc/sysconfig/selinux;
		sed -i "s/^SELINUX=disabled/SELINUX=enforcing/" /etc/selinux/config;
		# Enable selinux need restart
		reboot;
		exit 0;
	fi
}

function change_sshd_port()
{
	if [[ $(grep "^Port $ssh_port" /etc/ssh/sshd_config | wc -l) -eq 0 ]]; then
		echo "Change ssh port to : $ssh_port"

		# Add selinux port
		semanage port -a -t ssh_port_t -p tcp $ssh_port;
		# Add firewall port
		firewall-cmd --permanent --zone=public --add-port=$ssh_port/tcp;

		# Reload firewall
		firewall-cmd --reload;

		# Change ssh port to 1036
		sed -i "s/^#*Port[[:space:]]*[[:digit:]]*/Port $ssh_port/" /etc/ssh/sshd_config

		systemctl restart sshd.service;
	fi
}

# 安装MySQL
function install_mysql()
{
	if [[ $o_mysql_state -eq 1 || $1 -eq 1 ]] && [[ $(service_test "mariadb") -eq 0 ]]; then

		echo "Start install mariadb..."
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

		echo "Mariadb installed success."

		o_mysql_state=2;

	fi
}

# 安装VPN服务
function install_vpn()
{
	if [[ $o_vpn_state -eq 1 || $1 -eq 1 ]] && [[ $(service_test "pptpd") -eq 0 || $(service_test "ipsec") -eq 0 || $(service_test "xl2tpd") -eq 0 ]]; then

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
		rm -rf /usr/lib/firewalld/services/pptpd.xml
		cat >>/usr/lib/firewalld/services/pptpd.xml<<EOF
<?xml version="1.0" encoding="utf-8"?>
<service>
  <short>pptpd</short>
  <description>PPTP and Fuck the GFW</description>
  <port protocol="tcp" port="1723"/>
</service>
EOF

		rm -rf /usr/lib/firewalld/services/l2tpd.xml

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

		o_vpn_state=2;
	fi
  install_freeradius
}

function install_freeradius() {
  install_mysql 1
  yum -y install freeradius freeradius-mysql freeradius-utils

}

function install_strongswan() {
  # 参考
  # https://www.kiritostudio.com/running-a-strongswan-server-with-radius-on-your-vps/
  # http://cache.baiducontent.com/c?m=9f65cb4a8c8507ed4fece763105392230e54f73260878e482a958448e435061e5a3cb0e76c7944538f9061251cab4a5ae0f63d70200357eddd97d65e98e6d27e20c961742d40d35613a358ea981a32c151c41abef80ee6cab061c5f59592&p=907d890f86cc42af53f5c7710f4983&newp=8b2a975b978415c308e2977e060590231610db2151d4d11e6b82c825d7331b001c3bbfb42323140ed6cf796201ae4d57e9f63d7136032ba3dda5c91d9fb4c574799666732470&user=baidu&fm=sc&query=strongswan+freeradius&qid=f9f9019900012e99&p1=6
  # http://www.07net01.com/2016/12/1757328.html
  # https://github.com/philpl/setup-strong-strongswan/blob/master/setup.sh
  # https://www.vultr.com/docs/using-strongswan-for-ipsec-vpn-on-centos-7
  # http://zlyang.blog.51cto.com/1196234/1881225/
  # https://blog.itnmg.net/centos7-ipsec-vpn/
  # https://wbuntu.com/?p=323
  # http://maskray.me/blog/2015-12-31-strongswan

  if [[ $o_vpn_state -eq 1 || $1 -eq 1 ]] && [[ $(service_test "strongswan") -eq 0 ]]; then
    yum install pam-devel openssl-devel make gcc curl tcpdump -y
    dir=$(pwd);
    rm -rf strongswan
    mkdir strongswan
    curl -sS "http://xieguoliang.com/downloads/strongswan-5.5.1.tar.gz" | tar -zvxC strongswan --strip-components 1
    cd strongswan
    ./configure --prefix=/usr --sysconfdir=/etc/strongswan \
      --enable-eap-identity \
      --enable-eap-md5 \
      --enable-eap-mschapv2 \
      --enable-eap-tls \
      --enable-eap-ttls \
      --enable-eap-peap \
      --enable-eap-tnc \
      --enable-eap-dynamic \
      --enable-eap-radius \
      --enable-xauth-eap  \
      --enable-xauth-pam  \
      --enable-dhcp \
      --enable-openssl \
      --enable-addrblock \
      --enable-unity \
      --enable-certexpire \
      --enable-radattr \
      --enable-swanctl \
      --enable-openssl \
      --disable-gmp

    make && make install

    systemctl enable strongswan

    cd $dir;

    yum install -y libpcap-devel

    rm -rf xl2tpd-1.3.8
    mkdir xl2tpd-1.3.8
    wget -c "http://xieguoliang.com/downloads/xl2tpd-1.3.8.tar.gz"
    tar xzvf xl2tpd-1.3.8.tar.gz
    cd xl2tpd-1.3.8

    make && make install

    ln -s /usr/local/sbin/xl2tpd /usr/sbin/xl2tpd

    rm -rf /lib/systemd/system/xl2tpd.service;
    cat >>/lib/systemd/system/xl2tpd.service<<EOF
[Unit]
Description=Level 2 Tunnel Protocol Daemon (L2TP)
Wants=network-online.target
After=network-online.target
After=strongswan.service
# Some ISPs in Russia use l2tp without IPsec, so don't insist anymore
#Wants=ipsec.service

[Service]
Type=simple
PIDFile=/var/run/xl2tpd/xl2tpd.pid
ExecStartPre=/sbin/modprobe -q l2tp_ppp
ExecStart=/usr/sbin/xl2tpd -D
Restart=always

[Install]
WantedBy=multi-user.target

EOF

    mkdir /var/run/xl2tpd
    chmod a+rwx /var/run/xl2tpd
    systemctl enable xl2tpd
    cd $dir;

    #yum install -y ppp pptpd;

    input_host_name;

    #install_httpd 1;

    CN="$host_name";
    if [[ -z "$CN" ]]; then
      CN="$serverip";
    fi

    # 生成证书
    # 1. 生成一个私钥：
    ipsec pki --gen --type rsa --size 4096 --outform pem > ca.pem

    # 2. 基于这个私钥自己签一个 CA 根证书
    # –self 表示自签证书
    #  –in 是输入的私钥
    # –dn 是判别名

    #   C 表示国家名，同样还有 ST 州/省名，L 地区名，STREET（全大写） 街道名
    #   O 组织名称
    #   CN 友好显示的通用名
    # –ca 表示生成 CA 根证书
    # –lifetime 为有效期, 单位是天
    ipsec pki --self --in ca.pem --dn "C=CN, O=GuoLiang, CN=$CN" --ca --lifetime 3650 --outform pem >ca.cert.pem

    # 生成服务器端证书
    # 1. 同样先生成一个私钥
    ipsec pki --gen --type rsa --size 2048 --outform pem > server.pem

    # 2. 用我们刚才自签的 CA 证书给自己发一个服务器证书：
    # 从私钥生成公钥
    ipsec pki --pub --in server.pem --type rsa --outform pem > server.pub.pem

    # 用刚生成的公钥生成服务器证书
    # –issue, –cacert 和 –cakey 就是表明要用刚才自签的 CA 证书来签这个服务器证书。
    # –dn, –san，–flag 是一些客户端方面的特殊要求：

    # iOS 客户端要求 CN 也就是通用名必须是你的服务器的 URL 或 IP 地址;
    # Windows 7 不但要求了上面，还要求必须显式说明这个服务器证书的用途（用于与服务器进行认证），–flag serverAuth;
    # 非 iOS 的 Mac OS X 要求了“IP 安全网络密钥互换居间（IP Security IKE Intermediate）”这种增强型密钥用法（EKU），–flag ikdeIntermediate;
    # Android 和 iOS 都要求服务器别名（serverAltName）就是服务器的 URL 或 IP 地址，–san。
    ipsec pki --issue --lifetime 3600 --cacert ca.cert.pem --cakey ca.pem --in server.pub.pem --dn "C=CN, O=GuoLiang, CN=$CN" --san="$CN" --flag serverAuth --flag ikeIntermediate --outform pem > server.cert.pem

    # 生成客户端证书(可选)

    # 客户端证书是在启用客户端证书验证的时候, 用于验证客户端用户身份的. 每个用户一个证书. 如果需要很高的安全性, 可以用客户端证书, 一般情况下, 不需要使用.
    # 1. 依然是生成私钥：
    ipsec pki --gen --type rsa --size 2048 --outform pem > client.pem

    # 2. 然后用刚才自签的 CA 证书来签客户端证书：
    # 从私钥生成公钥
    ipsec pki --pub --in client.pem --type rsa --outform pem > client.pub.pem

    # 这里就不需要上面那一堆特殊参数了

    ipsec pki --issue --lifetime 3600 --cacert ca.cert.pem --cakey ca.pem  --in client.pub.pem --dn "C=cn, O=GuoLiang, CN=$CN" --outform pem > client.cert.pem
    # 打包证书为 pkcs12
    # 此时会提示输入两次密码, 这个密码是在导入证书到其他系统时需要验证的. 没有这个密码即使别人拿到了证书也没法使用.

    EXPORT_P12=$(expect -c "
      set timeout -1
      spawn openssl pkcs12 -export -inkey client.pem -in client.cert.pem -name \"VPN Client Cert\" -certfile ca.cert.pem -caname \"$CN VPN CA\" -out client.cert.p12
      expect \"Enter Export Password:\"
      send \"$vpn_cert_password\r\"

      expect \"Enter Export Password:\"
      send \"$vpn_cert_password\r\"

      expect eof
    ");

    echo "$EXPORT_P12"

    cp -r ca.pem /etc/strongswan/ipsec.d/private/
    cp -r server.pem /etc/strongswan/ipsec.d/private/
    cp -r client.pem /etc/strongswan/ipsec.d/private/

    cp -r ca.cert.pem /etc/strongswan/ipsec.d/cacerts/
    cp -r server.cert.pem /etc/strongswan/ipsec.d/certs/
    cp -r server.pub.pem /etc/strongswan/ipsec.d/certs/
    cp -r client.cert.pem /etc/strongswan/ipsec.d/certs/

    rm -rf /etc/strongswan/ipsec.conf;
    cat >>/etc/strongswan/ipsec.conf<<EOF
config setup
    uniqueids=never
    charondebug="cfg 2, dmn 2, ike 2, net 0"

conn iOS_cert
    keyexchange=ikev1
    fragmentation=yes
    left=%defaultroute
    leftauth=pubkey
    leftsubnet=0.0.0.0/0
    leftcert=server.cert.pem
    right=%any
    rightauth=pubkey
    rightauth2=xauth
    rightsourceip=$iprange.0/24
    rightcert=client.cert.pem
    auto=add

conn android_xauth_psk
    keyexchange=ikev1
    left=%defaultroute
    leftauth=psk
    leftsubnet=0.0.0.0/0
    right=%any
    rightauth=psk
    rightauth2=xauth
    rightsourceip=$iprange.0/24
    auto=add

conn networkmanager-strongswan
    keyexchange=ikev2
    left=%defaultroute
    leftauth=pubkey
    leftsubnet=0.0.0.0/0
    leftcert=server.cert.pem
    right=%any
    rightauth=pubkey
    rightsourceip=$iprange.0/24
    rightcert=client.cert.pem
    auto=add

conn ios_ikev2
    keyexchange=ikev2
    ike=aes256-sha256-modp2048,3des-sha1-modp2048,aes256-sha1-modp2048!
    esp=aes256-sha256,3des-sha1,aes256-sha1!
    rekey=no
    left=%defaultroute
    leftid=@$CN
    leftsendcert=always
    leftsubnet=0.0.0.0/0
    leftcert=server.cert.pem
    leftfirewall=yes
    right=%any
    rightauth=eap-mschapv2
    rightsourceip=$iprange.0/24
    rightsendcert=never
    eap_identity=%any
    dpdaction=clear
    fragmentation=yes
    auto=add

conn windows7
    keyexchange=ikev2
    ike=aes256-sha1-modp1024!
    rekey=no
    left=%defaultroute
    leftauth=pubkey
    leftsubnet=0.0.0.0/0
    leftcert=server.cert.pem
    right=%any
    rightauth=eap-mschapv2
    rightsourceip=$iprange.0/24
    rightsendcert=never
    eap_identity=%any
    auto=add

conn L2TP-PSK
    keyexchange=ikev1
    authby=secret
    leftprotoport=17/1701
    leftfirewall=no
    rightprotoport=17/%any
    type=transport
    auto=add
EOF

    rm -rf /etc/strongswan/strongswan.conf
    cat >>/etc/strongswan/strongswan.conf<<EOF
charon {
      load_modular = yes
      duplicheck.enable = no
      install_virtual_ip = yes
      compress = yes
      plugins {
              include strongswan.d/charon/*.conf
      }
      dns1 = 114.114.114.114
      dns2 = 8.8.8.8
      nbns1 = 8.8.8.8
      nbns2 = 8.8.4.4
}
include strongswan.d/*.conf
EOF

    rm -rf /etc/strongswan/ipsec.secrets
    cat>>/etc/strongswan/ipsec.secrets<<EOF
: RSA server.pem
: PSK "$shared_secret"
$vpn_username : EAP "$vpn_password"
$vpn_username : XAUTH "$vpn_password"
EOF

    # 生成iOS Profile
    rm -rf $CN.mobileconfig
    plid="org.$CN.vpn."$(uuidgen);
    pluid=$(uuidgen)
    vpnplid=$(uuidgen)
    vpnpluid=$(uuidgen)
    cat >>$CN.mobileconfig<<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>IKEv2</key>
			<dict>
				<key>AuthName</key>
				<string>$vpn_username</string>
				<key>AuthPassword</key>
				<string>$vpn_password</string>
				<key>AuthenticationMethod</key>
				<string>None</string>
				<key>ChildSecurityAssociationParameters</key>
				<dict>
					<key>DiffieHellmanGroup</key>
					<integer>14</integer>
					<key>EncryptionAlgorithm</key>
					<string>3DES</string>
					<key>IntegrityAlgorithm</key>
					<string>SHA1-96</string>
					<key>LifeTimeInMinutes</key>
					<integer>1440</integer>
				</dict>
				<key>DeadPeerDetectionRate</key>
				<string>Medium</string>
				<key>DisableMOBIKE</key>
				<integer>0</integer>
				<key>DisableRedirect</key>
				<integer>0</integer>
				<key>EnableCertificateRevocationCheck</key>
				<integer>0</integer>
				<key>EnablePFS</key>
				<integer>0</integer>
				<key>ExtendedAuthEnabled</key>
				<true/>
				<key>IKESecurityAssociationParameters</key>
				<dict>
					<key>DiffieHellmanGroup</key>
					<integer>14</integer>
					<key>EncryptionAlgorithm</key>
					<string>3DES</string>
					<key>IntegrityAlgorithm</key>
					<string>SHA1-96</string>
					<key>LifeTimeInMinutes</key>
					<integer>1440</integer>
				</dict>
				<key>LocalIdentifier</key>
				<string>$vpn_username</string>
				<key>RemoteAddress</key>
				<string>$CN</string>
				<key>RemoteIdentifier</key>
				<string>$CN</string>
				<key>UseConfigurationAttributeInternalIPSubnet</key>
				<integer>0</integer>
			</dict>
			<key>IPv4</key>
			<dict>
				<key>OverridePrimary</key>
				<integer>1</integer>
			</dict>
			<key>PayloadDescription</key>
			<string>Configures VPN settings</string>
			<key>PayloadDisplayName</key>
			<string>VPN</string>
			<key>PayloadIdentifier</key>
			<string>com.apple.vpn.managed.$vpnplid</string>
			<key>PayloadType</key>
			<string>com.apple.vpn.managed</string>
			<key>PayloadUUID</key>
			<string>$vpnpluid</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
			<key>Proxies</key>
			<dict>
				<key>HTTPEnable</key>
				<integer>0</integer>
				<key>HTTPSEnable</key>
				<integer>0</integer>
			</dict>
			<key>UserDefinedName</key>
			<string>$CN</string>
			<key>VPNType</key>
			<string>IKEv2</string>
		</dict>
	</array>
	<key>PayloadDisplayName</key>
	<string>$CN VPN</string>
	<key>PayloadIdentifier</key>
	<string>$plid</string>
	<key>PayloadRemovalDisallowed</key>
	<false/>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadUUID</key>
	<string>$pluid</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
</dict>
</plist>
EOF

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

    # 开启内核转发
    sysctl -w net.ipv4.ip_forward=1
    sysctl -w net.ipv6.conf.all.forwarding=1

    sed -i "/net.ipv4.ip_forward/d" /etc/sysctl.conf
    sed -i "/net.ipv6.conf.all.forwarding/d" /etc/sysctl.conf

    sed -i "$ a net.ipv4.ip_forward = 1" /etc/sysctl.conf
    sed -i "$ a net.ipv6.conf.all.forwarding = 1" /etc/sysctl.conf
    sysctl -p

    # 配置防火墙
    firewall-cmd --permanent --add-service="ipsec"
    firewall-cmd --permanent --add-port=500/tcp
    firewall-cmd --permanent --add-port=500/udp
    firewall-cmd --permanent --add-port=1723/tcp
    firewall-cmd --permanent --add-port=4500/udp
    firewall-cmd --permanent --add-port=1701/udp
    firewall-cmd --permanent --direct --add-rule ipv4 filter FORWARD 0 -p tcp -i ppp+ -j TCPMSS --syn --set-mss 1356;
    firewall-cmd --permanent --add-masquerade
    firewall-cmd --permanent --add-rich-rule='rule protocol value="esp" accept'
    firewall-cmd --permanent --add-rich-rule='rule protocol value="ah" accept'
    firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="'$iprange'.0/24" masquerade'
    firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="'$iprange'.0/24" forward-port port="4500" protocol="udp" to-port="4500"'
    firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="'$iprange'.0/24" forward-port port="1701" protocol="udp" to-port="1701"'
    firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="'$iprange'.0/24" forward-port port="500" protocol="tcp" to-port="500"'
    firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="'$iprange'.0/24" forward-port port="500" protocol="udp" to-port="500"'
    firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="'$iprange'.0/24" forward-port port="1723" protocol="tcp" to-port="1723"'
    firewall-cmd --reload;




    # 对应iptables配置
    # 开放端口
    # iptables -A INPUT -p udp --dport 500 -j ACCEPT
    # iptables -A INPUT -p udp --dport 4500 -j ACCEPT

    #启用ip伪装
    # iptables -t nat -I POSTROUTING -s 10.1.0.0/16 -o eth0 -m policy --dir out --pol ipsec -j ACCEPT
    # iptables -t nat -A POSTROUTING -s 10.1.0.0/16 -o eth0 -j MASQUERADE

    #添加转发
    # iptables -A FORWARD -s 10.1.0.0/16 -j ACCEPT

    #ausearch -c 'charon' --raw | audit2allow -M my-charon
    #semodule -i my-charon.pp

    systemctl restart strongswan xl2tpd.service;

    if [[ -z "$site_dir" ]]; then
      site_dir="/var/www/html";
  		if [[ -n "$host_name" ]]; then
  			site_dir="/var/www/$host_name"
      fi
    fi
    if [[ -d "$site_dir" ]]; then
      cp $CN.mobileconfig $site_dir/downloads/
      echo "You can download iOS profile from URL : http://$CN/downloads/$CN.mobileconfig"
    fi
  fi
}

function install_ftp()
{

	if [[ $o_ftp_state -eq 1 || $1 -eq 1 ]] && [[ $(service_test "vsftpd") -eq 0 ]]; then

		# 先安装Mysql数据库
		install_mysql 1;

		echo "Instal vsftpd...";

		yum install -y vsftpd ftp;
		if [[ ! -f "pam_mysql-0.7-0.16.rc1.fc20.x86_64.rpm"  ]]; then
			wget -N https://raw.githubusercontent.com/hrcbc/centos/master/pam_mysql-0.7-0.16.rc1.fc20.x86_64.rpm;
		fi
		rpm -ivh pam_mysql-0.7-0.16.rc1.fc20.x86_64.rpm;

		rm -rf pam_mysql-0.7-0.16.rc1.fc20.x86_64.rpm;

		groupadd nogroup;

		useradd --home /home/vsftpd --gid nogroup -m --shell /bin/false vsftpd;

		mysql -uroot -p$mysql_root_password -e "
			drop database if exists ftpserver;
			create database ftpserver;
			grant select,insert,update,delete,create,drop on ftpserver.* to 'vsftpd'@'localhost' identified by '$mysql_vsftpd_password';
			grant select,insert,update,delete,create,drop on ftpserver.* to 'vsftpd'@'localhost.localdomain' identified by '$mysql_vsftpd_password';
			flush privileges;

			use ftpserver;

			CREATE TABLE accounts (
				id INT NOT NULL AUTO_INCREMENT PRIMARY KEY ,
				username VARCHAR( 30 ) NOT NULL ,
				pass VARCHAR( 50 ) NOT NULL ,
				UNIQUE (username)
			) ENGINE = MYISAM ;

			insert into accounts(username,pass) values('$ftp_username',password('$ftp_password'));
		";

		# 修改vsftpd配置文件
		yes |mv /etc/vsftpd/vsftpd.conf /etc/vsftpd/vsftpd.conf.bak

		cat >>/etc/vsftpd/vsftpd.conf<<EOF
listen=YES
listen_port=8342
pasv_enable=YES
pasv_min_port=50000
pasv_max_port=60000
anonymous_enable=NO
local_enable=YES
write_enable=YES
local_umask=022
dirmessage_enable=YES
xferlog_enable=YES
connect_from_port_20=YES
nopriv_user=vsftpd
allow_writeable_chroot=YES
chroot_local_user=YES
#secure_chroot_dir=/var/run/vsftpd
pam_service_name=vsftpd
rsa_cert_file=/etc/ssl/certs/vsftpd.pem
guest_enable=YES
guest_username=vsftpd
#local_root=/home/vsftpd/$USER
#user_sub_token=$USER
virtual_use_local_privs=YES
pasv_promiscuous=YES
user_config_dir=/etc/vsftpd/vsftpd_user_conf
EOF

		mkdir -p /var/run/vsftpd;

		yes |mv /etc/pam.d/vsftpd /etc/pam.d/vsftpd.bak

		cat >>/etc/pam.d/vsftpd<<EOF
auth required pam_mysql.so user=vsftpd passwd=$mysql_vsftpd_password host=localhost db=ftpserver table=accounts usercolumn=username passwdcolumn=pass crypt=2
account required pam_mysql.so user=vsftpd passwd=$mysql_vsftpd_password host=localhost db=ftpserver table=accounts usercolumn=username passwdcolumn=pass crypt=2
EOF

		mkdir -p /etc/vsftpd/vsftpd_user_conf;

		rm -rf /etc/vsftpd/vsftpd_user_conf/$ftp_username
		cat >>/etc/vsftpd/vsftpd_user_conf/$ftp_username<<EOF
write_enable=YES
allow_writeable_chroot=YES
anon_world_readable_only=NO
anon_upload_enable=YES
anon_mkdir_write_enable=YES
anon_other_write_enable=YES
local_root=/
guest_username=apache
EOF


		sed -i "/mkdir -p \/var\/run\/vsftpd/d" /etc/rc.local
		sed -i "$ a mkdir -p \/var\/run\/vsftpd"  /etc/rc.local

		# 设置Selinux权限
		setsebool -P ftpd_connect_db 1;
		setsebool -P ftp_home_dir 1;
		setsebool -P tftp_home_dir 1;
		setsebool -P ftpd_full_access 1;
		setsebool -P allow_ftpd_anon_write 1;

		semanage port -a -t  ftp_port_t -p tcp 8342;
		firewall-cmd --permanent --zone=public --add-port=8342/tcp;
		firewall-cmd --permanent --zone=public --add-port=50000-60000/tcp;
		firewall-cmd --reload;

		systemctl enable vsftpd.service;
		systemctl restart vsftpd.service;

		echo "FTP installed success.";

		o_ftp_state=2;
	fi
}


function install_httpd()
{
	if [[ $o_http_state -eq 1 || $1 -eq 1 ]] && [[ $(service_test "httpd") -eq 0 ]]; then

		clear;

		echo "Install HTTP server..."

		input_host_name;

		yum -y install httpd httpd-devel php php-mysql php-gd php-ldap php-odbc php-pear php-xml php-xmlrpc php-mbstring php-snmp php-soap curl curl-devel php-mcrypt phpmyadmin;

		site_dir="/var/www/html";

		if [[ -n "$host_name" ]]; then
			site_dir="/var/www/$host_name"

			# 配置虚拟主机
			mkdir -p /etc/httpd/vhost-conf.d

			sed -i "/Include vhost-conf.d\/*.conf/d" /etc/httpd/conf/httpd.conf
			sed -i "$ a Include vhost-conf.d\/*.conf" /etc/httpd/conf/httpd.conf

			rm -rf /etc/httpd/vhost-conf.d/$host_name.conf

			cat >>/etc/httpd/vhost-conf.d/$host_name.conf<<EOF
NameVirtualHost *:80

<VirtualHost *:80>
   ServerName $host_name
   ServerAlias $host_name
   DocumentRoot $site_dir
   DirectoryIndex index.html index.php
</VirtualHost>
<Directory "$site_dir">
   Options +Includes -Indexes
   AllowOverride All
   Order Deny,Allow
   Allow from All
</Directory>

<Directory "$site_dir/downloads">
   Options Indexes FollowSymLinks
   AllowOverride All
   Order Deny,Allow
   Allow from All
</Directory>
EOF
		fi

		mkdir -p $site_dir;



		# 配置phpMyAdmin
		sed -i "s/Require ip 127.0.0.1/Require all granted/g" /etc/httpd/conf.d/phpMyAdmin.conf;
		sed -i "/Require ip ::1/d" /etc/httpd/conf.d/phpMyAdmin.conf;



		rm -rf $site_dir/index.php

		cat >>$site_dir/index.php<<EOF
<?php
	echo phpinfo();
?>
EOF

		mkdir -p $site_dir/downloads;
		echo "test" > $site_dir/downloads/test.txt;

		setenforce 0;

		# 添加防火墙
		firewall-cmd --permanent --zone=public --add-service=http
		firewall-cmd --permanent --zone=public --add-service=https
		firewall-cmd --reload

		setsebool -P allow_httpd_anon_write=1
  		setsebool -P httpd_enable_cgi 1
  		setsebool -P httpd_enable_homedirs 1
  		setsebool -P httpd_tty_comm 1
  		setsebool -P httpd_unified 0
  		setsebool -P httpd_can_network_connect 1

		# 启动服务
		systemctl enable httpd.service;
		systemctl restart httpd.service;

		setenforce 1;

		if [[ -n "$host_name" ]]; then
			semanage fcontext -a -t public_content_rw_t "/var/www/$host_name(/.*)?"
			restorecon -R -v /var/www/$host_name
		fi


		echo "HTTP server installed success."

		o_http_state=2;
	fi

}


function install_svn()
{
	if [[ $o_svn_state -eq 1 || $1 -eq 1 ]] && [[  $(command_test "svnadmin") -eq 0 ]] && [ ! -f "/etc/httpd/conf.d/httpd-svn.conf" ]; then

		install_mysql 1;

		install_httpd 1;

		echo "Start installing SVN...";

		yum install -y subversion mod_dav_svn mod_ssl openssl-devel  apr-util-mysql;

		 cp /usr/lib64/apr-util-1/apr_dbd_mysql.so /etc/httpd/modules/
		# 配置Apache

		rm -rf /etc/httpd/conf.d/httpd-svn.conf;

		cat >>/etc/httpd/conf.d/httpd-svn.conf<<EOF
DBDriver mysql
DBDParams "host=localhost port=3306 dbname=$svn_dbname user=$svn_dbuser pass=$mysql_svn_password"
DBDMin 1
DBDKeep 8
DBDMax 20
DBDExptime 200

<Location /svn_repos>
	DAV svn
  	SVNPath /var/svn/repos
  	AuthzSVNAccessFile /var/svn/repos/conf/authz

  	AuthType Basic
  	AuthName "SVN Repository"
  	AuthBasicProvider dbd
  	AuthDBDUserPWQuery "SELECT CONCAT('{SHA}', pass) FROM accounts WHERE username = %s"
  	Require valid-user
</Location>
EOF

		# 创建版本库
		mkdir -p /var/svn;

		rm -rf create /var/svn/repos;

		svnadmin create /var/svn/repos;

		cat >> /var/svn/repos/conf/authz <<EOF
[/]
$svn_username=rw
EOF

		chown -R apache.apache /var/svn/repos;

		semanage fcontext -a -t public_content_rw_t "/var/svn/repos(/.*)?";
		restorecon -R -v /var/svn/repos;

		# 创建数据库用户
		mysql -uroot -p$mysql_root_password -e "
			drop database if exists $svn_dbname;
			create database $svn_dbname;
			grant select,insert,update,delete,create,drop on $svn_dbname.* to '$svn_dbuser'@'localhost' identified by '$mysql_svn_password';
			grant select,insert,update,delete,create,drop on $svn_dbname.* to '$svn_dbuser'@'localhost.localdomain' identified by '$mysql_svn_password';
			flush privileges;

			use $svn_dbname;

			CREATE TABLE IF NOT EXISTS accounts (
				id INT NOT NULL AUTO_INCREMENT PRIMARY KEY ,
				username VARCHAR( 30 ) NOT NULL ,
				pass VARCHAR( 50 ) NOT NULL ,
				UNIQUE (username)
			) ENGINE = MYISAM ;

			insert into accounts(username,pass) values('$svn_username','$svn_password');
		";

		systemctl restart httpd.service;

		echo "SVN installed success.";

		o_svn_state=2;
	fi


}

function install_tomcat()
{
	if [[ $o_tomcat_state -eq 1 || $1 -eq 1  ]] && [[ $(service_test "tomcat") -eq 0 ]]; then

		clear;
		echo "Start installing TOMCAT...";
		input_host_name;

		# 下载解压文件
		if [[ ! -f "apache-tomcat-8.5.9.tar.gz" ]]; then
			wget -c http://mirror.bit.edu.cn/apache/tomcat/tomcat-8/v8.5.9/bin/apache-tomcat-8.5.9.tar.gz;
		fi

		rm -rf /var/local/apache-tomcat-8.5.9;
		rm -rf /var/local/tomcat;

		tar xzvf ./apache-tomcat-8.5.9.tar.gz -C /var/local;
		ln -s /var/local/apache-tomcat-8.5.9 /var/local/tomcat;

		#rm -rf ./apache-tomcat-8.5.9.tar.gz;

		# 添加防火墙
		firewall-cmd --permanent --zone=public --add-port=8080/tcp;
		firewall-cmd --reload;
		semanage port -a -t http_port_t -p tcp 8080;

		# 配置环境变量
		export TOMCAT_HOME=/var/local/tomcat;
		export CATALINA_HOME=$TOMCAT_HOME;
		export CATALINA_BASE=$CATALINA_HOME;
		sed -i '/export TOMCAT_HOME=\/var\/local\/tomcat/d' /etc/profile;
		sed -i '/export CATALINA_HOME=\$TOMCAT_HOME/d' /etc/profile;
		sed -i '/export CATALINA_BASE=\$CATALINA_HOME/d' /etc/profile;
		sed -i '$ a export TOMCAT_HOME=\/var\/local\/tomcat' /etc/profile;
		sed -i '$ a export CATALINA_HOME=\$TOMCAT_HOME' /etc/profile;
		sed -i '$ a export CATALINA_BASE=\$CATALINA_HOME' /etc/profile;
		source /etc/profile;

		# 增加服务配置
		getent group tomcat || groupadd -r tomcat;
		getent passwd tomcat || useradd -r -d $TOMCAT_HOME -s /bin/nologin -g tomcat tomcat;
		chown -R tomcat:tomcat $TOMCAT_HOME;
		chown -R tomcat:tomcat /var/local/apache-tomcat-8.5.9;
		chmod -R ug+rwx /var/local/apache-tomcat-8.5.9;


		cat >>$TOMCAT_HOME/bin/setenv.sh<<EOF
#add tomcat pid
CATALINA_PID="$TOMCAT_HOME/tomcat.pid"
#add java opts
JAVA_OPTS="-server -XX:PermSize=256M -XX:MaxPermSize=1024m -Xms512M -Xmx1024M -XX:MaxNewSize=256m"

EOF

		rm -rf /lib/systemd/system/tomcat.service;
		cat >>/lib/systemd/system/tomcat.service<<EOF
[Unit]
Description=Apache Tomcat 8
After=syslog.target network.target

[Service]
Type=forking
PIDFile=$TOMCAT_HOME/tomcat.pid

Environment=JAVA_HOME=$JAVA_HOME
Environment=CATALINA_PID=$TOMCAT_HOME/tomcat.pid
Environment=CATALINA_HOME=$TOMCAT_HOME
Environment=CATALINA_BASE=$TOMCAT_HOME
Environment='CATALINA_OPTS=-Xms512M -Xmx1024M -server -XX:+UseParallelGC'
Environment='JAVA_OPTS=-Djava.awt.headless=true -Djava.security.egd=file:/dev/./urandom'

ExecStart=$TOMCAT_HOME/bin/startup.sh
ExecReload=/bin/kill -s HUP $MAINPID
ExecStop=/bin/kill -s QUIT $MAINPID
PrivateTmp=true

User=tomcat
Group=tomcat

[Install]
WantedBy=multi-user.target
EOF

		site_home="/var/www/tomcat/default";

		# 修改配置文件
		if [[ -n "$host_name" ]]; then
			site_home="/var/www/tomcat/$host_name";

			tmpfile="/tmp/$RANDOM";
			cat >>$tmpfile<<EOF
      <Host name="$host_name" debug="0" appBase="$site_home" unpackWARs="true" autoDeploy="true">
      	<Alias>$host_name</Alias>
      	<Context path="/" docBase="$site_home"></Context>
      </Host>
EOF

			sed -i "/<Engine[[:space:]]*name=\"Catalina\"[[:space:]]*defaultHost=\"localhost\">/r $tmpfile" $TOMCAT_HOME/conf/server.xml;
			rm -rf $tmpfile;
		else
			sed -i "/[[:space:]]*unpackWARs=\"true\" autoDeploy=\"true\">/a \        <Context path=\"/\" docBase=\"$site_home\"></Context>" $TOMCAT_HOME/conf/server.xml;
		fi


		if [[ ! -d "$site_home" ]]; then
			mkdir -p $site_home;
		fi

		# 生产Hello world

		rm -rf $site_home/index.jsp;

		cat >>$site_home/index.jsp<<EOF
<%@ page language="java" import="java.util.*" pageEncoding="UTF-8"%>
<%
String path = request.getContextPath();
String basePath = request.getScheme()+"://"+request.getServerName()+":"+request.getServerPort()+path+"/";
%>
<!doctype html>
<html>
<head>
<meta charset="UTF-8">
<title>Hello World</title>
</head>

<body>
	<%
    	out.println("Hello world!");
    %>
</body>
</html>
EOF

		chown -R tomcat:tomcat $site_home;
		chmod -R ug+rw $site_home/*;

		semanage fcontext -a -t public_content_rw_t "$site_home(/.*)?"
		restorecon -R -v $site_home;

		if [[ $http_proxy_tomcat -eq 1 ]]; then

			install_httpd 1;

			if [[ -n "$host_name" ]]; then
				sed -i "/ProxyPassMatch \^\/svn_repos\/ \!\//d" /etc/httpd/vhost-conf.d/$host_name.conf
				sed -i "/ProxyPass \/ http:\/\/$host_name:8080\//d" /etc/httpd/vhost-conf.d/$host_name.conf
				sed -i "/ProxyPassReverse \/ http:\/\/$host_name:8080\//d" /etc/httpd/vhost-conf.d/$host_name.conf
				sed -i "s/DirectoryIndex index.html index.php.*/DirectoryIndex index.html index.php index.jsp\n\   ProxyPassMatch \^\/svn_repos\/ \!\n\   ProxyPass \/ http:\/\/$host_name:8080\/\n\   ProxyPassReverse \/ http:\/\/$host_name:8080\//" /etc/httpd/vhost-conf.d/$host_name.conf

			else
				sed -i "/ProxyPassMatch \^\/svn_repos\/ \!\//d" /etc/httpd/conf/httpd.conf
				sed -i "/ProxyPass \/ http:\/\/127.0.0.1:8080\//d" /etc/httpd/conf/httpd.conf
				sed -i "/ProxyPassReverse \/ http:\/\/127.0.0.1:8080\//d" /etc/httpd/conf/httpd.conf
				cat >>/etc/httpd/conf/httpd.conf<<EOF
ProxyPassMatch ^/svn_repos/ !
ProxyPass / http://127.0.0.1:8080/
ProxyPassReverse / http://127.0.0.1:8080/
EOF
			fi

			systemctl restart httpd.service
		fi

		# 启动服务
		systemctl daemon-reload;
		systemctl enable tomcat.service;
		systemctl restart tomcat.service;

		o_tomcat_state=2;

		echo "TOMCAT installed success.";
	fi
}

function install_oracle12c()
{
	# http://m.blog.itpub.net/29047826/viewspace-1422559/
	#
	if [[ $o_oracle_state -eq 1 || $1 -eq 1 ]] && [[ $(service_test "oracle") -eq 0 ]]; then

		clear;
		echo "Start installing Oracle...";

		input_oracle_password;

		oracle_sid="orcl12c"

		setenforce 0;

		# Create required OS users and groups for Oracle Database.
		getent group oinstall || groupadd oinstall;
		getent group dba || groupadd dba;
		getent passwd oracle || useradd -g oinstall -G dba oracle;
		echo "$oracle_password" | passwd --stdin oracle;

		# Add kernel parameters
		sed -i "/fs\.aio-max-nr[[:space:]]*=.*/d" /etc/sysctl.conf;
		sed -i "/fs\.file-max[[:space:]]*=.*/d" /etc/sysctl.conf;
		sed -i "/kernel\.shmall[[:space:]]*=.*/d" /etc/sysctl.conf;
		sed -i "/kernel\.shmmax[[:space:]]*=.*/d" /etc/sysctl.conf;
		sed -i "/kernel\.shmmni[[:space:]]*=.*/d" /etc/sysctl.conf;
		sed -i "/kernel\.sem[[:space:]]*=.*/d" /etc/sysctl.conf;
		sed -i "/net\.ipv4\.ip_local_port_range[[:space:]]*=.*/d" /etc/sysctl.conf;
		sed -i "/net\.core\.rmem_default[[:space:]]*=.*/d" /etc/sysctl.conf;
		sed -i "/net\.core\.rmem_max[[:space:]]*=.*/d" /etc/sysctl.conf;
		sed -i "/net\.core\.wmem_default[[:space:]]*=.*/d" /etc/sysctl.conf;
		sed -i "/net\.core\.wmem_max[[:space:]]*=.*/d" /etc/sysctl.conf;

		cat >>/etc/sysctl.conf<<EOF
fs.aio-max-nr = 1048576
fs.file-max = 6815744
kernel.shmall = 2097152
kernel.shmmax = 4398046511104
kernel.shmmni = 4096
kernel.sem = 250 32000 100 128
net.ipv4.ip_local_port_range = 9000 65500
net.core.rmem_default = 262144
net.core.rmem_max = 4194304
net.core.wmem_default = 262144
net.core.wmem_max = 1048586
EOF
		sysctl -p;
		#sysctl -a;

		# Specify limits for oracle user
		sed -i "/^oracle.*/d" /etc/security/limits.conf;
		cat >>/etc/security/limits.conf<<EOF
oracle   soft   nofile   	131072
oracle   hard   nofile   	131072
oracle   soft   nproc    	131072
oracle   hard   nproc    	131072
oracle   soft   memlock    	50000000
oracle   hard   memlock    	50000000
oracle   soft   core     	unlimited
oracle   hard   core     	unlimited
EOF



		#sed -i "/.*pam_limits.so/ d" /etc/pam.d/login;
		#cat >>/etc/pam.d/login<<EOF
#session    required     /lib64/security/pam_limits.so 
#session    required     pam_limits.so 
#EOF

		# Download install file
		if [[ ! -f "linuxamd64_12102_database_1of2.zip" ]]; then
			#wget -N http://192.168.1.168/Tools/Database/Oracle/linuxamd64_12102_database_1of2.zip
			wget -N http://xieguoliang.com/downloads/linuxamd64_12102_database_1of2.zip
		fi
		if [[ ! -f "linuxamd64_12102_database_2of2.zip" ]]; then
			#wget -N http://192.168.1.168/Tools/Database/Oracle/linuxamd64_12102_database_2of2.zip
			wget -N http://xieguoliang.com/downloads/linuxamd64_12102_database_2of2.zip
		fi

		rm -rf /stage;

		unzip linuxamd64_12102_database_1of2.zip -d /stage/
		unzip linuxamd64_12102_database_2of2.zip -d /stage/


		# Install required packages:
		yum install -y binutils.x86_64 compat-libcap1.x86_64 gcc.x86_64 gcc-c++.x86_64 glibc.i686 glibc.x86_64 glibc-devel.i686 glibc-devel.x86_64 ksh compat-libstdc++-33 libaio.i686 libaio.x86_64 libaio-devel.i686 libaio-devel.x86_64 libgcc.i686 libgcc.x86_64 libstdc++.i686 libstdc++.x86_64 libstdc++-devel.i686 libstdc++-devel.x86_64 libXi.i686 libXi.x86_64 libXtst.i686 libXtst.x86_64 make.x86_64 sysstat.x86_64  glibc-headers  unixODBC unixODBC-devel  zlib-devel;

		# 设置环境变量

		oracle_dir="/oracle/12c";
		export ORACLE_BASE=$oracle_dir/db_base

		rm -rf $oracle_dir;
		mkdir -p $ORACLE_BASE

		chown -R oracle:oinstall $oracle_dir;
		chmod -R ug+rwx $oracle_dir;

		export ORACLE_HOME=$ORACLE_BASE/db_home
		export ORACLE_SID=$oracle_sid;
		export ORACLE_OWNER=oracle
		export PATH=$ORACLE_HOME/bin:$PATH
		export LD_LIBRARY_PATH=$ORACLE_HOME/lib:/lib:/usr/lib:/usr/lib64;
		export CLASSPATH=$ORACLE_HOME/jlib:$ORACLE_HOME/rdbms/jlib

		sed -i "/######## Start Limit Oracle #########/,/######## End Limit Oracle #########/d" /etc/profile;
		sed -i "/export ORACLE_BASE=.*/d" /etc/profile;
		sed -i "/export ORACLE_HOME=.*/d" /etc/profile;
		sed -i "/export ORACLE_SID=.*/d" /etc/profile;
		sed -i "/export ORACLE_OWNER=.*/d" /etc/profile;
		sed -i "/export PATH=\$ORACLE_HOME\/bin:\$PATH/d" /etc/profile;
		sed -i "/export LD_LIBRARY_PATH=.*/d" /etc/profile;
		sed -i "/CLASSPATH=\$ORACLE_HOME\/jlib.*/d" /etc/profile;

		cat >>/etc/profile<<EOF
######## Start Limit Oracle #########
if [ "\$USER" = "oracle" ]; then
	if [ "\$SHELL" = "/bin/ksh" ]; then
		ulimit -p 16384
		ulimit -n 65536
	else
		ulimit -u 16384 -n 65536
	fi
fi
######## End Limit Oracle #########

export ORACLE_BASE=$oracle_dir/db_base
export ORACLE_HOME=\$ORACLE_BASE/db_home
export ORACLE_SID=$oracle_sid
export ORACLE_OWNER=oracle
export PATH=\$ORACLE_HOME/bin:\$PATH
export LD_LIBRARY_PATH=\$ORACLE_HOME/lib:/lib:/usr/lib:/usr/lib64
export CLASSPATH=\$ORACLE_HOME/jlib:\$ORACLE_HOME/rdbms/jlib
EOF
		source /etc/profile;

		# 生成安装文件

		rm -rf /stage/database/db_install.rsp;
		cat >>/stage/database/db_install.rsp<<EOF
oracle.install.responseFileVersion=/oracle/install/rspfmt_dbinstall_response_schema_v12.1.0
oracle.install.option=INSTALL_DB_SWONLY
ORACLE_HOSTNAME=localhost
UNIX_GROUP_NAME=oinstall
INVENTORY_LOCATION=$oracle_dir/oraInventory
SELECTED_LANGUAGES=en
ORACLE_HOME=$oracle_dir/db_base/db_home
ORACLE_BASE=$oracle_dir/db_base
oracle.install.db.InstallEdition=EE
oracle.install.db.DBA_GROUP=dba
oracle.install.db.OPER_GROUP=dba
oracle.install.db.BACKUPDBA_GROUP=dba
oracle.install.db.DGDBA_GROUP=dba
oracle.install.db.KMDBA_GROUP=dba
oracle.install.db.config.starterdb.characterSet=AL32UTF8
oracle.install.db.config.starterdb.installExampleSchemas=false
oracle.install.db.config.starterdb.password.ALL=$oracle_password
oracle.install.db.config.starterdb.password.SYS=$oracle_password
oracle.install.db.config.starterdb.password.SYSTEM=$oracle_password
oracle.install.db.config.starterdb.password.DBSNMP=$oracle_password
oracle.install.db.config.starterdb.password.PDBADMIN=$oracle_password
SECURITY_UPDATES_VIA_MYORACLESUPPORT=false
DECLINE_SECURITY_UPDATES=true

EOF

		chown -R oracle:oinstall /stage/
		chmod -R ug+rwx /stage/

		# 运行安装

		mkdir -p /etc/oracle;
   		chown -R oracle:oinstall /etc/oracle;
   		chmod -R ug+rwx /etc/oracle;
		echo "Install is in progress,please wait...";
		return;

		RUN_INSTALL=$(expect -c "
			set timeout 300;
			spawn su - oracle -c \"/stage/database/runInstaller -silent -ignorePrereq -debug -showProgress -responseFile /stage/database/db_install.rsp\"
			expect \"100% Done.\"
			expect eof
		");

		echo "$RUN_INSTALL"
		if [[ $(echo $RUN_INSTALL | grep "100% Done."|wc -l) -eq 1 ]]; then
			echo "Install finish."

			if [[ -f "$oracle_dir/oraInventory/orainstRoot.sh" ]]; then
				$oracle_dir/oraInventory/orainstRoot.sh
			fi
			if [[ -f "$oracle_dir/db_base/db_home/root.sh" ]]; then
				$oracle_dir/db_base/db_home/root.sh;
			fi

			# 添加防火墙
			firewall-cmd --zone=public --add-port=1521/tcp --add-port=5500/tcp --add-port=5520/tcp --add-port=3938/tcp --permanent
			firewall-cmd --reload;

			# NETCA
			rm -rf /stage/database/netca.rsp
			cat >>/stage/database/netca.rsp<<EOF
GENERAL]
RESPONSEFILE_VERSION="12.1"
CREATE_TYPE="CUSTOM"

[oracle.net.ca]
INSTALLED_COMPONENTS={"server","net8","javavm"}
INSTALL_TYPE=""typical""
LISTENER_NUMBER=1
LISTENER_NAMES={"LISTENER"}

LISTENER_PROTOCOLS={"TCP;1521"}

LISTENER_START=""LISTENER""

NAMING_METHODS={"TNSNAMES","ONAMES","HOSTNAME"}

NSN_NUMBER=1
NSN_NAMES={"EXTPROC_CONNECTION_DATA"}
NSN_SERVICE={"PLSExtProc"}
NSN_PROTOCOLS={"TCP;HOSTNAME;1521"}

EOF
			# 建库
			gdbname="$oracle_sid.localhost";
			if [[ -n "$host_name" ]]; then
				gdbname="$oracle_sid.$host_name";
			fi

			rm -rf /stage/database/dbca.rsp
			cat >>/stage/database/dbca.rsp<<EOF
[GENERAL]
RESPONSEFILE_VERSION = "12.1.0"
OPERATION_TYPE = "createDatabase"
[CREATEDATABASE]
GDBNAME = "$gdbname"
#DATABASECONFTYPE  = "SI"
#RACONENODESERVICENAME =
#POLICYMANAGED = "false"
#CREATESERVERPOOL = "false"
#SERVERPOOLNAME =
#CARDINALITY =
#FORCE = "false"
#PQPOOLNAME =
#PQCARDINALITY =
SID = "$oracle_sid"
#CREATEASCONTAINERDATABASE =
#NUMBEROFPDBS =
#PDBNAME =
# PDBADMINPASSWORD = ""
#NODELIST=
TEMPLATENAME = "General_Purpose.dbc"
#OBFUSCATEDPASSWORDS = FALSE
SYSPASSWORD = "$oracle_password"
SYSTEMPASSWORD = "$oracle_password"
#SERVICEUSERPASSWORD = "$oracle_password"
EMCONFIGURATION = "NONE"
#EMEXPRESSPORT = ""
#RUNCVUCHECKS = FALSE
#DBSNMPPASSWORD = "password"
#OMSHOST =
#OMSPORT =
#EMUSER =
#EMPASSWORD=
#DVCONFIGURATION = "false"
#DVOWNERNAME = ""
#DVOWNERPASSWORD = ""
#DVACCOUNTMANAGERNAME = ""
#DVACCOUNTMANAGERPASSWORD = ""
#OLSCONFIGURATION = "false"
#DATAFILEJARLOCATION =
#DATAFILEDESTINATION =
#RECOVERYAREADESTINATION=
#STORAGETYPE=FS
#DISKGROUPNAME=DATA
#ASMSNMP_PASSWORD=""
#RECOVERYGROUPNAME=RECOVERY
CHARACTERSET = "AL32UTF8"
NATIONALCHARACTERSET= "UTF8"
#REGISTERWITHDIRSERVICE= TRUE
#DIRSERVICEUSERNAME= "name"
#DIRSERVICEPASSWORD= "password"
#WALLETPASSWORD= "password"
#LISTENERS = "listener1,listener2"
#VARIABLESFILE =
#VARIABLES =
#INITPARAMS =
#SAMPLESCHEMA=TRUE
#MEMORYPERCENTAGE = "40"
#DATABASETYPE = "MULTIPURPOSE"
#AUTOMATICMEMORYMANAGEMENT = "TRUE"
#TOTALMEMORY = "800"
EOF

			echo "Create database is in progress,please wait...";

			su - oracle -c "$ORACLE_HOME/bin/netca -silent -responseFile /stage/database/netca.rsp"

			su - oracle -c "$ORACLE_HOME/bin/dbca -silent -responseFile /stage/database/dbca.rsp"

			if [[ -f "/etc/oratab" ]]; then
				sed -i "/$oracle_sid:.*/d" /etc/oratab
			fi

			chown -R oracle:oinstall /etc/oratab
			chmod ug+rw /etc/oratab
			sed -i "$ a $oracle_sid:$ORACLE_HOME:Y" /etc/oratab



			setenforce 1;
			o_oracle_state=2;

			echo "Oracle installed success.";
		else
			echo "Oracle installed failure.";
		fi
	fi
}

function install_oracle11gr2()
{
	if [[ $o_oracle_state -eq 1 || $1 -eq 1 ]] && [[ $(service_test "oracledb") -eq 0 ]]; then

		clear;
		echo "Start installing Oracle 11G R2...";

		input_oracle_password;

		oracle_sid="orcl11g"

		setenforce 0;

		# Create required OS users and groups for Oracle Database.
		getent group oinstall || groupadd oinstall;
		getent group dba || groupadd dba;
		getent passwd oracle || useradd -g oinstall -G dba oracle;
		echo "$oracle_password" | passwd --stdin oracle;

		# Add kernel parameters
		sed -i "/fs\.aio-max-nr[[:space:]]*=.*/d" /etc/sysctl.conf;
		sed -i "/fs\.file-max[[:space:]]*=.*/d" /etc/sysctl.conf;
		sed -i "/kernel\.shmall[[:space:]]*=.*/d" /etc/sysctl.conf;
		sed -i "/kernel\.shmmax[[:space:]]*=.*/d" /etc/sysctl.conf;
		sed -i "/kernel\.shmmni[[:space:]]*=.*/d" /etc/sysctl.conf;
		sed -i "/kernel\.sem[[:space:]]*=.*/d" /etc/sysctl.conf;
		sed -i "/net\.ipv4\.ip_local_port_range[[:space:]]*=.*/d" /etc/sysctl.conf;
		sed -i "/net\.core\.rmem_default[[:space:]]*=.*/d" /etc/sysctl.conf;
		sed -i "/net\.core\.rmem_max[[:space:]]*=.*/d" /etc/sysctl.conf;
		sed -i "/net\.core\.wmem_default[[:space:]]*=.*/d" /etc/sysctl.conf;
		sed -i "/net\.core\.wmem_max[[:space:]]*=.*/d" /etc/sysctl.conf;

		cat >>/etc/sysctl.conf<<EOF
fs.aio-max-nr = 1048576
fs.file-max = 6815744
kernel.shmall = 2097152
kernel.shmmax = 4398046511104
kernel.shmmni = 4096
kernel.sem = 250 32000 100 128
net.ipv4.ip_local_port_range = 9000 65500
net.core.rmem_default = 262144
net.core.rmem_max = 4194304
net.core.wmem_default = 262144
net.core.wmem_max = 1048586
EOF
		sysctl -p;
		#sysctl -a;

		# Specify limits for oracle user
		sed -i "/^oracle.*/d" /etc/security/limits.conf;
		cat >>/etc/security/limits.conf<<EOF
oracle   soft   nofile   	1024
oracle   hard   nofile   	65536
oracle   soft   nproc    	2047
oracle   hard   nproc    	16384
oracle   soft   stack   	10240
EOF



		#sed -i "/.*pam_limits.so/ d" /etc/pam.d/login;
		#cat >>/etc/pam.d/login<<EOF
#session    required     /lib64/security/pam_limits.so 
#session    required     pam_limits.so 
#EOF

		# Download install file
		if [[ ! -f "linux.x64_11gR2_database_1of2.zip" ]]; then
			#wget -N http://192.168.1.168/Tools/Database/Oracle/linux.x64_11gR2_database_1of2.zip
			wget -N http://xieguoliang.com/downloads/linux.x64_11gR2_database_1of2.zip
		fi
		if [[ ! -f "linux.x64_11gR2_database_2of2.zip" ]]; then
			#wget -N http://192.168.1.168/Tools/Database/Oracle/linux.x64_11gR2_database_2of2.zip
			wget -N http://xieguoliang.com/downloads/linux.x64_11gR2_database_2of2.zip
		fi

		rm -rf /stage;

		unzip linux.x64_11gR2_database_1of2.zip -d /stage/
		unzip linux.x64_11gR2_database_2of2.zip -d /stage/


		# Install required packages:
		yum install -y binutils.x86_64 compat-libcap1.x86_64 gcc.x86_64 gcc-c++.x86_64 glibc.i686 glibc.x86_64 glibc-devel.i686 glibc-devel.x86_64 ksh compat-libstdc++-33 libaio.i686 libaio.x86_64 libaio-devel.i686 libaio-devel.x86_64 libgcc.i686 libgcc.x86_64 libstdc++.i686 libstdc++.x86_64 libstdc++-devel.i686 libstdc++-devel.x86_64 libXi.i686 libXi.x86_64 libXtst.i686 libXtst.x86_64 make.x86_64 sysstat.x86_64  glibc-headers  unixODBC unixODBC-devel  zlib-devel elfutils-libelf-devel elfutils-libelf-devel-static numactl-devel pcre-devel;

		# 设置环境变量

		oracle_dir="/oracle/11g";
		oracle_hostname=$(hostname);
		export ORACLE_BASE=$oracle_dir/db_base

		rm -rf $oracle_dir;
		mkdir -p $ORACLE_BASE

		chown -R oracle:oinstall $oracle_dir;
		chmod -R ug+rwx $oracle_dir;

		export ORACLE_HOME=$ORACLE_BASE/db_home
		export ORACLE_SID=$oracle_sid;
		export ORACLE_OWNER=oracle
		export PATH=$ORACLE_HOME/bin:$PATH
		export LD_LIBRARY_PATH=$ORACLE_HOME/lib:/lib:/usr/lib:/usr/lib64;
		export CLASSPATH=$CLASSPATH:$ORACLE_HOME/jlib:$ORACLE_HOME/rdbms/jlib

		sed -i "/######## Start Limit Oracle #########/,/######## End Limit Oracle #########/d" /etc/profile;
		sed -i "/export ORACLE_BASE=.*/d" /etc/profile;
		sed -i "/export ORACLE_HOME=.*/d" /etc/profile;
		sed -i "/export ORACLE_SID=.*/d" /etc/profile;
		sed -i "/export ORACLE_OWNER=.*/d" /etc/profile;
		sed -i "/export PATH=\$ORACLE_HOME\/bin:\$PATH/d" /etc/profile;
		sed -i "/export LD_LIBRARY_PATH=.*/d" /etc/profile;
		sed -i "/export CLASSPATH=\$CLASSPATH:\$ORACLE_HOME\/jlib.*/d" /etc/profile;

		cat >>/etc/profile<<EOF
######## Start Limit Oracle #########
if [ \$USER = "oracle" ]; then
	if [ \$SHELL = "/bin/ksh" ]; then
		ulimit -p 16384
		ulimit -n 65536
	else
		ulimit -u 16384 -n 65536
	fi
fi
######## End Limit Oracle #########

export ORACLE_BASE=$oracle_dir/db_base
export ORACLE_HOME=\$ORACLE_BASE/db_home
export ORACLE_SID=$oracle_sid
export ORACLE_OWNER=oracle
export PATH=\$ORACLE_HOME/bin:\$PATH
export LD_LIBRARY_PATH=\$ORACLE_HOME/lib:/lib:/usr/lib:/usr/lib64
export CLASSPATH=\$CLASSPATH:\$ORACLE_HOME/jlib:\$ORACLE_HOME/rdbms/jlib
EOF
		source /etc/profile;

		# 生成安装文件

		rm -rf /stage/database/db_install.rsp;
		cat >>/stage/database/db_install.rsp<<EOF
oracle.install.responseFileVersion=/oracle/install/rspfmt_dbinstall_response_schema_v11_2_0
oracle.install.option=INSTALL_DB_SWONLY
ORACLE_HOSTNAME=$oracle_hostname
UNIX_GROUP_NAME=oinstall
INVENTORY_LOCATION=$oracle_dir/oraInventory
SELECTED_LANGUAGES=en,zh_CN
ORACLE_HOME=$oracle_dir/db_base/db_home
ORACLE_BASE=$oracle_dir/db_base
oracle.install.db.InstallEdition=EE
oracle.install.db.isCustomInstall=false
oracle.install.db.DBA_GROUP=dba
oracle.install.db.OPER_GROUP=dba
oracle.install.db.config.starterdb.type=GENERAL_PURPOSE
oracle.install.db.config.starterdb.globalDBName=$oracle_sid
oracle.install.db.config.starterdb.SID=$oracle_sid
oracle.install.db.config.starterdb.characterSet=AL32UTF8
oracle.install.db.config.starterdb.password.ALL=$oracle_password
SECURITY_UPDATES_VIA_MYORACLESUPPORT=false
DECLINE_SECURITY_UPDATES=true
EOF

		chown -R oracle:oinstall /stage/
		chmod -R ug+rwx /stage/

		# 运行安装

		mkdir -p /etc/oracle;
   		chown -R oracle:oinstall /etc/oracle;
   		chmod -R ug+rwx /etc/oracle;
		echo "Install is in progress,please wait...";


		RUN_INSTALL=$(expect -c "
			set timeout -1;
			spawn su - oracle -c \"/stage/database/runInstaller -silent -ignorePreReq -force -responseFile /stage/database/db_install.rsp\"
			expect \"You can find the log of this install session at:\"
			expect eof
			exit
		");

		echo "$RUN_INSTALL"

		logfile=$(echo "$RUN_INSTALL" |grep -w "$oracle_dir/oraInventory/logs/installActions[[:graph:]]*.log" |awk -v oracle_dir=$oracle_dir 'NR==1{print substr($0,index($0,oracle_dir),index($0,".log")-index($0,oracle_dir) + 4)}');
		echo "Log file is $logfile."
		clear;
		sleep 3;

		if [[ -n "$logfile" ]]; then
			INSTALL_LOG=$(expect -c "
				set timeout 600
				spawn tail -f "$logfile"
				expect \"Shutdown Oracle Database 11g Release 2 Installer\"
				expect eof
				exit
			");
			echo $INSTALL_LOG;

			echo "Install finish."

			if [[ -f "$oracle_dir/oraInventory/orainstRoot.sh" ]]; then
				$oracle_dir/oraInventory/orainstRoot.sh
			fi
			if [[ -f "$oracle_dir/db_base/db_home/root.sh" ]]; then
				$oracle_dir/db_base/db_home/root.sh;
			fi

			# 添加防火墙
			firewall-cmd --zone=public --add-port=1521/tcp --add-port=5500/tcp --add-port=5520/tcp --add-port=3938/tcp --permanent
			firewall-cmd --reload;

			# NETCA
			rm -rf /stage/database/netca.rsp
			cat >>/stage/database/netca.rsp<<EOF
[GENERAL]
RESPONSEFILE_VERSION="11.2"
CREATE_TYPE="CUSTOM"

[oracle.net.ca]
INSTALLED_COMPONENTS={"server","net8","javavm"}
INSTALL_TYPE=""typical""
LISTENER_NUMBER=1
LISTENER_NAMES={"LISTENER"}
LISTENER_PROTOCOLS={"TCP;1521"}
LISTENER_START=""LISTENER""
NAMING_METHODS={"TNSNAMES","ONAMES","HOSTNAME"}
NSN_NUMBER=1
NSN_NAMES={"EXTPROC_CONNECTION_DATA"}
NSN_SERVICE={"PLSExtProc"}
NSN_PROTOCOLS={"TCP;HOSTNAME;1521"}

EOF
			# 建库
			gdbname="$oracle_sid.localhost";
			if [[ -n "$host_name" ]]; then
				gdbname="$oracle_sid.$host_name";
			fi

			rm -rf /stage/database/dbca.rsp
			cat >>/stage/database/dbca.rsp<<EOF
[GENERAL]
RESPONSEFILE_VERSION = "11.2.0"
OPERATION_TYPE = "createDatabase"

[CREATEDATABASE]
GDBNAME = "$oracle_sid"
SID = "$oracle_sid"
TEMPLATENAME = "General_Purpose.dbc"
SYSPASSWORD = "$oracle_password"
SYSTEMPASSWORD = "$oracle_password"
CHARACTERSET = "AL32UTF8"
NATIONALCHARACTERSET= "UTF8"
EOF

			echo "Create database is in progress,please wait...";


			if [[ -f "/etc/oratab" ]]; then
				sed -i "/$oracle_sid:.*/d" /etc/oratab
			fi

			su - oracle -c "$ORACLE_HOME/bin/netca /silent /responseFile /stage/database/netca.rsp"

			rm -rf $ORACLE_HOME/network/admin/listener.ora;
			cat>>$ORACLE_HOME/network/admin/listener.ora<<EOF
# listener.ora Network Configuration File: $ORACLE_HOME/network/admin/listener.ora
# Generated by Oracle configuration tools.

SID_LIST_LISTENER =
  (SID_LIST =
    (SID_DESC =
      (GLOBAL_DBNAME = $oracle_sid)
      (ORACLE_HOME = $ORACLE_HOME)
      (SID_NAME = $oracle_sid)
    )
  )

LISTENER =
  (DESCRIPTION_LIST =
    (DESCRIPTION =
      (ADDRESS = (PROTOCOL = IPC)(KEY = EXTPROC1521))
      (ADDRESS = (PROTOCOL = TCP)(HOST = localhost)(PORT = 1521))
    )
  )

ADR_BASE_LISTENER = $ORACLE_BASE
EOF
			# 建库
			su - oracle -c "$ORACLE_HOME/bin/dbca -silent -responseFile /stage/database/dbca.rsp"

			# 创建服务
			cat>>$ORACLE_HOME/bin/oracledb<<EOF
#!/bin/bash

export ORACLE_BASE=$ORACLE_BASE
export ORACLE_HOME=$ORACLE_HOME
export ORACLE_OWNR=oracle
export PATH=\$PATH:\$ORACLE_HOME/bin

if [ ! -f \$ORACLE_HOME/bin/dbstart -o ! -d \$ORACLE_HOME ]; then
	echo "Oracle startup: cannot start"
	exit 1
fi

case "\$1" in
        start)
                # Oracle listener and instance startup
                echo -n "Starting Oracle: "
                if [[ \$USER = \$ORACLE_OWNR ]]; then
                        \$ORACLE_HOME/bin/lsnrctl start
                        \$ORACLE_HOME/bin/dbstart \$ORACLE_HOME
                        \$ORACLE_HOME/bin/emctl start dbconsole
                else
                        su \$ORACLE_OWNR -c "\$ORACLE_HOME/bin/lsnrctl start"
                        su \$ORACLE_OWNR -c "\$ORACLE_HOME/bin/dbstart \$ORACLE_HOME"
                        su \$ORACLE_OWNR -c "\$ORACLE_HOME/bin/emctl start dbconsole"
                fi
                touch /var/lock/oracle
                echo "OK"
                ;;
        stop)
                # Oracle listener and instance shutdown
                echo -n "Shutdown Oracle: "
                if [[ \$USER = \$ORACLE_OWNR ]]; then
                        \$ORACLE_HOME/bin/emctl stop dbconsole
                        \$ORACLE_HOME/bin/lsnrctl stop
                        \$ORACLE_HOME/bin/dbshut \$ORACLE_HOME
                else
                        su \$ORACLE_OWNR -c "\$ORACLE_HOME/bin/emctl stop dbconsole"
                        su \$ORACLE_OWNR -c "\$ORACLE_HOME/bin/lsnrctl stop"
                        su \$ORACLE_OWNR -c "\$ORACLE_HOME/bin/dbshut \$ORACLE_HOME"
                fi
                rm -f /var/lock/oracle
                echo "OK"
                ;;
        reload|restart)
                \$0 stop
                \$0 start
                ;;
        *)
                echo "Usage: centos.sh start|stop|restart|reload"
                exit 1
esac

exit 0
EOF

			rm -rf /etc/sysconfig/oracledb;
			cat >>/etc/sysconfig/oracledb<<EOF
ORACLE_BASE=$ORACLE_BASE
ORACLE_HOME=$ORACLE_HOME
ORACLE_SID=$oracle_sid
EOF
			chown -R oracle:dba /etc/sysconfig/oracledb
			chmod ug+rwx /etc/sysconfig/oracledb

			rm -rf /usr/lib/systemd/system/oracledb.service;
			cat >>/usr/lib/systemd/system/oracledb.service<<EOF
[Unit]
Description=Oracle Service
After=network.target

[Service]
Type=forking
EnvironmentFile=/etc/sysconfig/oracledb
ExecStart=$ORACLE_HOME/bin/oracledb start
ExecStop=$ORACLE_HOME/bin/oracledb stop
User=oracle

[Install]
WantedBy=multi-user.target

EOF


			sed -i "$ a $oracle_sid:$ORACLE_HOME:Y" /etc/oratab

			chown -R oracle:dba /etc/oratab
			chmod ug+rw /etc/oratab

			chown -R oracle:dba $oracle_dir;
			chmod -R ug+rwx $oracle_dir;

			setenforce 1;

			# 启动服务
			systemctl daemon-reload;
			systemctl enable oracledb.service;

			chmod 777 /var/tmp/.oracle

			#emca -config dbcontrol db

			systemctl restart oracledb.service;

			o_oracle_state=2;

			echo "Oracle installed success.";
		else
			echo "Oracle installed failure.";
		fi
	fi
}

function install_cobbler()
{
	if [[ $o_cobbler_state -eq 1 || $1 -eq 1 ]] && [[ $(service_test "cobblerd") -eq 0 ]]; then

		clear;
		echo "Start installing Cobbler...";

		install_httpd 1;

		# Install
		yum install -y cobbler cobbler-web dnsmasq syslinux pykickstart dhcp tftp-server tftp bind xinetd fence-agents;
		#yum install -y perl-libwww perl-Compress-Zlib perl-Digest-SHA1 perl-Net* rsync perl-LockFile-Simple perl-Digest-MD5-M4p;
		#yum install system-config-kickstart
   		#system-config-kickstart
		#wget http://archive.ubuntu.com/ubuntu/pool/universe/d/debmirror/debmirror_2.10ubuntu1.tar.gz
		#tar -xzvf debmirror_2.10ubuntu1.tar.gz
		#cd debmirror-2.10ubuntu1
		#make
		#cp debmirror /usr/local/bin/
		#cp debmirror.1 /usr/share/man/man1/
		#cpan install Net::INET6Glue
		# Okay, debmirror now works, but needs that wrapper script:
		#(ubuntu_mirror.sh)
		# #!/bin/bash
		# arch=amd64
		# section=main,restricted,universe,multiverse
		# release=lucid
		# server=us.archive.ubuntu.com
		# inPath=/ubuntu
		# proto=http
		# proxy=http://proxy.local:8888
		# outpath=/var/www/repos/ubuntu
		#
		# debmirror       -a $arch \
		#                 --no-source \
		#                 -s $section \
		#                 -h $server \
		#                 -d $release \
		#                 -r $inPath \
		#                 --progress \
		#                 --ignore-release-gpg \
		#                 --no-check-gpg \
		#                 --proxy=$proxy \
		#                 -e $proto \
		#                 $outPath

		cd $cur_path;

		rm -rf /etc/cobbler/settings.bak;

		# 修改配置
		cp /etc/cobbler/settings /etc/cobbler/settings.bak;
		rand_pass=$(openssl passwd -1 -salt 'cobbler' 'abcd1234')
		sed -i "s/^server: 127.0.0.1/server: $serverip/" /etc/cobbler/settings;
		sed -i "s/^next_server: 127.0.0.1/next_server: $serverip/" /etc/cobbler/settings;
		sed -i "s/^default_password_crypted:.*/default_password_crypted: \"$rand_pass\"/" /etc/cobbler/settings;
		sed -i "s/^manage_dhcp:.*/manage_dhcp:\ 1/" /etc/cobbler/settings;
		sed -i "s/option routers[[:space:]]*.*/option routers\             $serverip;/" /etc/cobbler/dhcp.template;
		sed -i "s/disable[[:space:]]*=[[:space:]]*yes/disable\			=\ no/" /etc/xinetd.d/tftp;

		# Selinux
		mkdir -p /var/lib/cobbler/policy;
		rm -rf /var/lib/cobbler/policy/cobbler-web.te
		cat >> /var/lib/cobbler/policy/cobbler-web.te<<EOF
policy_module(cobbler-web, 1.0)

gen_require(\
type cobblerd_t;
type systemd_unit_file_t;
)

allow cobblerd_t systemd_unit_file_t:file getattr;
EOF
		cd /var/lib/cobbler/policy
		make -f /usr/share/selinux/devel/Makefile cobbler-web.pp
		semodule -i cobbler-web.pp
		cd $cur_path;



		# 暂时关闭Selinux
		setenforce 0;
		# Firewall
		# /etc/sysconfig/iptables
		# -A INPUT -m state --state NEW -m udp -p udp -m udp --dport 69 -j ACCEPT

		firewall-cmd --zone=public --add-service=tftp --permanent;
		firewall-cmd --zone=public --add-service=dhcp --permanent;
		# DHCP
		firewall-cmd --zone=public --add-port=68/tcp --permanent;
		firewall-cmd --zone=public --add-port=123/udp --permanent;
		firewall-cmd --zone=public --add-port=25150/udp --add-port=25151/tcp --add-port=25152/tcp --permanent;
		# DNS
		firewall-cmd --zone=public --add-port=53/tcp --add-port=53/udp --permanent;

		firewall-cmd --reload;

		systemctl restart httpd.service;

		systemctl enable rsyncd.service cobblerd.service tftp.service xinetd.service dhcpd.service;
		systemctl restart cobblerd.service;
		systemctl restart httpd.service rsyncd.service tftp.service xinetd.service;

		cobbler sync;
		cobbler get-loaders;

		cobbler sync;
		systemctl restart dhcpd.service;

		# 添加镜像

		if [[ ! -f "CentOS-7-x86_64-DVD-1511.iso" ]]; then
			wget -c http://mirrors.aliyun.com/centos/7/isos/x86_64/CentOS-7-x86_64-DVD-1511.iso
		fi

		rm -rf /var/lib/cobbler/kickstarts/centos7.cfg;
		cat >>/var/lib/cobbler/kickstarts/centos7.cfg<<EOF
# kickstart template for CentOS7
# (includes %end blocks)
# do not use with earlier distros

#platform=x86, AMD64, or Intel EM64T
# System authorization information
auth  --useshadow  --enablemd5
# System bootloader configuration
bootloader --location=mbr
# Partition clearing information
clearpart --all --initlabel
# Use text mode install
text
# Firewall configuration
firewall --enabled
# Run the Setup Agent on first boot
firstboot --disable
# System keyboard
keyboard us
# System language
lang en_US
# Use network installation
url --url=\$tree
# If any cobbler repo definitions were referenced in the kickstart profile, include them here.
$yum_repo_stanza
# Network information
\$SNIPPET('network_config')
# Reboot after installation
reboot

#Root password
rootpw --iscrypted \$default_password_crypted
# SELinux configuration
selinux --enforcing
# Do not configure the X Window System
skipx
# System timezone
timezone Asia/Shanghai --isUtc
# Install OS instead of upgrade
install
# Clear the Master Boot Record
zerombr
# Allow anaconda to partition the system as needed
autopart

%pre
\$SNIPPET('log_ks_pre')
\$SNIPPET('kickstart_start')
\$SNIPPET('pre_install_network_config')
# Enable installation monitoring
\$SNIPPET('pre_anamon')
%end

%packages
\$SNIPPET('func_install_if_enabled')
%end

%post --nochroot
\$SNIPPET('log_ks_post_nochroot')
%end

%post
\$SNIPPET('log_ks_post')
# Start yum configuration
\$yum_config_stanza
# End yum configuration
\$SNIPPET('post_install_kernel_options')
\$SNIPPET('post_install_network_config')
\$SNIPPET('func_register_if_enabled')
\$SNIPPET('download_config_files')
\$SNIPPET('koan_environment')
\$SNIPPET('redhat_register')
\$SNIPPET('cobbler_register')
# Enable post-install boot notification
\$SNIPPET('post_anamon')
# Start final steps
\$SNIPPET('kickstart_done')
# End final steps
%end
EOF
		mount -t iso9660 -o loop,ro CentOS-7-x86_64-DVD-1511.iso /mnt
		cobbler import --name=CentOS7 --arch=x86_64 --path=/mnt
		cobbler profile add --name=CentOS7 --distro=CentOS7-x86_64 --kickstart=/var/lib/cobbler/kickstarts/centos7.cfg;
		cobbler system add --name=CentOS7 --profile=CentOS7
		cobbler sync;

		# 开启Selinux
		setenforce 1;

		# 设置权限
		setsebool -P cobbler_can_network_connect 1;
		setsebool -P httpd_can_network_connect_cobbler 1;
		setsebool -P httpd_can_network_connect true;
		setsebool -P httpd_serve_cobbler_files 1
		setsebool -P cobbler_use_nfs 1
   		setsebool -P httpd_can_network_connect_cobbler 1
   		setsebool -P cobbler_use_cifs 1
   		setsebool -P cobbler_anon_write 1

		setsebool -P tftp_anon_write 1;
		setsebool -P tftp_home_dir 1;

		semanage fcontext -a -t public_content_rw_t "/var/www/cobbler(/.*)?";
		restorecon -R -v /var/www/cobbler;

		semanage fcontext -a -t dhcp_etc_t "/etc/dhcp(/.*)?";
		restorecon -R -v /etc/dhcp;

		semanage fcontext -a -t public_content_rw_t "/var/lib/cobbler(/.*)?";
		restorecon -R -v /var/lib/cobbler;

		semanage fcontext -a -t public_content_rw_t "/var/lib/tftpboot(/.*)?"
		restorecon -R -v /var/lib/tftpboot;

		semanage fcontext -a -t cobblerd_exec_t '/srv/cobblerd/content(/.*)?'
       	restorecon -R -v /srv/mycobblerd_content;

       	semanage fcontext -a -t httpd_sys_rw_content_t "/var/lib/cobbler/webui_sessions(/.*)?"
       	restorecon -R -v /var/lib/cobbler/webui_sessions;

		o_cobbler_state=2;
		echo "Cobbler installed success.";
	fi
}

function install_weblogic12()
{
	if [[ $o_weblogic_state -eq 1 || $1 -eq 1  ]] && [[ $(service_test "weblogicd") -eq 0 ]]; then

		clear;
		echo "Start installing WebLogic...";
		input_host_name;

		# 创建用户
		getent group bea || groupadd bea;
		getent passwd weblogic || useradd -g bea weblogic;

		yum -y install binutils compat-libcap1 compat-libstdc++-33 gcc gcc-c++ glibc glibc-devel libaio libaio-devel libgcc libstdc++ libstdc++-devel make openmotif openmotif22 sysstat

		# 下载解压文件
		if [[ ! -f "fmw_12.2.1.2.0_wls_quick_Disk1_1of1.zip" ]]; then
			wget -c http://xieguoliang.com/downloads/fmw_12.2.1.2.0_wls_quick_Disk1_1of1.zip;
		fi

		rm -rf /stage;
		mkdir -p /stage/wls12c;
		unzip fmw_12.2.1.2.0_wls_quick_Disk1_1of1.zip -d /stage/wls12c

		ORACLE_BASE=/var/local/wls1212
		MW_HOME=$ORACLE_BASE/weblogic
		DOMAIN_NAME="localhost"
		if [[ -n "$host_name" ]]; then
			DOMAIN_NAME=$host_name;
		fi

		DOMAIN_HOME=$ORACLE_BASE/domains/$DOMAIN_NAME

		export ORACLE_BASE;
		export MW_HOME;

		sed -i "/export MW_HOME=.*/d" /etc/profile;

		cat >>/etc/profile<<EOF
export MW_HOME=$MW_HOME
EOF


		rm -rf /home/weblogic/.bash_profile;
		cat >>/home/weblogic/.bash_profile<<EOF
export ORACLE_HOME=$MW_HOME
export DOMAIN_HOME=$DOMAIN_HOME
export JAVA_OPTIONS='-Djava.security.egd=file:/dev/./urandom -DUseSunHttpHandler=true'
export CLASSPATH=$CLASSPATH:$MW_HOME/wlserver/server/lib/weblogic.jar
EOF

		cat >>/stage/wls12c/oraInst.loc<<EOF
inventory_loc=$ORACLE_BASE/oraInventory
inst_group=bea
EOF
		cat >>/stage/wls12c/wls.resp<<EOF
[ENGINE]
#DO NOT CHANGE THIS.
Response File Version=1.0.0.0.0

[GENERIC]
ORACLE_BASE=$ORACLE_BASE
ORACLE_HOME=$MW_HOME
INSTALL_TYPE=WebLogic Server
DECLINE_SECURITY_UPDATES=true
SECURITY_UPDATES_VIA_MYORACLESUPPORT=false
EOF

		rm -rf /stage/wls12c/create_domain.rsp;
		cat >>/stage/wls12c/create_domain.rsp<<EOF
read template from "$MW_HOME/wlserver/common/templates/wls/wls.jar";
set JavaHome "$JAVA_HOME";
set ServerStartMode "prod";

find Server "AdminServer" as AdminServer;
set AdminServer.ListenAddress "";
set AdminServer.ListenPort "7001";
set AdminServer.SSL.Enabled "true";
set AdminServer.SSL.ListenPort "7002";


find User "weblogic" as u1;
set u1.password "$weblogic_password";

write domain to "$DOMAIN_HOME";

close template;

EOF

		rm -rf $ORACLE_BASE;

		mkdir -p $MW_HOME;
		mkdir -p $ORACLE_BASE/oraInventory;
		mkdir -p $DOMAIN_HOME;

		chown -R weblogic:bea /stage/wls12c
		chmod -R ug+rwx /stage/wls12c

		chown -R weblogic:bea $ORACLE_BASE
		chmod -R ug+rwx $ORACLE_BASE

		rm -rf /tmp/OraInstall*
		rm -rf /etc/oraInst.loc

		source /etc/profile

		echo "Weblogic installing,Please wait..."

		RUN_INSTALL=$(expect -c "
			set timeout 600;
			spawn su - weblogic -c \"java -jar -d64 /stage/wls12c/fmw_12.2.1.2.0_wls_quick.jar -silent -invPtrLoc /stage/wls12c/oraInst.loc -responseFile /stage/wls12c/wls.resp ORACLE_HOME=$MW_HOME\"
			expect \"The installation of Oracle Fusion Middleware 12c WebLogic and Coherence Developer 12.2.1.2.0 completed successfully\"
			expect eof
			exit
		");

		echo "$RUN_INSTALL"

		if [[ $(echo "$RUN_INSTALL" | grep "The installation of Oracle Fusion Middleware 12c WebLogic and Coherence Developer 12.2.1.2.0 completed successfully"|wc -l) -eq 1 ]]; then
			echo "Install finish."
			echo "Creating domain,Please wait..."

			RUN_INSTALL=$(expect -c "
				set timeout 1200;
				spawn su - weblogic -c \"$MW_HOME/oracle_common/common/bin/config.sh -mode=silent -silent_script=/stage/wls12c/create_domain.rsp -logfile=/var/log/create_domain.log\"
				expect \"succeed: close template\"
				expect eof
				exit
			");

			echo "$RUN_INSTALL"

			if [[ $(echo "$RUN_INSTALL" | grep "succeed: write Domain to"|wc -l) -eq 1 ]]; then

				mkdir -p $DOMAIN_HOME/servers/AdminServer/security
				cat >>$DOMAIN_HOME/servers/AdminServer/security/boot.properties<<EOF
username=weblogic
password=$weblogic_password
EOF

				cat >>$DOMAIN_HOME/weblogic<<EOF
#!/bin/bash

export BEA_BASE=$ORACLE_BASE
export DOMAIN_HOME=$DOMAIN_HOME
export DOMAIN_LOG=\$DOMAIN_HOME/logs/`date -d now +%Y%m%d%H%M%S`.log
export PATH=\$PATH:\$DOMAIN_HOME/bin
DOMAIN_OWNER="weblogic"

if [ ! -f \$DOMAIN_HOME/bin/startWebLogic.sh -o ! -d \$DOMAIN_HOME ]
then
    echo "WebLogic startup:cannot start"
    exit 1
fi
# depending on parameter -- startup,shutdown,restart
case "\$1" in
	start)
	    echo -n "Starting Weblogic:log file \$DOMAIN_LOG"
	    touch \$DOMAIN_HOME/lock_weblogic
	    if [[ \$USER = \$DOMAIN_OWNER ]]; then
		    mkdir -p \$DOMAIN_HOME/logs
		    export JAVA_OPTIONS='-Djava.security.egd=file:/dev/./urandom -DUseSunHttpHandler=true'
		    nohup sh \$DOMAIN_HOME/bin/startWebLogic.sh > \$DOMAIN_LOG 2>&1 &
		else
			su - \$DOMAIN_OWNER -c "mkdir -p \$DOMAIN_HOME/logs"
		    su - \$DOMAIN_OWNER -c "export JAVA_OPTIONS='-Djava.security.egd=file:/dev/./urandom -DUseSunHttpHandler=true'"
		    su - \$DOMAIN_OWNER -c "nohup sh \$DOMAIN_HOME/bin/startWebLogic.sh > \$DOMAIN_LOG 2>&1 &"
		fi
	    echo " OK"
	    ;;
	stop)
	    echo -n "Shutdown Weblogic:"
	    rm -rf \$DOMAIN_HOME/lock_weblogic
	    if [[ \$USER = \$DOMAIN_OWNER ]]; then
	    	sh \$DOMAIN_HOME/bin/stopWebLogic.sh >> \$DOMAIN_LOG
	    else
	    	su - \$DOMAIN_OWNER -c "sh \$DOMAIN_HOME/bin/stopWebLogic.sh >> \$DOMAIN_LOG"
	    fi

	    PIDS=\$(ps -ax |grep "java.*weblogic"|grep -v "grep" |awk '{print \$1}')
		for pid in \$PIDS
		do
	    	kill -9 \$pid 2>/dev/null
		done
	    echo " OK"
	    ;;
	reload|restart)
	    \$0 stop
	    \$0 start
	    ;;
	*)
	    echo "Usage: `basename $0` start|restart|reload"
	    exit 1
	esac

exit 0

EOF

				site_home=/var/www/weblogic/localhost
				if [[ -n "$host_name" ]]; then
					site_home=/var/www/weblogic/$host_name
				fi
				app_name="default"
				app_home=$site_home/$app_name

				rm -rf $site_home;
				mkdir -p $app_home/WEB-INF;

				# 生成Hello world

				cat >>$app_home/index.jsp<<EOF
<%@ page language="java" import="java.util.*" pageEncoding="UTF-8"%>
<%
String path = request.getContextPath();
String basePath = request.getScheme()+"://"+request.getServerName()+":"+request.getServerPort()+path+"/";
%>
<!doctype html>
<html>
<head>
<meta charset="UTF-8">
<title>Hello World</title>
</head>

<body>
	<%
    	out.println("Hello world!");
    %>
</body>
</html>
EOF
				cat >>$app_home/WEB-INF/web.xml<<EOF
<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns="http://java.sun.com/xml/ns/javaee" xsi:schemaLocation="http://java.sun.com/xml/ns/javaee http://java.sun.com/xml/ns/javaee/web-app_2_5.xsd" id="WebApp_ID" version="2.5">
  <display-name>$app_name</display-name>
  <welcome-file-list>
    <welcome-file>index.html</welcome-file>
    <welcome-file>index.jsp</welcome-file>
    <welcome-file>default.html</welcome-file>
    <welcome-file>default.jsp</welcome-file>
  </welcome-file-list>
</web-app>
EOF

				deploy_target="AdminServer"
				virtual_host=""

				if [[ -n "$host_name" ]]; then
					deploy_target="$deploy_target,$host_name"
					tmpfile="/tmp/$RANDOM";
					cat >>$tmpfile<<EOF
  <virtual-host>
    <name>$host_name</name>
    <target>AdminServer</target>
    <web-server-log>
      <number-of-files-limited>false</number-of-files-limited>
      <file-count>7</file-count>
    </web-server-log>
    <virtual-host-name>$host_name</virtual-host-name>
  </virtual-host>
EOF
					sed -i "/<configuration-version>/r $tmpfile" $DOMAIN_HOME/config/config.xml;
				fi

				mkdir -p $site_home/.plan
				cat >>$site_home/.plan/$app_name.xml<<EOF
<?xml version='1.0' encoding='UTF-8'?>
<deployment-plan xmlns="http://xmlns.oracle.com/weblogic/deployment-plan" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://xmlns.oracle.com/weblogic/deployment-plan http://xmlns.oracle.com/weblogic/deployment-plan/1.0/deployment-plan.xsd">
  <application-name>localhost</application-name>
  <module-override>
    <module-name>default</module-name>
    <module-type>war</module-type>
    <module-descriptor external="true">
      <root-element>weblogic-web-app</root-element>
      <uri>WEB-INF/weblogic.xml</uri>
    </module-descriptor>
    <module-descriptor external="false">
      <root-element>web-app</root-element>
      <uri>WEB-INF/web.xml</uri>
    </module-descriptor>
  </module-override>
  <config-root>$site_home/.plan</config-root>
</deployment-plan>

EOF
				mkdir -p $site_home/.plan/WEB-INF
				cat >>$site_home/.plan/WEB-INF/weblogic.xml<<EOF
<?xml version='1.0' encoding='UTF-8'?>
<weblogic-web-app xmlns="http://xmlns.oracle.com/weblogic/weblogic-web-app" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://xmlns.oracle.com/weblogic/weblogic-web-app http://xmlns.oracle.com/weblogic/weblogic-web-app/1.6/weblogic-web-app.xsd">
  <session-descriptor></session-descriptor>
  <jsp-descriptor></jsp-descriptor>
  <container-descriptor></container-descriptor>
  <context-root>/</context-root>
</weblogic-web-app>
EOF




				chown -R weblogic:bea $site_home
				chmod -R ug+rw $site_home

				rm -rf /usr/lib/systemd/system/weblogic.service;
			cat >>/usr/lib/systemd/system/weblogic.service<<EOF
[Unit]
Description=Weblogic Service
After=network.target

[Service]
Type=forking
ExecStart=$DOMAIN_HOME/weblogic start
ExecStop=$DOMAIN_HOME/weblogic stop
User=weblogic
Group=bea

[Install]
WantedBy=default.target

EOF
				chown -R weblogic:bea $DOMAIN_HOME
				chmod -R ug+rwx $DOMAIN_HOME

				# 添加防火墙
				firewall-cmd --permanent --zone=public --add-port=7001/tcp;
				firewall-cmd --permanent --zone=public --add-port=7002/tcp;
				firewall-cmd --reload;
				semanage port -a -t http_port_t -p tcp 7001;
				semanage port -a -t http_port_t -p tcp 7002;

				# 启动服务
				systemctl daemon-reload;
				systemctl enable weblogic.service;

				systemctl restart weblogic.service;

				# 等待服务器启动

				sleep 10;

				# 布署示例项目
				# 参考https://docs.oracle.com/cd/E13222_01/wls/docs103/deployment/deploy.html
				su - weblogic -c "java weblogic.Deployer -adminurl t3://localhost:7001 -username weblogic -password $weblogic_password -deploy -name $app_name -targets $deploy_target -source $app_home -stage -plan $site_home/.plan/$app_name.xml"

				su - weblogic -c "java weblogic.Deployer -adminurl t3://localhost:7001 -user weblogic -password $weblogic_password -start -name $app_name"

				o_weblogic_state=2;

				echo "WebLogic installed success.";
			else
				echo "WebLogic installed failure.";
			fi
		else
			echo "WebLogic installed failure.";
		fi
	fi
}

function install_gitlab()
{
	# http://blog.wengyingjian.com/2016/02/08/server-gitlab-init/
	if [[ $o_gitlab_state -eq 1 || $1 -eq 1 ]] && [[ $(service_test "gitlab-runsvdir") -eq 0 ]]; then

		clear;
		echo "Start installing Gitlab...";


		yum install -y postfix
		systemctl enable postfix
		systemctl restart postfix
		firewall-cmd --permanent --add-service=http
		systemctl reload firewalld

		curl -sS http://packages.gitlab.cc/install/gitlab-ce/script.rpm.sh | sudo bash
		#curl -sS https://packages.gitlab.com/install/repositories/gitlab/gitlab-ce/script.rpm.sh | sudo bash
		#rm -rf /etc/yum.repos.d/gitlab-ce.repo
		#cat >>/etc/yum.repos.d/gitlab-ce.repo<<EOF
#[gitlab-ce]
#name=gitlab-ce
#baseurl=http://mirrors.tuna.tsinghua.edu.cn/gitlab-ce/yum/el7
#repo_gpgcheck=0
#gpgcheck=0
#enabled=1
#gpgkey=https://packages.gitlab.com/gpg.key
#EOF
#		sudo yum makecache

		yum install -y gitlab-ce;
		gitlab-ctl reconfigure;

		if [ "$gitlab_port"!="80" ]; then
			sed -i "s/^[[:space:]]*listen[[:space:]]*80;/       listen       $gitlab_port;/"  /opt/gitlab/embedded/conf/nginx.conf
			sed -i "s/^external_url 'http:\/\/localhost'/external_url 'http:\/\/localhost:$gitlab_port'/"  /etc/gitlab/gitlab.rb
			sed -i "s/^[[:space:]]*port:[[:space:]]*80;/    port       $gitlab_port;/"  /opt/gitlab/embedded/service/gitlab-rails/config/gitlab.yml
      #unicorn['port'] = 9090
			# 添加防火墙
			firewall-cmd --permanent --zone=public --add-port=$gitlab_port/tcp;
			firewall-cmd --reload;
			semanage port -a -t http_port_t -p tcp $gitlab_port;
		fi


		gitlab-ctl reconfigure;
		systemctl restart gitlab-runsvdir.service

		# 配置
		# https://docs.gitlab.com/omnibus/README.html

		# 备份还原 （备份和恢复文件都是git用户）
		# /var/opt/gitlab/backups
		# gitlab-rake gitlab:backup:create
		# gitlab-rake gitlab:backup:restore
		# gitlab-rake gitlab:backup:restore BACKUP=1393513186

		o_gitlab_state=2;
		echo "Gitlab installed success.";
	fi
}

function install_vncserver()
{
	yum groupinstall -y "GNOME Desktop"
	yum install -y tigervnc-server tigervnc-server-module tigervnc


	cat >/etc/systemd/system/vncserver@:1.service<<EOF
[Unit]
Description=Remote desktop service (VNC)
After=syslog.target network.target
[Service]
Type=forking
User=root
ExecStart=/usr/bin/vncserver :1 -geometry 1280x1024 -depth 16 -securitytypes=none -fp /usr/share/X11/fonts/misc
ExecStop=/usr/bin/vncserver -kill :1
[Install]
WantedBy=multi-user.target
EOF

	systemctl enable vncserver@:1.service

}

function install_kvm()
{
	# 参考
	# http://www.tuicool.com/articles/3YjEzm
	# http://jensd.be/207/linux/install-and-use-centos-7-as-kvm-virtualization-host
	# https://linux.dell.com/files/whitepapers/KVM_Virtualization_in_RHEL_7_Made_Easy.pdf
	if [[ $o_kvm_state -eq 1 || $1 -eq 1 ]] && [[ $(service_test "libvirtd") -eq 0 ]]; then

		clear;
		echo "Start installing KVM...";

		# 检测CPU是否支持
		support_kvm=$(egrep 'vmx|svm'  /proc/cpuinfo);
		if [[ -z "$support_kvm" ]]; then
			echo "Your system does not support virtualization !";
			exit 0;
		fi


		# 安装组件
		yum install -y kvm python-virtinst libvirt virt-install bridge-utils virt-manager qemu-kvm-tools  virt-viewer  virt-v2v libguestfs-tools
		systemctl enable libvirtd.service
		systemctl restart libvirtd.service

		# 创建网桥
		if [ ! -f "/etc/sysconfig/network-scripts/ifcfg-br0" ]; then

			bootproto=$(cat /etc/sysconfig/network-scripts/ifcfg-$eth |egrep  "^BOOTPROTO="|awk '{print substr($1,11)}' |sed 's/"//g');
			uuid=$(cat /etc/sysconfig/network-scripts/ifcfg-$eth |egrep  "^UUID="|awk '{print substr($1,6)}' |sed 's/"//g');
			macaddr=$(cat /etc/sysconfig/network-scripts/ifcfg-$eth |egrep  "^HWADDR="|awk '{print substr($1,6)}' |sed 's/"//g');

			rm -rf /etc/sysconfig/network-scripts/ifcfg-br0;
			cat>>/etc/sysconfig/network-scripts/ifcfg-br0 <<EOF
DEVICE=br0
TYPE=Bridge
ONBOOT=yes
NM_CONTROLLED=no
EOF

			if [[ -n "$uuid" ]]; then
				echo "UUID=\"$uuid\"" >> /etc/sysconfig/network-scripts/ifcfg-br0
			fi

			if [[ -n "$macaddr" ]]; then
				echo "HWADDR=$macaddr" >> /etc/sysconfig/network-scripts/ifcfg-br0
			fi

			#if [ "$bootproto" = "dhcp" ]; then

			#	echo "BOOTPROTO=dhcp" >> /etc/sysconfig/network-scripts/ifcfg-br0
			#else
				cat >>/etc/sysconfig/network-scripts/ifcfg-br0 <<EOF
BOOTPROTO=none
IPADDR=$serverip
NETMASK=$netmask
GATEWAY=$gateway
EOF
			#fi

			sed -i "/^BRIDGE=/d" /etc/sysconfig/network-scripts/ifcfg-$eth;
			#sed -i "/^HWADDR=/d" /etc/sysconfig/network-scripts/ifcfg-$eth;
			#sed -i "/^DEVICE=/aHWADDR=$macaddr" /etc/sysconfig/network-scripts/ifcfg-$eth;
			sed -i "$ a BRIDGE=br0" /etc/sysconfig/network-scripts/ifcfg-$eth;

			echo "/etc/sysconfig/network-scripts/ifcfg-$eth:"
			cat /etc/sysconfig/network-scripts/ifcfg-$eth

			echo "/etc/sysconfig/network-scripts/ifcfg-br0:"
			cat /etc/sysconfig/network-scripts/ifcfg-br0
			echo "Network bridge setup success."

			need_boot="yes"
			printf "Do you like to reboot your system,Yes or no:[yes]\n"
			read tmp;
			if [[ -n "$tmp" ]]; then
				need_boot="$tmp";
			fi

			if [ $need_boot="yes" ]; then
				reboot;
			else
				systemctl restart network.service;
			fi
		fi


		# 允许网络请求转发
		sed -i "/net.ipv4.ip_forward/d" /etc/sysctl.conf
		sed -i "$ a net.ipv4.ip_forward = 1" /etc/sysctl.conf
		sysctl -p /etc/sysctl.conf

		# 创建虚拟机
		mkdir -p /var/lib/libvirt/images
		mkdir -p /data/iso

		if [[ -f "CentOS-7-x86_64-DVD-1511.iso" ]]; then
			mv CentOS-7-x86_64-DVD-1511.iso /data/iso
		fi

		# 添加防火墙
		vncport=25910
		vncpass='qingfeng***2016'
		firewall-cmd --permanent --zone=public --add-port=$vncport/tcp;
		firewall-cmd --reload;
		semanage port -a -t vnc_port_t -p tcp $vncport;
		setsebool -P virt_use_samba 1
		setsebool -P virt_use_nfs 1
		# semanage fcontext -l | grep virt_image_t
		# semanage fcontext --add -t virt_image_t '/vm-images(/.*)?'
		# restorecon -R -v /vm-images
		# ls –aZ /vm-images

		# virt-install --name=centos01 --ram 512 --vcpus=1 --disk path=/data/kvm/centos01.img,size=7,bus=virtio --accelerate --cdrom /root/CentOS-7-x86_64-DVD-1511.iso --vnc --vncport=5910 --vnclisten=0.0.0.0 --network bridge=br0,model=virtio
		## virt-install --name=CentOS7-x86_64 ram=512 --vcpus=1 -f /home/kvm/ubuntu64.qcow2 --location /home/os --network bridge=br0 --extra-args='console=tty0 console=ttyS0,115200n8 serial' --force
		virt-install --name=CentOS7-x86_64 --ram=4096 --vcpus=4 --disk path=/var/lib/libvirt/images/CentOS7-x86_64.img,size=120,bus=virtio --accelerate --cdrom=/data/iso/CentOS-7-x86_64-DVD-1511.iso --graphics vnc,listen=0.0.0.0,port=$vncport,password=$vncpass --network bridge=br0,model=virtio --network network=default  --os-type=linux --os-variant=rhel7

		#virt-install --name=default --ram=4096 --vcpus=2 --disk path=/var/lib/libvirt/images/default.img,size=120,bus=virtio --accelerate --cdrom=/data/iso/CentOS-7-x86_64-DVD-1511.iso --graphics vnc,listen=0.0.0.0,port=$vncport,password=$vncpass --network bridge=br0,model=virtio --network network=default  --os-type=linux --os-variant=rhel7

		#virsh autostart CentOS7-x86_64
		#virsh console CentOS7-x86_64

		# virsh list --all
		# virsh destroy CentOS7-x86_64
		# virsh undefine CentOS7-x86_64
		# rm -rf /data/kvm/disk03.img
		# 打开图形界面，在终端选择 kconsole ，并且打开 virt-manager 工具

		# 还可以使用命令克隆：
 		# nohup virt-clone -o centos01 -n centos02 -f /data/kvm/centos02.img &
 		# virsh reboot CentOS7-x86_64 （重启）
		# virsh start CentOS7-x86_64   （启动）
		# virsh suspend CentOS7-x86_64  挂起

		# virsh
		#    attach-disk CentOS7-x86_64 /data/iso/CentOS-7-x86_64-DVD-1511.iso hda --driver file --type cdrom --mode readonly

		# virt-clone --connect qemu:///system --original CentOS7-x86_64 --name CentOS7-Web --file /data/kvm/CentOS7-Web.img

		# 网络配置
		# virsh net-dumpxml default   # 查看默认的网络配置
		# virsh net-edit default      # 编辑
		# virsh net-destroy default   # 关闭
		# virsh net-start default     # 重启

		# virsh snapshot-list test-server
		# virsh snapshot-create-as test-server test-server-installed
		# virsh snapshot-revert test-server test-server-installed
		# virsh snapshot-delete test-server test-server-installed

		#  qemu-img resize /var/lib/libvirt/images/pgj-test.img +50G

		# grubby --update-kernel=ALL --args="console=ttyS0"

		o_kvm_state=2;
		echo "KVM installed success.";
	fi
}

function mask_to_prefix()
{
	yum install -y bc > /dev/null 2>&1;
    mask=${1}
	prefix_cnt=0
	prefix=""
	local mask_list=($(echo ${mask} | awk -F . '{print $1,$2,$3,$4}'))
    local mask_cnt=${#mask_list[*]}
    mask_cnt=$((${mask_cnt} - 1))
    for i in `seq 0 ${mask_cnt}`
    do
            tmp=$(echo "obase=2;ibase=10;${mask_list[$i]}" | bc)
            prefix="${prefix}${tmp}"
    done
    prefix_cnt=$(echo ${prefix} | grep -o 1 | wc -l)
    echo $prefix_cnt
}

function config_route()
{
	if [[ $(service_test "config-route") -eq 0 ]]; then
		clear;
		local tmpfile=/tmp/$RANDOM;
		local cmd="";
		rm -rf $tmpfile;
		echo "Config route for multi  network interfaces."
		ip=$(ip a|grep "inet " |grep -v "127.0.0.1"|awk '{print substr($2,1,index($2,"/")-1)","$NF}')
		index=1
		for i in $ip
		do
			local ipaddr=${i/,*/}
			local eth=${i/*,/}
			local gateway=$(ip route list |grep "$eth" |grep -w "via" |awk 'NR==1{print $3}');
			local netmask=$(ifconfig $eth |grep -w "netmask" |awk '{print $4}');
			local prefix=$(mask_to_prefix $netmask);
			local preip=$(echo $ipaddr | awk -F . '{print $1"."$2"."$3}');
			local priority=$index"00"

			#echo "ipaddr:$ipaddr, eth:$eth, gateway:$gateway, netmask:$netmask, prefix:$prefix, preip:$preip";


			echo "echo \"$preip.0/$prefix dev $eth tab $index\" > /etc/sysconfig/network-scripts/route-$eth" >> $tmpfile
			echo "echo \"default via $gateway dev $eth tab $index\" >> /etc/sysconfig/network-scripts/route-$eth" >> $tmpfile
			echo "echo \"from $ipaddr/32 tab $index priority $priority\" > /etc/sysconfig/network-scripts/rule-$eth" >> $tmpfile

			cmd="$cmd\nip route add $preip.0/$prefix dev $eth tab $index"
			cmd="$cmd\nip route add default via $gateway dev $eth tab $index"
			cmd="$cmd\nip rule add from $ipaddr/32 tab $index priority $priority"
			let "index=$index+1"
	    done
	    echo -e $cmd >> $tmpfile;

	    #echo "The config file is $tmpfile"
	    #chmod ug+x $tmpfile;
	    #cat $tmpfile;

	    # 生成服务
	    echo -e "#!/bin/bash\n$cmd" > /etc/config-route.sh
	    chmod ug+x /etc/config-route.sh

		rm -rf /usr/lib/systemd/system/config-route.service;
		cat >>/usr/lib/systemd/system/config-route.service<<EOF
[Unit]
Description=Config Route Service
After=network.target

[Service]
Type=forking
ExecStart=/etc/config-route.sh start
ExecStop=/etc/config-route.sh stop
User=root
Group=root

[Install]
WantedBy=default.target

EOF
		# 启动服务
		systemctl daemon-reload;
		systemctl enable config-route.service;

		echo "Config route for server success."
	fi
}

function nat-forward()
{
	if [[ $(service_test "nat-forwardcd") -eq 0 ]]; then
		rm -rf /etc/nat-forward.sh
		cat >>/etc/nat-forward.sh<<EOF
#!/bin/bash

firewall-cmd --add-masquerade > /dev/null 2>&1;

file="/etc/sysconfig/nat-tables"

if [[ ! -f "\$file" ]]; then
    echo "Can't find config file!"
    exit
fi

cmd=""

while read line
do
        # 去注释
        line=\${line/\#*/}
        # 去头尾空白
        line=\$(echo \$line |sed -e "s/^[ \s]\{1,\}//g" | sed -e "s/[ \s]\{1,\}\$//g");

        if [[ -n "\$line" ]]; then
            # 直接执行命令
            if [[ \${line:0:1} == "\$" ]]; then
                echo \${line:1};
                eval \${line:1};
                continue;
            fi

            from=\$(echo \$line|awk '{print \$1}')
            to=\$(echo \$line|awk '{print \$2}')

            from_ip=\${from/:*/}
            from_port=\${from/*:/}
            from_port=\${from_port/-/:}

            to_ip=\${to/:*/}
            to_port=\${to/*:/}
            to_port=\${to_port/-/:}

            #echo "from ip:\$from_ip, from_port:\$from_port, to_ip:\$to_ip, to_port:\$to_port"


            cmd=\${cmd}"\niptables -t nat     -D POSTROUTING   -p tcp  -s \$to_ip   --sport \$to_port   -j SNAT    --to \$from_ip > /dev/null 2>&1"
            cmd=\${cmd}"\niptables -t nat     -D PREROUTING    -p tcp  -d \$from_ip --dport \$from_port -j DNAT    --to \$to_ip:\${to_port/:/-} > /dev/null 2>&1;"
            cmd=\${cmd}"\niptables -D FORWARD -d \$to_ip/32    -p tcp  -m state     --dport \$to_port   -j ACCEPT  --state NEW -m tcp > /dev/null 2>&1;"

            cmd=\${cmd}"\niptables -t nat     -A POSTROUTING   -p tcp  -s \$to_ip   --sport \$to_port   -j SNAT    --to \$from_ip"
            cmd=\${cmd}"\niptables -t nat     -A PREROUTING    -p tcp  -d \$from_ip --dport \$from_port -j DNAT    --to \$to_ip:\${to_port/:/-}"
            cmd=\${cmd}"\niptables -I FORWARD -d \$to_ip/32    -p tcp  -m state     --dport \$to_port   -j ACCEPT  --state NEW -m tcp"
        fi
done < \$file


if [[ -n "\$cmd" ]]; then
    #echo -e "\$cmd"
    echo -e \$cmd | while read line
    do
        echo "\$line"
       	eval "\$line"
    done
fi

echo "OK"
EOF
		chmod ug+x /etc/nat-forward.sh

		rm -rf /usr/lib/systemd/system/nat-forward.service;
		cat >>/usr/lib/systemd/system/nat-forward.service<<EOF
[Unit]
Description=Config Nat Forward
After=network.target

[Service]
Type=forking
ExecStart=/etc/nat-forward.sh start
ExecStop=/etc/nat-forward.sh stop
User=root
Group=root

[Install]
WantedBy=default.target

EOF
		# 启动服务
		systemctl daemon-reload;
		systemctl enable nat-forward.service;
	fi

	if [[ -n "$options" ]]; then
		from=$(echo $options |awk -F - '{print $1}')
		to=$(echo $options |awk -F - '{print $2}')
		if [[ $(echo $from |grep ":" |wc -l) -eq 0 ]]; then
			from="$serverip:$from"
		fi

		local file="/etc/sysconfig/nat-tables"
		if [[ -f "$file"  ]]; then
			rm -rf $file.bak
			cp $file $file.bak

			sed -i "/$from.*/d" $file
		fi
		echo "$from $to" >> $file
	fi

	sh /etc/nat-forward.sh
}

case $action in
	install)
		install;;

	config-route)
		config_route;;

	nat-forward)
        nat-forward;;
esac
