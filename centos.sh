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
 	--install Install server componect,include:mysql,http,svn,vpn,ftp,tomcat
";


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

yum update -y;

yum install -y epel-release;

yum install -y gcc-c++ openssl-devel wget unzip expect;


# 配置Java环境

if [[ $(command_test "java") -eq 0 ]] || [[ $(java -version 2>&1 |grep -w "java version \"1.8" | wc -l) -eq 0 ]]; then
	 wget -N --no-check-certificate --no-cookies --header "Cookie: oraclelicense=accept-securebackup-cookie" http://download.oracle.com/otn-pub/java/jdk/8u102-b14/jdk-8u102-linux-x64.tar.gz

	 # wget --no-check-certificate --no-cookies --header "Cookie: oraclelicense=accept-securebackup-cookie" http://download.oracle.com/otn-pub/java/jdk/8u102-b14/jdk-8u102-linux-x64.rpm

	 # curl -v -j -k -L -H "Cookie: oraclelicense=accept-securebackup-cookie" http://download.oracle.com/otn-pub/java/jdk/8u102-b14/jdk-8u102-linux-x64.rpm > jdk-8u102-linux-x64.rpm
	 # In all cases above, subst 'i586' for 'x64' to download the 32-bit build.
	# -j -> junk cookies
	# -k -> ignore certificates
	# -L -> follow redirects
	# -H [arg] -> headers
	# curl can be used in place of wget.


	tar xzvf ./jdk-8u102-linux-x64.tar.gz -C /var/local;

	ln -s /var/local/jdk1.8.0_102 /var/local/jdk;

	rm -rf ./jdk-8u102-linux-x64.tar.gz;

	export JAVA_HOME=/var/local/jdk;
	export CLASS_PATH=.:$JAVA_HOME/lib;
	export PATH=$PATH:$JAVA_HOME/bin;
	sed -i '/export JAVA_HOME=\/var\/local\/jdk/d' /etc/profile
	sed -i '/export CLASS_PATH=\.\:\$JAVA_HOME\/lib/d' /etc/profile
	sed -i '/export PATH=\$PATH:\$JAVA_HOME\/bin/d' /etc/profile
	sed -i '$ a export JAVA_HOME=\/var\/local\/jdk' /etc/profile
	sed -i '$ a export CLASS_PATH=\.\:\$JAVA_HOME\/lib' /etc/profile
	sed -i '$ a export PATH=\$PATH:\$JAVA_HOME\/bin' /etc/profile
	source /etc/profile;
fi

############################### Read Args ###############################

action='';
options='';

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

if [ -n $options ]; then
        options=${options/+/|+};
        options=${options/-/|-};
        options=${options/,/|,};
else    
        options="all";
fi
options="|$options|";

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


############################# Define variables #############################

# Mysql
o_mysql_state=$(option_test "mysql");
mysql_root_password='guoliang.xie'

# SSH
ssh_port='1036'


# VPN
o_vpn_state=$(option_test "vpn");
serverip=$(ip addr|grep -w "inet" | grep -v "127.0.0.1" |awk 'NR==1{print substr($2,1,index($2,"/")-1)}');
eth=$(ip addr |grep '^[0-9]\+:[[:blank:]]\+[[:alnum:]]\+' |grep -v 'lo' |awk 'NR==1{gsub(":","");print $2}');
shared_secret="1ms.im";
iprange="10.0.1";
vpn_username="guoliang";
vpn_password="xgl.1234";

# FTP
o_ftp_state=$(option_test "ftp");
mysql_vsftpd_password=$(cat /dev/urandom | head -n 10 | md5sum | head -c 10);
ftp_username='hrcbc';
ftp_password='guoliang.xie';

# HTTP
o_http_state=$(option_test "http");
host_name="us.1ms.im"

# SVN
if [[ ! -f "sha1.jar" ]]; then
	wget -N https://raw.githubusercontent.com/hrcbc/centos/master/sha1.jar
fi
o_svn_state=$(option_test "svn");
mysql_svn_password=$(cat /dev/urandom | head -n 10 | md5sum | head -c 10);
svn_username="guoliang";
svn_password=$(java -jar ./sha1.jar xgl.1234);
svn_dbname="svnserver";
svn_dbuser="svn";

# Tomcat
o_tomcat_state=$(option_test "tomcat");


function install()
{
	
	setup_selinux;

	change_sshd_port;

	install_mysql;

	install_vpn;

	install_ftp;

	install_httpd;

	install_svn;

	install_tomcat;

}

function setup_selinux()
{
	if [[ $(sestatus |grep "disabled" | wc -l) -eq 1 ]]; then
		echo "Setup selinux...";

		yum install -y policycoreutils policycoreutils-python selinux-policy selinux-policy-targeted libselinux-utils setroubleshoot-server setools setools-console mcstrans;

		sed -i "s/^SELINUX=disabled/SELINUX=enforcing" /etc/sysconfig/selinux;
		# Enable selinux need restart
		reboot;
		exit 0;
	fi
}

function change_sshd_port()
{	
	if [[ $(grep "^Port 1036" /etc/ssh/sshd_config | wc -l) -eq 0 ]]; then
		echo "Change ssh port to : $ssh_port"
	
		# Add selinux port
		semanage port -a -t ssh_port_t -p tcp $ssh_port;
		# Add firewall port
		firewall-cmd --permanent --zone=public --add-port=$ssh_port/tcp;

		# Reload firewall
		firewall-cmd --reload;

		# Change ssh port to 1036
		sed -i "s/^#*Port 22/Port $ssh_port/" /etc/ssh/sshd_config

		systemctl restart sshd.service;
	fi
}

# 安装MySQL
function install_mysql()
{
	if [[ $o_mysql_state -eq 1 ]] && [[ $(service_test "mariadb") -eq 0 ]]; then

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
	if [[ $o_vpn_state -eq 1 ]] && [[ $(service_test "pptpd") -eq 0 || $(service_test "ipsec") -eq 0 || $(service_test "xl2tpd") -eq 0 ]]; then

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
}


function install_ftp()
{

	if [[ $o_ftp_state -eq 1 ]] && [[ $(service_test "vsftpd") -eq 0 ]]; then

		# 先安装Mysql数据库
		install_mysql;

		echo "Instal vsftpd...";
	
		yum install -y vsftpd ftp;	
		wget -N https://raw.githubusercontent.com/hrcbc/centos/master/pam_mysql-0.7-0.16.rc1.fc20.x86_64.rpm;
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
chroot_local_user=YES
secure_chroot_dir=/var/run/vsftpd
pam_service_name=vsftpd
rsa_cert_file=/etc/ssl/certs/vsftpd.pem
guest_enable=YES
guest_username=vsftpd
#local_root=/home/vsftpd/$USER
#user_sub_token=$USER
virtual_use_local_privs=YES
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
anon_world_readable_only=NO
anon_upload_enable=YES
anon_mkdir_write_enable=YES
anon_other_write_enable=YES
local_root=/
EOF
	
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
	if [[ $o_http_state -eq 1 ]] && [[ $(service_test "httpd") -eq 0 ]]; then

		echo "Install HTTP server..."

		yum -y install httpd httpd-devel php php-mysql php-gd php-ldap php-odbc php-pear php-xml php-xmlrpc php-mbstring php-snmp php-soap curl curl-devel php-mcrypt phpmyadmin

		mkdir -p /var/www/$host_name;

		mkdir -p /var/www/$host_name/downloads;

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
   DocumentRoot /var/www/$host_name  
   DirectoryIndex index.html index.php  
</VirtualHost>  
<Directory "/var/www/$host_name">  
   Options +Includes -Indexes  
   AllowOverride All  
   Order Deny,Allow  
   Allow from All  
</Directory>

<Directory "/var/www/$host_name/downloads">  
   Options Indexes FollowSymLinks
   AllowOverride All  
   Order Deny,Allow  
   Allow from All  
</Directory>
EOF

		# 配置phpMyAdmin
		sed -i "s/Require ip 127.0.0.1/Require all granted/g" /etc/httpd/conf.d/phpMyAdmin.conf;
		sed -i "/Require ip ::1/d" /etc/httpd/conf.d/phpMyAdmin.conf;

		rm -rf /var/www/$host_name/index.php

		cat >>/var/www/$host_name/index.php<<EOF
<?php
	echo phpinfo();
?>
EOF

		echo "test" > /var/www/$host_name/downloads/test.txt;


		# 添加防火墙
		firewall-cmd --permanent --zone=public --add-service=http
		firewall-cmd --permanent --zone=public --add-service=https
		firewall-cmd --reload

		semanage fcontext -a -t public_content_rw_t "/var/www/$host_name(/.*)?"
		restorecon -R -v /var/www/$host_name


		# 启动服务
		systemctl enable httpd.service;
		systemctl restart httpd.service;
		
		echo "HTTP server installed success."

		o_http_state=2;
	fi
	
}


function install_svn() 
{
	if [[ $o_svn_state -eq 1 ]] && [[  $(command_test "svnadmin") -eq 0 ]] && [ ! -f "/etc/httpd/conf.d/httpd-svn.conf" ]; then

		install_mysql;

		install_httpd;

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
	if [[ $o_tomcat_state -eq 1 ]]; then

		# 下载解压文件
		wget -N http://mirror.bit.edu.cn/apache/tomcat/tomcat-8/v8.5.5/bin/apache-tomcat-8.5.5.tar.gz;
		tar xzvf ./apache-tomcat-8.5.5.tar.gz -C /var/local;
		ln -s /var/local/apache-tomcat-8.5.5 /var/local/tomcat;
		rm -rf ./apache-tomcat-8.5.5.tar.gz;

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
		groupadd tomcat;
		useradd -M -s /bin/nologin -g tomcat -d $TOMCAT_HOME tomcat
		chown -R tomcat:tomcat $TOMCAT_HOME

		rm -rf ;

		cat >>$TOMCAT_HOME/bin/setenv.sh<<EOF
#add tomcat pid
CATALINA_PID="$TOMCAT_HOME/tomcat.pid"
#add java opts
JAVA_OPTS="-server -XX:PermSize=256M -XX:MaxPermSize=1024m -Xms512M -Xmx1024M -XX:MaxNewSize=256m"

EOF

		rm -rf /lib/systemd/system/tomcat.service;
		cat >>/lib/systemd/system/tomcat.service<<EOF
[Unit]
Description=Apache Tomcat
After=syslog.target network.target

[Service]
Type=forking
PIDFile=$TOMCAT_HOME/tomcat.pid
Environment=JAVA_HOME=$JAVA_HOME
Environment=CATALINA_PID=$TOMCAT_HOME/tomcat.pid
Environment=CATALINA_HOME=$TOMCAT_HOME
Environment=CATALINA_BASE=$TOMCAT_HOME

WorkingDirectory=$TOMCAT_HOME

ExecStart=$TOMCAT_HOME/bin/startup.sh
ExecStop=$TOMCAT_HOME/bin/shutdown.sh

User=tomcat
Group=tomcat

[Install]
WantedBy=multi-user.target
EOF
	
		# 启动服务
		systemctl enable tomcat.service;
		systemctl start tomcat.service;

		o_tomcat_state=2;
	fi
}

case $action in
	install)
		install;;
esac




