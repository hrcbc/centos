#!/bin/bash

SUMMARY="
#########################################################################
#  Maintain tools for KVM server                                        #
#  Create by GuoLiang                                                   #
#  2016-11-11                                                           #
#########################################################################
";

action='';
old=''
new=''
vnc_port=""
vnc_passwd="abcd1234"

ARGS=`getopt -o i,o:,n: -u -al clone,install:,vnc-port:,vnc-passwd: -- "$@"`
eval set -- '$ARGS'

while [ -n "$1" ]
do
	case "$1" in
		--install)
			action="$1";
			shift 2;;

		--clone)
			action="clone";
			shift;;

		--vnc-port)
			vnc_port="$2";
			shift 2;;

		--vnc-passwd)
			vnc_passwd="$2";
			shift 2;;

		-o)
			old="$2";
			shift 2;;

		-n)
			new="$2";
			shift 2;;

		--)
			break;;



		*)
			#echo "$1 is not option";
			echo $USAGE;
			break;;
	esac
done


function clone()
{
	echo "Clone $old to $new..."
	virt-clone -o $old -n $new -f /var/lib/libvirt/images/$new.img
	virsh dumpxml $new>/tmp/$new.xml

	sed -i "s/\/var\/lib\/libvirt\/qemu\/channel\/target\/domain-[[:graph:]]*\/org.qemu.guest_agent.0/\/var\/lib\/libvirt\/qemu\/channel\/target\/domain-$new\/org.qemu.guest_agent.0/" /tmp/$new.xml
	if [[ -n "$vnc_port" ]]; then
		sed  -i "s/<graphics type='vnc' port='-*[[:digit:]]*' autoport='[[:graph:]]*' listen='[[:graph:]]*'>/<graphics type='vnc' port='$vnc_port' autoport='no' listen='0.0.0.0' passwd='$vnc_passwd'>/" /tmp/$new.xml
		firewall-cmd --permanent --zone=public --add-port=$vnc_port/tcp;
		firewall-cmd --reload;
		semanage port -a -t vnc_port_t -p tcp $vnc_port; 
	else
		sed -s "s/<graphics type='vnc' port='-*[[:digit:]]*' autoport='[[:graph:]]*' listen='[[:graph:]]*'>/<graphics type='vnc' port='-1' autoport='yes' listen='[[:graph:]]*' passwd='$vnc_passwd'>/" /tmp/$new.xml
	fi
	virsh define /tmp/$new.xml

	echo "VM clone success."
}

if [ $action=="$clone" ]; then
	clone;
fi
