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