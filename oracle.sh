#!/bin/bash

SUMMARY="
#########################################################################
#  Maintain tools for Oracle dabatase                                   #
#  Create by GuoLiang                                                   #
#  2017-01-13                                                           #
#########################################################################
";

echo "$SUMMARY";


USAGE="
 DESCRIPTION
 	This script is used for Oracle database

 OPTIONS
 	--create-user         Create an account
  --oracle-username   	Specifies the user name
 	--oracle-password   	Specify the password
";


action=""
oracle_username="piaoguanjia_oa"
oracle_password="pgj_oa_170113"
oracle_base="$ORACLE_BASE"
oracle_sid="$ORACLE_SID"

ARGS=`getopt -o i -u -al create-user,oracle-username:,oracle-password:,oracle-base:,oracle-sid: -- "$@"`
eval set -- '$ARGS'

while [ -n "$1" ]
do
	case "$1" in
		--create-user)
			action="$1";
			shift;;

    --oracle-username)
      oracle_username="$2";
      shift 2;;

		--oracle-password)
			oracle_password="$2";
			shift 2;;

    --oracle-base)
  		oracle_base="$2";
  		shift 2;;

		--oracle-sid)
			oracle_sid="$2";
			shift 2;;

		--)
			break;;

		*)
			echo "unrecognized option '$1'";
			echo "$USAGE";
			break;;
	esac
done

function setup() {
  if [[ $action="create-user" ]]; then
    create_user;
  fi
}

function create_user() {
  su - oracle -c '
sqlplus / as sysdba <<EOF
CREATE TABLESPACE '$oracle_username' datafile "'$oracle_base'/oradata/'$oracle_sid'/'$oracle_username'.dbf" size 10000m;
CREATE USER '$oracle_username' IDENTIFIED BY "'$oracle_username'" DEFAULT TABLESPACE '$oracle_username' TEMPORARY TABLESPACE "TEMP";
GRANT connect,RESOURCE TO '$oracle_username';
GRANT connect,RESOURCE,IMP_FULL_DATABASE,DEBUG CONNECT SESSION,DEBUG ANY PROCEDURE TO '$oracle_username';
GRANT IMP_FULL_DATABASE to '$oracle_username';
GRANT DEBUG CONNECT SESSION to '$oracle_username';
GRANT DEBUG ANY PROCEDURE TO '$oracle_username';

EOF
'
}

setup;
