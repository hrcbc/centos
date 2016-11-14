#!/bin/bash

SUMMARY="
#########################################################################
#  Maintain tools for KVM server                                        #
#  Create by GuoLiang                                                   #
#  2016-11-11                                                           #
#########################################################################
";

action='';

ARGS=`getopt -o i -u -al clone:,install: -- "$@"`
eval set -- '$ARGS'

while [ -n "$1" ]
do
	case "$1" in
		--install)
			action="$1";
			shift 2;;

		--clone)
			action="$1";
			shift;;

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

}