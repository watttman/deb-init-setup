#!/bin/sh
#
#
# This script blocks slow ssh probes by adding IPs to iptables xt_recent file (which is supposed to hold the blacklisted IPs)
# All iptables needs to be prepared beforehand!
#
#

# ssh auth log file where wrong passwd ssh attempts are stored
AUTHLOGFILE='/var/log/auth.log'
# cat /var/log/auth.log | grep 'Failed password for invalid user' | awk -F'from ' '{ print $2 }' | awk '{ print $1 }' | sort | uniq

# Trusted network prefix - IP addresses which start like this, will not be banned. Must be a regex; can provide up to 3 (see checkIP function if need to add more)
TRUSTEDIPREGEX='^192\.168\.167\..'
TRUSTEDIPREGEX2='^87\.227\.187\..'
TRUSTEDIPREGEX3='^206\.223\.179.\.'


# iptables xt_recent blacklisted /proc/net file for ssh log attempts - iptables must be configured accordingly beforehand!
XTRECENTBLACKLIST=/proc/net/xt_recent/SSHBLACKLIST

# Say log looks like this:

# Sleep seconds interval between log analyze runs; 600 sec = 10 minutes
RUNINTERVAL=300




AWK=`which awk`
SORT=`which sort`
UNIQ=`which uniq`
GREP=`which grep`
DIG=`which dig`
IPTABLES=`which iptables`

BSNAME=$(basename -- "${0}")
IP4TOBLOCKTMPFILE="/tmp/${BSNAME}.temp.txt"
LOGFILE="/var/log/${BSNAME}.log"

THISSERVERIP=`${DIG} @resolver1.opendns.com ANY myip.opendns.com +short`


blacklist () {
	local IP
	local OUT
	IP="$1"
	OUT=$( ${GREP} "${IP}" "${XTRECENTBLACKLIST}")
	if [ "x${OUT}" = "x" ]; then
		echo "+${IP}" > "${XTRECENTBLACKLIST}"
		echo "${IP} was not in the blacklist. BLACKLISTED ${IP} ."
	else
		echo "${IP} is already in the blacklist, doing nothing"
	fi
}




checkIP () {
	local IPADDR
	local TEMPS

	IPADDR="$1"
	echo "The IP ${IPADDR} will be processed ..."

	if [ "x${IPADDR}" = "x" ]; then
		echo "    Blank IP address parsed, check configuration! "
		return 1
	fi

        if [ "${THISSERVERIP}" = "${IPADDR}" ]; then
                echo "    IP address to analyze ${IPADDR} is same as our IP address ${THISSERVERIP}, we are not going to block ourselves! Skipping.  "
                return 1
        fi

	if ! [ "x${TRUSTEDIPREGEX}" = "x" ]; then
		TEMPS="$(echo "${IPADDR}" | ${GREP} -e "${TRUSTEDIPREGEX}")"
		if ! [ "x${TEMPS}" = "x" ]; then
			echo "    ${IPADDR} is trusted, doing nothing"
			return 1
		fi
	fi
	if ! [ "x${TRUSTEDIPREGEX2}" = "x" ]; then
		TEMPS="$(echo "${IPADDR}" | ${GREP} -e "${TRUSTEDIPREGEX2}")"
		if ! [ "x${TEMPS}" = "x" ]; then
			echo "    ${IPADDR} is trusted, doing nothing"
			return 1
		fi
	fi
	if ! [ "x${TRUSTEDIPREGEX3}" = "x" ]; then
		TEMPS="$(echo "${IPADDR}" | ${GREP} -e "${TRUSTEDIPREGEX3}")"
		if ! [ "x${TEMPS}" = "x" ]; then
			echo "    ${IPADDR} is trusted, doing nothing"
			return 1
		fi
	fi

	TEMPS=$( ${GREP} "${IPADDR}" "${XTRECENTBLACKLIST}")
	if ! [ "x${TEMPS}" = "x" ]; then
		echo "    ${IPADDR} is already in the blacklist, doing nothing"
		return 1
	fi

	return 0
}



processIP () {
	local IPADDR
	local EXTEN

	IPADDR="$1"
	checkIP "${IPADDR}"
	RESULT=$?
	[ ${RESULT} -eq 1 ] && return 1

	blacklist "${IPADDR}"
}



analyzeSecureLog () {

        THISSERVERIP=`${DIG} -4 @resolver1.opendns.com ANY myip.opendns.com +short`

	echo `date`
        echo "This server IP is ${THISSERVERIP}, will be excluded from blocking"

	# process security log file for invalid users
        echo "Processing log ${AUTHLOGFILE} (invalid users) "
	echo
	if [ -f ${AUTHLOGFILE} ]; then
		# collect ips of possible intruders
		${GREP} 'Failed password for invalid user' ${AUTHLOGFILE} | ${AWK} -F'from ' '{ print $2 }' | ${AWK} '{ print $1 }' | ${SORT} | ${UNIQ} > ${IP4TOBLOCKTMPFILE}
        	while IFS= read -r line
        	do
                	processIP "${line}"
                	echo
        	done < "${IP4TOBLOCKTMPFILE}"
	else
		echo "Security log file ${AUTHLOGFILE} does not exist! Please configure it."
	fi

	# process security log file for root 3 or more invalid passwords
        echo "Processing log ${AUTHLOGFILE} (failed passw >=3) "
	echo
	if [ -f ${AUTHLOGFILE} ]; then
		# collect ips of possible intruders
		${GREP} 'Failed password for root' ${AUTHLOGFILE} | ${AWK} -F'from ' '{ print $2 }' | ${AWK} '{ print $1 }' | ${SORT} | ${UNIQ} -c > ${IP4TOBLOCKTMPFILE}
        	while IFS= read -r line
        	do
			COUNT="$(echo "${line}" | ${AWK} '{ print $1 }')"
			IPADDR="$(echo "${line}" | ${AWK} '{ print $2 }')"
			if [ "${COUNT}" -gt 2 ]; then
				echo -n "IP ${IPADDR} made ${COUNT} attempts... "
				processIP "${IPADDR}"
                		echo
			fi
        	done < "${IP4TOBLOCKTMPFILE}"
	else
		echo "Security log file ${AUTHLOGFILE} does not exist! Please configure it."
	fi

}



main () {
	while :
	do
		# echo "Press [CTRL+C] to stop.."
		if test -f "$XTRECENTBLACKLIST"; then
			analyzeSecureLog > ${LOGFILE}
			# echo "..."
		else
			echo "iptables file ${XTRECENTBLACKLIST} does not exist, skipping run..."
		fi
		sleep ${RUNINTERVAL}
	done
}


main &


