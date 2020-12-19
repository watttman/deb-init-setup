#!/bin/sh
#
#
# This script blocks slow Asterisk probes by adding IPs to iptables xt_recent file (which is supposed to hold the blacklisted IPs)
# All iptables needs to be prepared beforehand!
#
#

# expected Asterisk log entries format:
# [2019-12-17 10:31:34] NOTICE[2907] chan_sip.c: Registration from '<sip:4553@206.248.171.64>' failed for '45.56.172.224:49690' - Wrong password

# asterisk log file where wrong passwd registry attempts are stored
ASTERISKLOGFILE='/var/log/asterisk/full'
ASTERISKSECURITYLOGFILE='/var/log/asterisk/security_log'

# Minimum acceptable exten number in the range of our extensions; if the IP tries to authenticate with wrong password to IP out of that range; it will be blacklisted
MINOKEXTENNUM=3000
# Maximum acceptable exten number in the range of our extensions; if the IP tries to authenticate with wrong password to IP out of that range; it will be blacklisted
MAXOKEXTENNUM=3020
# Trusted network prefix - IP addresses which start like this, will not be banned. Must be a regex; can provide up to 3 (see checkIP function if need to add more)
# excluding local network and trunk ip's
TRUSTEDIPREGEX='^192\.168\.167\..'
TRUSTEDIPREGEX2='^208\.85\.218\.76'
TRUSTEDIPREGEX3='^178\.32\.219\.16'
TRUSTEDIPREGEX4=''


# iptables xt_recent blacklisted list /proc/net file - iptables must be configured accordingly beforehand!
XTRECENTBLACKLIST=/proc/net/xt_recent/BLACKLISTED


# Say log looks like this:
#[2019-12-18 13:08:10] NOTICE[2907] chan_sip.c: Registration from '<sip:2235@206.248.171.64>' failed for '185.104.185.232:58720' - Wrong password
#[2019-12-18 13:42:06] NOTICE[24971] chan_sip.c: Registration from '"9011"<sip:9011@inss.ca>' failed for '37.187.140.178:54685' - Wrong password


# the token number (space separated) where the term with IP (aka '85.203.15.123:59182') appears in PBX wrong password log - so we can parse
# it is counted AFTER(!!) the word 'failed for ' in the log !
IPTOKENLOGNUM=1

# whether the port for wrong attemps is logged, or only the IP (for older asterisk ver)
# leave blank if port is not logged, anything else if port is logged
ISPORTLOGGED=yes

# Sleep seconds interval between log analyze runs; 600 sec = 10 minutes
RUNINTERVAL=600




AWK=`which awk`
SORT=`which sort`
UNIQ=`which uniq`
GREP=`which grep`
DIG=`which dig`
IPTABLES=`which iptables`

BSNAME=$(basename -- "${0}")
IP4TOBLOCKTMPFILE="/tmp/${BSNAME}.temp.txt"
LOGFILE="/var/log/${BSNAME}.log"

THISSERVERIP=`${DIG} +short myip.opendns.com @resolver1.opendns.com`


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
	if ! [ "x${TRUSTEDIPREGEX4}" = "x" ]; then
		TEMPS="$(echo "${IPADDR}" | ${GREP} -e "${TRUSTEDIPREGEX4}")"
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

	# get the list of extensions probed for this IP
        ${GREP} "${IPADDR}" ${ASTERISKLOGFILE} | ${GREP} 'Registration ' | ${GREP} 'failed for' | ${AWK} -F'sip:' '{ print $2}' | ${AWK} '{print $1}' | ${AWK} -F'@' '{print $1}' | ${SORT} | ${UNIQ} | while read EXTEN
	do
		echo -n "    Extension '${EXTEN}' for IP ${IPADDR} will be tested... "
		if ! [ "${EXTEN}" -eq "${EXTEN}" ] 2> /dev/null ; then
			echo -n "'${EXTEN}' is not a number... "
			blacklist "${IPADDR}"
			break
		else
			echo -n "'${EXTEN}' is a number... "
			if [ ${EXTEN} -lt ${MINOKEXTENNUM} ] || [ ${EXTEN} -gt ${MAXOKEXTENNUM} ] ; then
				echo -n " And it is OUT of the accepted range ${MINOKEXTENNUM}:${MAXOKEXTENNUM}. "
				blacklist "${IPADDR}"
				break
			else
				echo " And it is within the accepted range ${MINOKEXTENNUM}:${MAXOKEXTENNUM}. May be legit. "
			fi
		fi
	done

}

processIPsecure () {
	local IPADDR
	local EXTEN
	local MYEXT

	IPADDR="$1"
	checkIP "${IPADDR}"
	RESULT=$?
	[ ${RESULT} -eq 1 ] && return 1

	# get the list of extensions probed for this IP
        # cat ${ASTERISKLOGFILE} | ${GREP} "${IPADDR}" | ${GREP} 'Registration ' | ${GREP} 'failed for' | ${AWK} -F'sip:' '{ print $2}' | ${AWK} '{print $1}' | ${AWK} -F'@' '{print $1}' | ${SORT} | ${UNIQ} | while read EXTEN
	# ${GREP} "RemoteAddress=\"/${IPADDR}/" ${ASTERISKSECURITYLOGFILE} | ${GREP} -v 'UsingPassword="1"' | ${GREP} -v 'SuccessfulAuth' | ${GREP} 'res_security_log.c: ' | ${GREP} 'Service="SIP"' | ${AWK} -F'res_security_log.c: ' '{ print $2 }' | ${AWK} -F',' '{ print $6 }' | ${AWK} -F'=' '{ print $2 }' | ${AWK} -F'"' '{ print $2 }' | ${AWK} -F'@' '{ print $1 }' | ${SORT} | ${UNIQ} | while read MYEXT
	${GREP} "/${IPADDR}/" ${ASTERISKSECURITYLOGFILE} | ${GREP} -v 'UsingPassword="1"' | ${GREP} -v 'SuccessfulAuth' | ${GREP} 'res_security_log.c: ' | ${GREP} 'Service="SIP"' | ${AWK} -F'res_security_log.c: ' '{ print $2 }' | ${AWK} -F',' '{ print $6 }' | ${AWK} -F'=' '{ print $2 }' | ${AWK} -F'"' '{ print $2 }' | ${AWK} -F'@' '{ print $1 }' | ${SORT} | ${UNIQ} | while read MYEXT
	do
		EXTEN="${MYEXT}"
		echo -n "    Extension '${EXTEN}' for IP ${IPADDR} will be tested... "

		TEMPS="$(echo "${MYEXT}" | awk -F':' '{print $1}')"
		if [ "x${TEMPS}" = "xsip" ]; then
			EXTEN="$(echo "${MYEXT}" | awk -F':' '{print $2}')"
			echo -n "Cleared 'sip' prefix, final extension is '${EXTEN}' ... "
		fi
		if ! [ "${EXTEN}" -eq "${EXTEN}" ] 2> /dev/null ; then
			echo -n "'${EXTEN}' is not a number... "
			blacklist "${IPADDR}"
			break
		else
			echo -n "'${EXTEN}' is a number... "
			if [ ${EXTEN} -lt ${MINOKEXTENNUM} ] || [ ${EXTEN} -gt ${MAXOKEXTENNUM} ] ; then
				echo -n " And it is OUT of the accepted range ${MINOKEXTENNUM}:${MAXOKEXTENNUM}. "
				blacklist "${IPADDR}"
				break
			else
				echo " And it is within the accepted range ${MINOKEXTENNUM}:${MAXOKEXTENNUM}. May be legit. "
			fi
		fi
	done

}



analyzeAsteriskLog () {

        THISSERVERIP=`${DIG} +short myip.opendns.com @resolver1.opendns.com`

	echo `date`
        echo "This server IP is ${THISSERVERIP}, will be excluded from blocking"



	# process normal log file (i.e. full; where notice goes)
        echo "Processing log ${ASTERISKLOGFILE}"
	echo
	if [ "x${ISPORTLOGGED}" = "x" ]; then
		# port is NOT logged, must NOT parse out the IP only
                echo "Assiming port is NOT logged in the asterisk log..."
             	${GREP} 'Registration ' ${ASTERISKLOGFILE} | ${GREP} 'failed' | ${AWK} -F'failed for ' '{ print $2}' | ${AWK} "{ print \$${IPTOKENLOGNUM} }" | ${AWK} -F"'" '{ print $2 }' | ${SORT} | ${UNIQ} > ${IP4TOBLOCKTMPFILE}
	else
		# port is logged, must parse out the IP only
                echo "Assiming port IS logged in the asterisk log..."
                ${GREP} 'Registration ' ${ASTERISKLOGFILE} | ${GREP} 'failed' | ${AWK} -F'failed for ' '{ print $2}' | ${AWK} "{ print \$${IPTOKENLOGNUM} }" | ${AWK} -F':' '{ print substr($1,2) }' | ${SORT} | ${UNIQ} > ${IP4TOBLOCKTMPFILE}

	fi
	echo
	while IFS= read -r line
	do
		processIP "${line}"
		echo
	done < "${IP4TOBLOCKTMPFILE}"



	# process security log file
        echo "Processing log ${ASTERISKSECURITYLOGFILE}"
	echo
	if [ -f ${ASTERISKSECURITYLOGFILE} ]; then
		# collect ips of possible intruders
		${GREP} -v 'UsingPassword="1"' ${ASTERISKSECURITYLOGFILE} | ${GREP} 'res_security_log.c: ' | ${GREP} -v 'SuccessfulAuth' | ${GREP} 'Service="SIP"' | ${AWK} -F'res_security_log.c: ' '{ print $2 }' | ${AWK} -F',' '{ print $9 }' | ${AWK} -F'=' '{ print $2 }' | ${AWK} -F'"' '{ print $2 }' | ${AWK} -F'/' '{ print $3 }' | ${SORT} | ${UNIQ} > ${IP4TOBLOCKTMPFILE}
        	while IFS= read -r line
        	do
                	processIPsecure "${line}"
                	echo
        	done < "${IP4TOBLOCKTMPFILE}"
	else
		echo "Security log file ${ASTERISKSECURITYLOGFILE} does not exist! Please configure it."
	fi

}



main () {
	while :
	do
		# echo "Press [CTRL+C] to stop.."
		if test -f "$XTRECENTBLACKLIST"; then
			analyzeAsteriskLog > ${LOGFILE}
			# echo "..."
		else
			echo "iptables file ${XTRECENTBLACKLIST} does not exist, skipping run..."
		fi
		sleep ${RUNINTERVAL}
	done
}


main &


