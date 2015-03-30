#!/bin/bash

BASEDIR=/root/configuration-history/

for sdir in `ls ${BASEDIR} | grep '^[0-9][0-9][0-9]' | sort`; do
	# echo ${sdir}
	DNUM="$( cut -d '-' -f 1 <<< "${sdir}" )"
	DACTION="$( cut -d '-' -f 2- <<< "${sdir}" )"
	echo "* ${DACTION} (${DNUM}):"
	for sfile in `ls ${BASEDIR}/${sdir}/ | grep '^[0-9][0-9][0-9][0-9].*[\.]txt.*' | sort`; do
		BSNAME=$(basename "${sfile}")
		FNUM="$( cut -d '-' -f 1 <<< "${BSNAME}" )"
		FACTION="$( cut -d '-' -f 2- <<< "${BSNAME}" )"
		EXTN="${FACTION##*.}"
		BASFACT="${FACTION%.*}"
		echo -e -n '\t'
		if [ "${EXTN}" == "done" ]; then
			echo "APPLIED: ${BASFACT} (${FNUM})"
		elif [ "${EXTN}" == "txt" ]; then
			echo "SKIPPED: ${BASFACT} (${FNUM})"
		elif [ "${EXTN}" == "partial" ]; then
			echo "PARTIALLY APPLIED: ${BASFACT} (${FNUM})"
		else
			echo "ERR: Unable to handle file ${BSNAME}: parsing to ${FACTION} (${FNUM}) ${BASFACT} ${EXTN}"
		fi
	done
	echo
done
