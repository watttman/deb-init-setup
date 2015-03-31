#!/bin/bash

#
# Fixes permissions and ownership for website file hierarchy (inside site-top-directory assumes web subdir for root, and tmp and session subdirs) 
# site-top-directory is the path after /var/www/username/
# creates site-top-directory/{web,tmp,session} hierarchy 
#
# params: username site-top-directory
#
#
# example (for advanced template):
# ./reset-website-dirs.sh debianlampuser host1-debian-box.local/[frontend]
# aka
# ./reset-website-dirs.sh debianlampuser gurulink.ca/gururms
#
# example (for basic template):
# ./reset-website-dirs.sh debianlampuser host1-debian-box.local
# aka
# ./reset-website-dirs.sh debianlampuser hirelogix.ca



SITEUSER="$1"
SITEDIR="$2"

BASEAPACHEDIR=/var/www
BASEWEBDIR=${BASEAPACHEDIR}/${SITEUSER}
ABS_SITE_DIR=${BASEWEBDIR}/${SITEDIR}

echo
echo "-- Base user web dir: ${BASEWEBDIR}"
echo "-- Base vhost site dir: ${ABS_SITE_DIR}"

echo
echo "--> Touching ${BASEWEBDIR} to ensure it exists..."
mkdir -p ${BASEWEBDIR} || { echo "Can't mkdir -p base user web dir ${BASEWEBDIR}"; exit 1; }
echo
echo "--> Touching ${ABS_SITE_DIR}/{web,tmp,session} to ensure it exists..."
mkdir -p ${ABS_SITE_DIR}/{web,tmp,session,log} || { echo "Can't mkdir -p the vhost site dir ${ABS_SITE_DIR}/{web,tmp,session,log} hierarchy"; exit 1; }





echo
echo "--> Setting test index.php file in root ..."
# create base index.asp, unless it already exists
[ -f ${ABS_SITE_DIR}/web/index.php ] && echo "/web/index.php already exists, skipping creation of sample index.php file... " || cat > ${ABS_SITE_DIR}/web/index.php <<DELIMITER
<?php
        # start session to test session writing
        session_start();

        # put message in error log to test php error logging
        error_log('test error log!',0);

        # write to rw area
        touch(realpath('../tmp') . '/' . 'testfile-in-tmp-by-apachephp.txt');
        mkdir(realpath('../tmp') . '/' . 'testdir-in-tmp-by-apachephp');
        touch(realpath('../tmp/testdir-in-tmp-by-apachephp') . '/' . 'testfile-by-apachephp.txt');
        touch(realpath('../session') . '/' . 'testfile-in-session.txt');

	echo "<center>Vhost ServerName: \${_SERVER['HTTP_HOST']}</center>";
	phpinfo();

DELIMITER





echo
echo "--> Fixing filesystem permissions for base user web dir..."

# set basewebdir permissions to siteuser:siteuser rw:rw
chown root:${SITEUSER} ${BASEWEBDIR}
chmod u=rwX,g=rwX,o=x ${BASEWEBDIR}
chown ${SITEUSER}:${SITEUSER} ${BASEWEBDIR}/*



echo
echo "--> Fixing filesystem permissions for vhost site dir..."

# set siteuser:www-data + sticky guid bit to dirs so all created belongs to apache group
# fix: do not touch any dirs out of {tmp,log,session} !
# chown -R ${SITEUSER}:www-data ${ABS_SITE_DIR}
chown ${SITEUSER}:www-data ${ABS_SITE_DIR}
chown ${SITEUSER}:www-data ${ABS_SITE_DIR}/{tmp,log,session}

# set readwrite:readwrite siteuser:www-data so both apache/php can write in tmp,log
chmod -R u=rwX,g=rwX,o-rwx ${ABS_SITE_DIR}/{tmp,log}
find ${ABS_SITE_DIR}/{tmp,log} -type d -exec chmod g+s {} +
find ${ABS_SITE_DIR}/{tmp,log} -type d -exec chmod u-s {} +

# set readwrite:readwrite www-data:www-data so apache/php can write in session
chmod u=rw,g=rwX,o-rwx ${ABS_SITE_DIR}/session
chmod g+s ${ABS_SITE_DIR}/session
# chown -R www-data:www-data ${ABS_SITE_DIR}/session/*
# chmod -R u=rw,g-rwx,o-rwx ${ABS_SITE_DIR}/session/*

# set rewrite:readonly siteuser:www-data so apache/php can readonly in web
# TODO hmmm, we may try to re-enable this? to verify after Yii2 template install
# chmod -R u=rwX,g=rX,o-rwx ${ABS_SITE_DIR}/web
# find ${ABS_SITE_DIR}/web -type d -exec chmod g+s {} +



echo
echo "--> Checking apache2 configuration  ..."
echo
apache2ctl -S
