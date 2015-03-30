#!/bin/bash

# Creates apache vhost on ip:port; securely configured
# ip:port must be already enabled in Listen directives /etc/apache2/ports.conf
#
#
# params: ( docroot is relative to current directory where the script is run )
# ip port host docroot
#
# example (for advanced template):
# ./create-apache-virtualhost.sh 192.168.167.184 8000 host1-debian-box.local /var/www/debianlampuser/host1-debian-box.local/[frontend]/web
# ./create-apache-virtualhost.sh 192.168.167.184 8000 host1-debian-box.local /var/www/debianlampuser/host1-debian-box.local/[backend]/web
# aka
# ./create-apache-virtualhost.sh 192.168.167.184 8000 gurulink.ca /var/www/debianlampuser/gurulink.ca/www/web
# ./create-apache-virtualhost.sh 192.168.167.184 8000 gururms.gurulink.ca /var/www/debianlampuser/gurulink.ca/gururms/web
#
# example (for basic template):
# ./create-apache-virtualhost.sh 192.168.167.184 8000 host1-debian-box.local /var/www/debianlampuser/host1-debian-box.local/web
# aka
# ./create-apache-virtualhost.sh 192.168.167.184 8000 hirelogix.ca /var/www/debianlampuser/hirelogix.ca/web
#


IP="$1"
PORT="$2"
HOST="$3"
DOCROOTDIR="$4"


APACHEVSITES_DIR=/etc/apache2/sites-available
ABS_SITE_ROOTDIR=$(realpath -m ${DOCROOTDIR})
ABS_SITE_DIR=$(dirname ${ABS_SITE_ROOTDIR})


echo "Vhost will respond at ${IP}:${PORT} under ${HOST} and www.${HOST}"
echo "-- Absolute vhost general dir: ${ABS_SITE_DIR}"
echo "----- Absolute site root index   subdir: ${ABS_SITE_ROOTDIR}"
echo "----- Absolute site tmp files    subdir: ${ABS_SITE_ROOTDIR}/tmp"
echo "----- Absolute site php-err log  subdir: ${ABS_SITE_DIR}/log"
echo "----- Absolute site web sessions subdir: ${ABS_SITE_ROOTDIR}/session"
echo "-- Absolute site apache2 log dir: [APACHE_LOG_DIR]"

echo
echo "--> [Re]creating ${HOST} vhost config: ${APACHEVSITES_DIR}/${HOST}.conf ..."

cat > ${APACHEVSITES_DIR}/${HOST}.conf <<DELIMITER
<VirtualHost ${IP}:${PORT}>

        ServerName ${HOST}
        ServerAlias www.${HOST}

        DocumentRoot ${ABS_SITE_ROOTDIR}

        ### INCLUDE DEFAULT virtualhost config template
	### securely blocks everything
        Include /etc/apache2/site-templates/default.conf


        ### NOW OVERRIDE DEFAULT virtualhost config template (or add more options), as needed:
	### ******* override Apache and PHP configuration from default site-template ******
	### see a lot more options and detailed comments on some of these, in default site-template included above
	###

	# enable next two for development only, disable in production
	php_flag display_errors On
	php_flag html_errors On

	php_admin_value error_log ${ABS_SITE_DIR}/log/${HOST}_php-err.log

	php_admin_value open_basedir ${ABS_SITE_DIR}/:/usr/share/php/:/usr/share/php5/:/dev/urandom:/usr/share/doc/php5-apcu/apc.php

	php_admin_value session.save_path ${ABS_SITE_DIR}/session

	php_admin_value upload_tmp_dir ${ABS_SITE_DIR}/tmp

	#now allow just site's directory
        <Directory ${ABS_SITE_ROOTDIR}>
                Options +FollowSymLinks
                AllowOverride None
                Order Allow,Deny
                Allow from all
		<LimitExcept GET POST OPTIONS>
			Order Allow,Deny
			Deny from all
		</LimitExcept>

	        ###
	        ### Recommended by Yii2 config guide
		### if a file/dir in the GET request does not exist (aka www.host.com/gseg/svs/afsf/svfs) then it goes to index.php in root dir,
		### with the path /gseg/svs/afsf/svfs in the GET request variable
	        ###
	        # use mod_rewrite for pretty URL support
	        RewriteEngine on
	        # If a directory or a file exists, use the request directly
	        RewriteCond %{REQUEST_FILENAME} !-f
	        RewriteCond %{REQUEST_FILENAME} !-d
	        # Otherwise forward the request to index.php
	        RewriteRule . index.php
        </Directory>

        # Possible values include: debug, info, notice, warn, error, crit,
        # alert, emerg.
        LogLevel warn

        ErrorLog \${APACHE_LOG_DIR}/${HOST}_error.log
	CustomLog \${APACHE_LOG_DIR}/${HOST}_access.log vhost_combined

</VirtualHost>

DELIMITER

echo "--> ...all previous vhost settings for ${HOST} have been reset. "


echo
echo "--> Checking apache2 configuration and (re)enabling ${HOST} site ..."
echo
apache2ctl -S && a2ensite ${HOST} && /etc/init.d/apache2 reload
