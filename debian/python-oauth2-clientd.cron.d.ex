#
# Regular cron jobs for the python-oauth2-clientd package.
#
0 4	* * *	root	[ -x /usr/bin/python-oauth2-clientd_maintenance ] && /usr/bin/python-oauth2-clientd_maintenance
