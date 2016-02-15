#!/bin/sh
#
### BEGIN INIT INFO
# Provides:          ext_virus_total
# Required-Start:    $local_fs $network $remote_fs
# Required-Stop:     $local_fs $network $remote_fs
# Should-Start:      $NetworkManager
# Should-Stop:       $NetworkManager
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: starts instance of ext_virus_total
# Description:       starts instance of ext_virus_total using start-stop-daemon
### END INIT INFO

# Load the VERBOSE setting and other rcS variables
. /lib/init/vars.sh

# Define LSB log_* functions.
# Depend on lsb-base (>= 3.0-6) to ensure that this file is present.
. /lib/lsb/init-functions

# Source ext_virus_total configuration
if [ -f /etc/default/ext_virus_total ]; then
    . /etc/default/ext_virus_total
else
    [ "${VERBOSE}" != no ] && echo "/etc/default/ext_virus_total not found. Using default settings.";
fi

## Don't set -e
## Don't edit this file!
## Edit user configuation in /etc/default/ext_virus_total to change
##

#This file goes to /etc/default/ext_virus_total
## VT_USER=root         #$RUN_AS, username to run ext_virus_total under, the default is root
## VT_GROUP=root        #$RUN_GROUP, group to run ext_virus_total under, the default is root
## VT_HOME=/home/user/Desktop/virustotal         #$APP_PATH, the location of ext_virus_total.py, the default is /opt/ext_virus_total
## VT_DATA=/opt/ext_virus_total         #$DATA_DIR, the location of ext_virus_total.db, cache, logs, the default is /opt/ext_virus_total
## VT_PIDFILE=/var/run/ext_virus_total/ext_virus_total.pid      #$PID_FILE, the location of ext_virus_total.pid, the default is /var/run/ext_virus_total/ext_virus_total.pid
## PYTHON_BIN=      #$DAEMON, the location of the python binary, the default is /usr/bin/python2.7
## VT_OPTS=         #$EXTRA_DAEMON_OPTS, extra cli option for ext_virus_total, i.e. " --config=/home/ext_virus_total/config.ini"
## SSD_OPTS=        #$EXTRA_SSD_OPTS, extra start-stop-daemon option like " --group=users"
##
## EXAMPLE if want to run as different user
## add VT_USER=username to /etc/default/ext_virus_total
## otherwise default ext_virus_total is used

# Script name
NAME=$(basename "$0")

# App name
APP_NAME=ext_virus_total.py

# Description
DESC=Ext_Virus_Total

## The defaults
# Run as username
RUN_AS=${VT_USER-ext_virus_total}

# Run as group
RUN_GROUP=${VT_GROUP-ext_virus_total}

# Path to app VT_HOME=path_to_app_ext_virus_total.py
APP_PATH=${VT_HOME-/opt/ext_virus_total}

# Data directory where virus_total.db, cache and logs are stored
DATA_DIR=${VT_DATA-/opt/ext_virus_total}

# Path to store PID file
PID_FILE=${VT_PIDFILE-/var/run/ext_virus_total/ext_virus_total.pid}

# path to python bin
DAEMON=${PYTHON_BIN-/usr/bin/python2.7}

# Extra daemon option like: VT_OPTS=" --config=/home/ext_virus_total/config.ini"
EXTRA_DAEMON_OPTS=${VT_OPTS-}

# Extra start-stop-daemon option like START_OPTS=" --group=users"
EXTRA_SSD_OPTS=${SSD_OPTS-}
##

PID_PATH=$(dirname $PID_FILE)
DAEMON_OPTS=" $APP_NAME -q --daemon --nolaunch --pidfile=${PID_FILE} --datadir=${DATA_DIR} ${EXTRA_DAEMON_OPTS}"

##

test -x $DAEMON || exit 0

# Create PID directory if not exist and ensure the ext_virus_total user can write to it
if [ ! -d $PID_PATH ]; then
    mkdir -p $PID_PATH
    chown $RUN_AS $PID_PATH
fi

if [ ! -d $DATA_DIR ]; then
    mkdir -p $DATA_DIR
    chown $RUN_AS $DATA_DIR
fi

if [ -e $PID_FILE ]; then
    PID=`cat $PID_FILE`
    if ! kill -0 $PID > /dev/null 2>&1; then
        [ "$VERBOSE" != no ] && echo "Removing stale $PID_FILE"
        rm -f $PID_FILE
    fi
fi

start_ext_virus_total() {
    [ "$VERBOSE" != no ] && log_daemon_msg "Starting $DESC" "$NAME"
    start-stop-daemon -d $APP_PATH -c $RUN_AS --group=${RUN_GROUP} $EXTRA_SSD_OPTS --start --quiet --pidfile $PID_FILE --exec $DAEMON -- $DAEMON_OPTS
    RETVAL="$?"
    case "${RETVAL}" in
        # Service was started or was running already
        0|1) [ "${VERBOSE}" != no ] && log_end_msg 0 ;;
        # Service couldn't be started
        2) [ "${VERBOSE}" != no ] && log_end_msg 1 ;;
    esac
    [ "${RETVAL}" = 2 ] && return 2
    return 0
}

stop_ext_virus_total() {
    [ "$VERBOSE" != no ] && log_daemon_msg "Stopping $DESC" "$NAME"
    start-stop-daemon --stop --pidfile $PID_FILE --quiet --retry TERM/30/KILL/5
    RETVAL="$?"
    case "${RETVAL}" in
        # Service was stopped or wasn't running
        0|1) [ "${VERBOSE}" != no ] && log_end_msg 0 ;;
        # Service couldn't be stopped
        2) [ "${VERBOSE}" != no ] && log_end_msg 1 ;;
    esac
    [ "${RETVAL}" = 2 ] && return 2
    [ -f "${PID_FILE}" ] && rm -f ${PID_FILE}
    return 0
}

case "$1" in
    start)
        start_ext_virus_total
        exit $?
        ;;
    stop)
        stop_ext_virus_total
        exit $?
        ;;

    restart|force-reload)
        stop_ext_virus_total
        sleep 2
        start_ext_virus_total
        exit $?
        ;;
    status)
        status_of_proc -p "$PID_FILE" "$DAEMON" "$DESC"
        exit $?
        ;;
    *)
        N=/etc/init.d/$NAME
        echo "Usage: $N {start|stop|restart|force-reload}" >&2
        exit 1
        ;;
esac

exit 0
