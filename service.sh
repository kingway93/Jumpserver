#!/bin/bash
# jumpserver        Startup script for the jumpserver Server
#
# chkconfig: - 85 12
# description: Open source detecting system
# processname: jumpserver
# Date: 2016-02-27
# Version: 3.0.1
# Site: http://www.jumpserver.org
# Author: Jumpserver Team

jumpserver_dir=

base_dir=$(dirname $0)
jumpserver_dir=${jumpserver_dir:-$base_dir}
export PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

if [ -f ${jumpserver_dir}/install/functions ];then
    . ${jumpserver_dir}/install/functions
elif [ -f /etc/init.d/functions ];then
    . /etc/init.d/functions
else
    echo "No functions script found in [./functions, ./install/functions, /etc/init.d/functions]"
    exit 1
fi

PROC_NAME="jumpserver"
lockfile=/var/lock/subsys/${PROC_NAME}

start() {
        if [ $(whoami) != 'root' ];then
            echo "Sorry, JMS must be run as root"
            exit 1
        fi

        # 日志和key的目录更改到/srv目录下
        [[ -d '/srv/logs/jumpserver' ]] || mkdir /srv/logs/jumpserver -p
        [[ -d '/srv/keys/jumpserver/keys' ]] || mkdir /srv/keys/jumpserver -p
        chmod 777 /srv/keys

        jump_start=$"Starting ${PROC_NAME} service:"
        if [ -f $lockfile ];then
             echo -n "jumpserver is running..."
             success "$jump_start"
             echo
        else
            daemon python $jumpserver_dir/manage.py crontab add &>> /var/log/jumpserver.log 2>&1
            daemon python $jumpserver_dir/run_server.py &> /dev/null 2>&1 &
            sleep 1
            echo -n "$jump_start"
            ps axu | grep 'run_server' | grep -v 'grep' &> /dev/null
            if [ $? == '0' ];then
                success "$jump_start"
                if [ ! -e $lockfile ]; then
                    lockfile_dir=`dirname $lockfile`
                    mkdir -pv $lockfile_dir
                fi
                touch "$lockfile"
                echo
            else
                failure "$jump_start"
                echo
            fi
        fi
}


stop() {
    echo -n $"Stopping ${PROC_NAME} service:"
    daemon python $jumpserver_dir/manage.py crontab remove &>> /var/log/jumpserver.log 2>&1
    ps aux | grep -E 'run_server.py' | grep -v grep | awk '{print $2}' | xargs kill -9 &> /dev/null
    ret=$?
    if [ $ret -eq 0 ]; then
        echo_success
        echo
        rm -f "$lockfile"
    else
        echo_failure
        echo
        rm -f "$lockfile"
    fi

}

status(){
    ps axu | grep 'run_server' | grep -v 'grep' &> /dev/null
    if [ $? == '0' ];then
        echo -n "jumpserver is running..."
        success
        touch "$lockfile"
        echo
    else
        echo -n "jumpserver is not running."
        failure
        echo
    fi
}



restart(){
    stop
    start
}

copy_config(){
    ENV=$1
    BASE_DIR=$(cd `dirname $0`; pwd)
    ENV_DIR=$BASE_DIR/env
    cp $ENV_DIR/$ENV.conf $BASE_DIR/jumpserver.conf
}

# See how we were called.
case "$1" in
  start)
        ENV=$2
        if [[ $ENV == 'dev26' || $ENV  == 'online' ]]
        then
            copy_config $ENV
            start
        else
            echo $"Usage: $0 {start enviroment(dev26|online)|stop|restart|status}"
        fi
        ;;
  stop)
        stop
        ;;

  restart)
        restart
        ;;

  status)
        status
        ;;
  *)
        echo $"Usage: $0 {start enviroment(dev26|online)|stop|restart|status}"
        exit 2
esac
