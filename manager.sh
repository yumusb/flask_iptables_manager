#!/bin/bash
pid=`ps -aux | grep "flask_iptables_manager.py" | grep -v "grep" | awk '{print $2}'`
[[ -n $pid ]] && kill -9 $pid && echo "已杀死旧进程 $pid"
nohup python3 flask_iptables_manager.py yourport yourtoken > /dev/null 2>&1 &
pid=`ps -aux | grep "flask_iptables_manager.py" | grep -v "grep" | awk '{print $2}'`
echo "服务运行pid: $pid"