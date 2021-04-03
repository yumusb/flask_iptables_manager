#!/bin/bash
red='\e[91m'
green='\e[92m'
yellow='\e[93m'
magenta='\e[95m'
cyan='\e[96m'
none='\e[0m'

#删除所有IP规则
rm_ip_rules() {
    tables=$(iptables -nL INPUT --line-numbers | grep -v "0.0.0.0/0            0.0.0.0/0" | grep -E "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"  | awk -F ' ' '{print $1}' | tac)
    for i in $tables;  
    do
    iptables -D INPUT $i ;  
    done
}
#删除所有端口规则 排除SSH
rm_port_rules() {
    sshport=`netstat -ntlp | awk '!a[$NF]++ && $NF~/sshd$/{sub (".*:","",$4);print $4}'`
    if [ -z "$sshport" ]; then
        echo -e "没获取到你小鸡的${red} ssh服务 ${none}端口哦！为了防止机器失连，脚本退出~ ${yellow}~(^_^) ${none}" && exit 1
    fi
    tables=$(iptables -L INPUT -v -n --line-numbers | grep "dpt:" | grep -v "dpt:$sshport" | awk -F ' ' '{print $1}' | tac)
    for i in $tables;  
    do
    iptables -D INPUT $i ;  
    done
}
#获取IP信息
get_ip() {
	ip=$(curl -s https://www.bt.cn/Api/getIpAddress)
	[[ -z $ip ]] && ip=$(curl -s https://ipinfo.io/ip)
	[[ -z $ip ]] && ip=$(curl -s https://api.ip.sb/ip)
	[[ -z $ip ]] && ip=$(curl -s https://api.ipify.org)
	[[ -z $ip ]] && ip=$(curl -s https://ip.seeip.org)
	[[ -z $ip ]] && ip=$(curl -s https://ifconfig.co/ip)
	[[ -z $ip ]] && ip=$(curl -s https://api.myip.com | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}")
	[[ -z $ip ]] && ip=$(curl -s icanhazip.com)
	[[ -z $ip ]] && ip=$(curl -s myip.ipip.net | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}")
	[[ -z $ip ]] && echo -e "\n$red 这垃圾小鸡扔了吧！$none\n" && exit
}

down_file() {
	#BASE_URL="https://gitee.com/yumusb/flask_iptables_manager/raw/master/"
	#files=[]
	git clone "https://gitee.com/yumusb/flask_iptables_manager.git"
}

#检查是否root用户
[[ $(id -u) != 0 ]] && echo -e " 哎呀……请使用 ${red}root ${none}用户运行 ${yellow}~(^_^) ${none}" && exit 1

#如果有该进程则杀掉
pid=`ps -aux | grep 'python flask_iptables_manager.py' | grep -v grep | awk '{print $2}'`
[[ -n $pid ]] && kill -9 $pid && echo "已杀死$pid"

#判断包管理类型

if [[ $(command -v yum) ]]; then
	cmd="yum"
elif [[ $(command -v apt) ]]; then
    cmd="apt"
else
    echo -e "暂不支持你的系统哦！" && exit 1
fi

# 环境配置
$cmd update -y
$cmd install wget -y
$cmd install python-pip -y
$cmd install iptables -y
$cmd install git -y
python -m pip install flask

if [ -z $HOME ]; then
  export HOME=~
fi
cd $HOME
rm -rf flask_iptables_manager
down_file
cd flask_iptables_manager

# 配置 iptables
iptables -P INPUT ACCEPT
iptables -F

#把SSH端口加到白名单
sshport=`netstat -ntlp | awk '!a[$NF]++ && $NF~/sshd$/{sub (".*:","",$4);print $4}'`
if [ -z "$sshport" ]; then
    echo -e "没获取到你小鸡的${red} ssh服务 ${none}端口哦！为了防止机器失连，脚本退出~ ${yellow}~(^_^) ${none}" && exit 1
fi
iptables -I INPUT -p tcp --dport $sshport -j ACCEPT -m comment --comment "ssh服务端口，默认规则"
echo -e "获取到你小鸡的${red} ssh ${none}运行端口在 ${yellow}$sshport ${none}，已经加白~"

#把SSH历史登录IP加白
lastip=`last | grep -E "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" | awk -F ' ' '{print $3}' | uniq`
for lastip1 in $lastip;
do 
iptables -I INPUT -s $lastip1 -j ACCEPT -m comment --comment "ssh历史登录IP";
echo -e "历史SSH登陆IP ${red} $lastip1 ${none}，已经加白~";
done

#拒绝所有连接，并允许主动外联行为
iptables -P INPUT DROP
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT -m comment --comment "默认规则"
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT -m comment --comment "默认规则"

#flask服务端口
echo "你的验证服务将要运行在哪个端口？[0-65535]"
read flaskport
iptables -I INPUT -p tcp --dport $flaskport -j ACCEPT -m comment --comment "Flask验证服务端口，默认规则"
echo "[+]-----------[+]"
#获取路径 
flaskroute=`date +%s%N | md5sum | head -c 8`
get_ip
LOCAL_IP=$(ip addr | grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -E -v "^127\.|^255\.|^0\." | head -n 1)
echo -e "你的激活服务运行在 \n${red}http://$ip:$flaskport/$flaskroute ${none}\n${green}http://$LOCAL_IP:$flaskport/$flaskroute ${none}" 

#驻守服务

sed -i "s/yourport/$flaskport/" manager.sh
sed -i "s/yourpath/$flaskroute/" manager.sh

chmod +x manager.sh
bash manager.sh
cat >/tmp/iptables_manager.service <<EOL
[Unit]
Description=Help to create iptables
[Service]
ExecStart=$HOME/flask_iptables_manager/manager.sh
Restart=always
Nice=10
CPUWeight=1
[Install]
WantedBy=multi-user.target
EOL
sudo mv /tmp/iptables_manager.service /etc/systemd/system/iptables_manager.service
sudo systemctl daemon-reload
sudo systemctl enable iptables_manager.service
sudo systemctl start iptables_manager.service