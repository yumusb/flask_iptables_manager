#!/usr/bin/env python3
# coding:utf-8
# @Author: yumu
# @Date:   2020-08-22
# @Email:   yumusb@foxmail.com
# @Last Modified by:   yumu
# @Last Modified time: 2020-08-22

from flask import Flask,request,render_template
import sys,os,commands,json,re

reload(sys)
sys.setdefaultencoding('utf8')

if(len(sys.argv)!=3):
    exit("usage: python %s (int)[port] (string)[path]" % (sys.argv[0]))
FLASK_PORT = int(sys.argv[1]) # 运行的端口


if(len(os.popen("iptables -nL | grep dpt:%s" % (FLASK_PORT)).read().strip())==0):
    os.popen('iptables -I INPUT -p tcp --dport %s -j ACCEPT -m comment --comment "Flask验证服务端口，默认规则"' % (FLASK_PORT))
    
FLASK_PATH = '/%s' % (sys.argv[2].strip()) # 运行的route
app = Flask(__name__)


@app.route('/')
def index():
    return 'Hello, World!'
@app.route(FLASK_PATH)
def hello_index():
    ip = request.remote_addr
    existed = os.popen("iptables -nL | grep '%s'" % (ip)).read()
    if(len(existed.strip())==0):
        os.popen("iptables -A INPUT -s {0} -j ACCEPT -m comment --comment \"`date '+%Y_%m_%d %H:%M:%S'`\" &> /dev/null" .format(ip))
        return ip+" add success"
    else:
        return ip+" existed"
    #return ip
@app.route(FLASK_PATH+"/admin/")
def admin():
    a = os.popen("iptables -L INPUT -v -n --line-number").read()
    a = a.split("\n")[2:]
    b = os.popen("iptables -nL INPUT | head -1").read()
    return render_template('admin.html',iptables=a,default=b)
@app.route(FLASK_PATH+"/admin/del/",methods=['POST'])
def admin_del():
    id = request.form['id']
    #print("iptables -D INPUT "+str(id))
    status,result = commands.getstatusoutput("iptables -D INPUT "+str(id))
    #print(res)
    data = {'status':str(status),'result':result}
    return json.dumps(data)
    
@app.route(FLASK_PATH+"/admin/DelAllPortRules/",methods=['POST'])
def DelAllPortRules():
    status,result = commands.getstatusoutput("sshport=`netstat -ntlp | awk '!a[$NF]++ && $NF~/sshd$/{sub (\".*:\",\"\",$4);print $4}'`;for i in $(iptables -nL INPUT --line-numbers | grep -v \"dpt:%s\" | grep -v \"dpt:$sshport\" | grep 'dpt:' | awk -F ' ' '{print $1}' | tac); do iptables -D INPUT $i ; done" % (FLASK_PORT))
    #print(res)
    data = {'status':str(status),'result':result}
    return json.dumps(data)
@app.route(FLASK_PATH+"/admin/DelAllIpRules/",methods=['POST'])
def DelAllIpRules():
    status,result = commands.getstatusoutput("for i in $(iptables -nL INPUT --line-numbers | grep -v \"0.0.0.0/0            0.0.0.0/0\" | grep -E \"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\" |  grep -v '%s' | awk -F ' ' '{print $1}' | tac); do iptables -D INPUT $i ; done" % (request.remote_addr))
    #print(res)
    data = {'status':str(status),'result':result}
    return json.dumps(data)
    
@app.route(FLASK_PATH+"/admin/add/",methods=['POST'])
def admin_add():
    param = request.form['p']
    params = param.split(chr(32)) # 空格
    params = param.split(chr(10)) # 换行
    params = param.split(",")
    base_commands = []
    pattern = re.compile(r'^(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/([1-9]|[1-2]\d|3[0-2])){0,1}$')
    for p in params:
        p = p.strip()
        if(("." not in p) and int(p) in range(1,65535)):
            existed = os.popen("iptables -L INPUT -n | grep \"dpt:%s \" " % p).read()
            if(len(existed.strip())==0):
                base_commands.append("iptables -I INPUT -p tcp --dport {0} -j ACCEPT -m comment --comment \"`date '+%Y_%m_%d %H:%M:%S'`\" &> /dev/null".format(p))
        elif(pattern.match(p)!=None):
            existed = os.popen("iptables -L INPUT -n | grep '%s'" % p).read()
            if(len(existed.strip())==0):
                base_commands.append("iptables -A INPUT -s {0} -j ACCEPT -m comment --comment \"`date '+%Y_%m_%d %H:%M:%S'`\" &> /dev/null".format(p))
    if(len(base_commands)>0):
        status,result = commands.getstatusoutput(";".join(base_commands))
        data = {'status':str(status),'result':result}
    else:
        data = {'status':str(999),'result':"参数有问题"}
    return json.dumps(data)
app.run(host='0.0.0.0',port=FLASK_PORT,debug=True)
