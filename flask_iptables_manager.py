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
    os.popen('iptables -I INPUT -p tcp --dport %s -m state --state NEW -j ACCEPT -m comment --comment "Flask验证服务端口，默认规则"' % (FLASK_PORT))
    
FLASK_PATH = '/%s' % (sys.argv[2].strip()) # 运行的route
app = Flask(__name__)


@app.route('/')
def index():
    return 'Hello, World!'
@app.route(FLASK_PATH)
def hello_index():
    ip = request.remote_addr
    existed = os.popen("iptables -L | grep %s" % (ip)).read()
    if(len(existed.strip())==0):
        os.popen("iptables -A INPUT -s %s -j ACCEPT -m comment --comment \"`date`\" &> /dev/null" % (ip))
        return ip+" add success"
    else:
        return ip+" existed"
    #return ip
@app.route(FLASK_PATH+"/admin/")
def admin():
    #a = os.popen("iptables -L INPUT -v -n --line-number | grep -v 'dpt:%s' | grep -v 'ssh服务端口'" % (FLASK_PORT)).read()
    a = os.popen("iptables -L INPUT -v -n --line-number").read()
    a = a.split("\n")[2:]
    # html = '<table border="1"><tr><th>num</th><th>target</th><th>prot</th><th>opt</th><th>source</th><th>destination</th><th>unknown</th></tr>'
    # for b in a:
    #     if(len(b)>5):
    #         html = html + '<tr>'
    #         #print(b.split("    "))
    #         c = b
    #         #print(c)
            
    #         num=c.split(" ")[0]
    #         html = html + '<td>'+num+'</td>'
    #         c=c[len(num):].strip()
            
    #         target=c.split(" ")[0]
    #         html = html + '<td>'+target+'</td>'
    #         c=c[len(target):].strip()
            
    #         prot=c.split(" ")[0]
    #         html = html + '<td>'+prot+'</td>'
    #         c=c[len(prot):].strip()
            
    #         opt=c.split(" ")[0]
    #         html = html + '<td>'+opt+'</td>'
    #         c=c[len(opt):].strip()
            
    #         source=c.split(" ")[0]
    #         html = html + '<td>'+source+'</td>'
    #         c=c[len(source):].strip()
            
    #         destination=c.split(" ")[0]
    #         html = html + '<td>'+destination+'</td>'
    #         c=c[len(destination):].strip()
            
    #         other=c.split("  ")[0]
    #         html = html + '<td>'+other+'</td>'
    #         c=c[len(other):].strip()
        
    #         html = html + '</tr>'
    # html = html + '</table>'
    
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
    ip = request.form['ip']
    #加端口白名单
    if(ip.split(".")[0]==ip):
        port = int(ip)
        if(port in range(1,65535)):
            existed = os.popen("iptables -L INPUT -n | grep dpt:%s" % (port)).read()
            if(len(existed.strip())==0):
                status,result = commands.getstatusoutput("iptables -I INPUT -p tcp --dport %s -m state --state NEW -j ACCEPT -m comment --comment \"`date`\" &> /dev/null" % (port))
                data = {'status':str(status),'result':result}
            else:
                data = {'status':999,'result':str(port)+"已经存在端口白名单！"}
                
        else:
            data = {'status':999,'result':'端口必须在0-65535之间！'}
        return json.dumps(data)
    
            
    # 加IP白名单
    if(ip.split("/")[0]==ip):
        ip = ip+"/32"
    pattern = re.compile(r'^(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\/([1-9]|[1-2]\d|3[0-2])$')
    if(pattern.match(ip)!=None):
        #print("iptables -L INPUT -n | grep '%s'" % (ip))
        existed = os.popen("iptables -L INPUT -n | grep '%s'" % (ip.split("/")[0])).read()
        #print(existed)
        if(len(existed.strip())==0):
            status,result = commands.getstatusoutput("iptables -A INPUT -s %s -j ACCEPT -m comment --comment \"`date`\" &> /dev/null" % (ip))
            data = {'status':str(status),'result':result}
        else:
            data = {'status':999,'result':str(ip)+"已经存在IP白名单！"}
    else:
        data = {'status':999,'result':'IP检查失败'}
    return json.dumps(data)
app.run(host='0.0.0.0',port=FLASK_PORT,debug=True)
