#!/usr/bin/env python3
# coding:utf-8
# @Author: yumu
# @Date:   2020-08-22
# @Email:   yumusb@foxmail.com
# @Last Modified by:   yumu
# @Last Modified time: 2020-08-22

from flask import Flask,request,render_template,session,redirect,url_for,flash
import sys,os,subprocess,json,re
import pyotp
import datetime
import time
import base64

#from imp import reload
# reload(sys)
# sys.setdefaultencoding('utf8')

if(len(sys.argv)!=3):
    exit("usage: python %s (int)[port] (string)[secret]" % (sys.argv[0]))
FLASK_PORT = int(sys.argv[1]) # 运行的端口


if(len(os.popen("iptables -nL | grep dpt:%s" % (FLASK_PORT)).read().strip())==0):
    os.popen('iptables -I INPUT -p tcp --dport %s -j ACCEPT -m comment --comment "Flask验证服务端口，默认规则"' % (FLASK_PORT))

secret = base64.b32encode(sys.argv[2].strip().encode()).decode()
totp = pyotp.TOTP(secret)

print(pyotp.totp.TOTP(secret).provisioning_uri(name='admin@youserver.com',issuer_name='Your Server'))
app = Flask(__name__)

if not os.path.exists('otplog'):
        os.makedirs('otplog')


@app.route('/')
def index():
    return 'Hello, World!'
@app.route('/login',methods=['GET','POST'])
def login():
    if 'admin' in session and session['admin']==1 :
        return redirect(url_for('admin'))
    if request.method == 'GET':
        return render_template("otp.html")
    ip = request.remote_addr
    otptoken = request.form['otp']
    logfilename = ("%s_%s.log")%(str(datetime.date.today()),ip)
    logline = ("time: %s from: %s otp: %s\n")%(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),ip,otptoken)
    ban = 0
    with open('otplog/'+logfilename,"a+") as f:
        f.seek(0)
        if len(f.readlines())>5:
            ban = 1
        f.write(logline)
    if ban == 1:
        flash("toooo many Login!! Ip has been banned.")
        return redirect(url_for('login'))
    if totp.verify(otptoken):
        session['admin']=1
        existed = os.popen("iptables -nL | grep '%s'" % (ip)).read()
        if(len(existed.strip())==0):
            os.popen("iptables -A INPUT -s {0} -j ACCEPT -m comment --comment \"`date '+%Y_%m_%d %H:%M:%S'`\" &> /dev/null" .format(ip))
        flash('Login Success')
        return redirect(url_for('admin'))
    else:
        flash('error')
        return redirect(url_for('login'))
@app.route("/admin/")
def admin():
    if 'admin' not in session:
        return redirect(url_for('login'))
    a = os.popen("iptables -L INPUT -v -n --line-number").read()
    a = a.split("\n")[2:]
    b = os.popen("iptables -nL INPUT | head -1").read()
    return render_template('admin.html',iptables=a,default=b)
@app.route("/admin/del/",methods=['POST'])
def admin_del():
    if 'admin' not in session:
        return redirect(url_for('login'))
    id = request.form['id']
    #print("iptables -D INPUT "+str(id))
    status,result = subprocess.getstatusoutput("iptables -D INPUT "+str(id))
    #print(res)
    data = {'status':str(status),'result':result}
    return json.dumps(data)
@app.route("/admin/DelAllPortRules/",methods=['POST'])
def DelAllPortRules():
    if 'admin' not in session:
        return redirect(url_for('login'))
    status,result = subprocess.getstatusoutput("sshport=`netstat -ntlp | awk '!a[$NF]++ && $NF~/sshd$/{sub (\".*:\",\"\",$4);print $4}'`;for i in $(iptables -nL INPUT --line-numbers | grep -v \"dpt:%s\" | grep -v \"dpt:$sshport\" | grep 'dpt:' | awk -F ' ' '{print $1}' | tac); do iptables -D INPUT $i ; done" % (FLASK_PORT))
    #print(res)
    data = {'status':str(status),'result':result}
    return json.dumps(data)
@app.route("/admin/DelAllIpRules/",methods=['POST'])
def DelAllIpRules():
    if 'admin' not in session:
        return redirect(url_for('login'))
    status,result = subprocess.getstatusoutput("for i in $(iptables -nL INPUT --line-numbers | grep -v \"0.0.0.0/0            0.0.0.0/0\" | grep -E \"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\" |  grep -v '%s' | awk -F ' ' '{print $1}' | tac); do iptables -D INPUT $i ; done" % (request.remote_addr))
    #print(res)
    data = {'status':str(status),'result':result}
    return json.dumps(data)
    
@app.route("/admin/add/",methods=['POST'])
def admin_add():
    if session['admin']!=1:
        return redirect(url_for('login'))
    param = request.form['p']
    param = re.sub('[^\d\.\/]+',',',param)
    params = param.split(",")
    base_commands = []
    pattern = re.compile(r'^(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/([1-9]|[1-2]\d|3[0-2])){0,1}$')
    for p in params:
        p = p.strip()
        if(len(p)>0):
            if(("." not in p) and int(p) in range(1,65535)):
                existed = os.popen("iptables -L INPUT -n | grep \"dpt:%s \" " % p).read()
                if(len(existed.strip())==0):
                    base_commands.append("iptables -I INPUT -p tcp --dport {0} -j ACCEPT -m comment --comment \"`date '+%Y_%m_%d %H:%M:%S'`\"".format(int(p)))
            elif(pattern.match(p)!=None):
                existed = os.popen("iptables -L INPUT -n | grep '%s'" % p).read()
                if(len(existed.strip())==0):
                    base_commands.append("iptables -A INPUT -s {0} -j ACCEPT -m comment --comment \"`date '+%Y_%m_%d %H:%M:%S'`\"".format(p))
    if(len(base_commands)>0):
        status,result = subprocess.getstatusoutput(";".join(base_commands))
        data = {'status':str(status),'result':result,'command':";".join(base_commands)}
    else:
        data = {'status':str(999),'result':"参数有问题"}
    return json.dumps(data)
app.secret_key = os.urandom(16)
app.run(host='0.0.0.0',port=FLASK_PORT,debug=True)