import numpy as np
import socket
import threading
import datetime
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import scrolledtext
import os
import pyperclip

brand='XarComm'
stage='Alpha'
version='1.0.0'

up={}
uk={}
clients=[]
clientsu=[]

def encryptmsg(msg,key):
    suite=Fernet(key)
    return (suite.encrypt(msg.encode())).decode()
def decryptmsg(msg,key):
    suite=Fernet(key)
    return (suite.decrypt(msg.encode())).decode()
def receive(client):
    enm = client.recv(1024).decode('ascii')
    index = clients.index(client)
    username = clientsu[index]
    key=uk[username]
    return decryptmsg(enm,key)
def send(client, message):
    index = clients.index(client)
    username = clientsu[index]
    key=uk[username]
    enm=encryptmsg(message,key)
    client.send(enm.encode('ascii'))
def keycheck(client):
    send(client,'卐')
    res=client.recv(1024).decode('ascii')
    if res=='ik':
        return False
    else:
        return True
def stopthreads():
    for u in clientsu:
        globals()['thread'+u]._stop=threading.Event()
        globals()['thread'+u]._stop.set()

checkedport=False
def checkport():
    try:
        global portent
        global port
        global server
        global checkedport
        global portt
        global chkportbut
        global log
        try:
            port=int(portent.get())
        except:
            try:
                log.config(state='normal')
                log.insert('end','Invalid port'+'\n')
                log.yview('end')
                log.config(state='disabled')
            except:
                os.system('taskkill /IM pyw.exe /F')
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((host, port))
        server.listen()
        portent.config(state='disabled')
        portt.config(state='disabled')
        chkportbut.config(state='disabled')
        checkedport=True
        return None
    except:
        try:
            log.config(state='normal')
            log.insert('end','Invalid port'+'\n')
            log.yview('end')
            log.config(state='disabled')
        except:
            os.system('taskkill /IM pyw.exe /F')
def shutdown():
    os.system('taskkill /IM pyw.exe /F')
def showpasswords(tl):
    global passwin
    def error(title,message):
        global passwin
        root=tk.Toplevel(passwin)
        root.iconphoto(False, tk.PhotoImage(file = 'statics/xlogo.png'))
        root.geometry('300x100')
        root.title(title)
        (tk.Label(root,text=message,pady=20,font=('Arial',10))).pack()
        (tk.Button(root,text='OK',padx=20,command=root.destroy)).pack()
        root.grab_set()
    global up
    global uk

    def negz(n):
        if n>=0:
            return n
        else:
            return 1
    us='Username'+((negz((len(max(list(up.keys()))))-len('Username')))*' ')
    ps='Password'+((negz((len(max(list(up.values()))))-len('Password')))*' ')
    passwin=tk.Toplevel(tl)
    passwin.iconphoto(False, tk.PhotoImage(file = 'statics/xlogo.png'))
    passwin.geometry(str(((len(us)+len(ps)+2+44)*8)+50)+'x'+str(((len(up)+1)*25)+90))
    passwin.title(brand+' Server User Credentials')
    (tk.Label(passwin,text=(us+':'+ps+':Security Key'),font=('Courier New',10),justify='left')).place(x=0,y=0)
    i=0
    l=0
    def uc(u):
        try:
            i=keys.index(u)
        except ValueError:
            error('ERROR','No such username exists')
            return None
        pyperclip.copy('Username:'+keys[i]+((len(us)-len(keys[i]))*' ')+'\n'+'Password:'+up[keys[i]]+((len(ps)-len(up[keys[i]]))*' ')+'\n'+'Security Key:'+uk[keys[i]].decode())

    while i in range(len(up)):
        keys=list(up.keys())
        info=tk.Text(passwin,font=('Courier New',10),height=1,borderwidth=0,pady=3)
        info.insert('1.0',str(keys[i]+((len(us)-len(keys[i]))*' ')+':'+up[keys[i]]+((len(ps)-len(up[keys[i]]))*' ')+':'+uk[keys[i]].decode()))
        info.place(x=0,y=(i+1)*25)
        info.config(state='disabled',inactiveselectbackground=info.cget('selectbackground'))
        i+=1
    ucredcent=tk.Entry(passwin,font=('Courier New',10))
    ucredcent.place(x=0,y=i*52.5)
    (tk.Button(passwin, text='Copy User Credentials', command=lambda: uc(ucredcent.get()))).place(x=175,y=i*50)
    (tk.Button(passwin, text='Done', padx=20,command=passwin.destroy)).place(x=475,y=i*65)
    passwin.grab_set()
def resetserver(root):
    def yes():
        resetcon.destroy()
        f=open('bin/config.txt','w')
        f.write('')
        f.close()
        del f
        reset=tk.Toplevel(root)
        reset.iconphoto(False, tk.PhotoImage(file = 'statics/xlogo1.png'))
        reset.geometry('300x100')
        reset.title('SUCCESS')
        reset.config(bg='white')
        (tk.Label(reset,text='Reset Successful',bg='white',pady=20,font=('Courier New',10))).pack()
        (tk.Button(reset,text='OK',padx=20,command=shutdown)).pack()
        reset.grab_set()
    def no():
        resetcon.destroy()
    resetcon=tk.Toplevel(root)
    resetcon.iconphoto(False, tk.PhotoImage(file = 'statics/xlogo1.png'))
    resetcon.geometry('300x100')
    resetcon.title('Confirm Reset')
    resetcon.config(bg='white')
    (tk.Label(resetcon,text='Are you sure to reset the server?',bg='white',pady=20,font=('Arial',10))).pack()
    (tk.Button(resetcon,text='Confirm',padx=20,command=yes)).place(x=40,y=60)
    (tk.Button(resetcon,text='Cancel',padx=20,command=no)).place(x=175,y=60)
    resetcon.grab_set()
    
def logwin():
    global log
    global root
    global portent
    global portt
    global xlogo
    global chkportbut
    root=tk.Tk()
    root.geometry('650x510')
    root.iconphoto(False, tk.PhotoImage(file = 'statics/xlogo.png'))
    root.title(brand+' Server')
    (tk.Label(root,text='Logs: ')).place(x=0,y=0)
    log=scrolledtext.ScrolledText(root,state='disabled')
    log.place(x=0,y=20,width=650,height=400)
    log.config(state='normal')
    log.insert('end','XarComm Server ('+stage+') v'+version+'\n'+('='*70)+'\n')
    log.yview('end')
    log.config(state='disabled')
    portt=tk.Label(root,text='Enter a valid port:',pady=5)
    portt.place(x=0,y=420)
    portent=tk.Entry(root,width=35)
    portent.place(x=0,y=450)
    chkportbut=tk.Button(root,text='Check port',padx=20,command=checkport)
    chkportbut.place(x=0,y=475)
    (tk.Button(root,text='Shutdown Server',padx=20,command=shutdown)).place(x=355,y=450)
    (tk.Button(root,text='Reset Server',padx=20,command=lambda: resetserver(root))).place(x=240,y=450)
    (tk.Button(root,text='Show Passwords',padx=20,command=lambda: showpasswords(root))).place(x=495,y=450)
    root.protocol('WM_DELETE_WINDOW', shutdown)
    root.mainloop()
    
    
def drawlog():
    global logwinthread
    logwinthread=threading.Thread(target=logwin)
    logwinthread.start()

def logwinlog(message):
    try:
        global log
        log.config(state='normal')
        log.insert('end',message+'\n')
        log.yview('end')
        log.config(state='disabled')
    except:
        os.system('taskkill /IM pyw.exe /F')

def connectlog(address,u,client,state):
    now=datetime.datetime.now()
    date=now.strftime('%Y-%m-%d')
    time=now.strftime('%H:%M:%S')
    if state=='j':
        log=date+' '+time+'='+u+';'+str(address)+';joined the chat'
    else:
        log=date+' '+time+'='+u+';'+str(address)+';left the chat'
    try:
        logfile=open(f'Logs\\connectlogs\\connectlog_{date}.txt','a')
    except:
        logfile=open(f'Logs\\connectlogs\\connectlog_{date}.txt','w')
    logfile.write(log+'\n')
    logfile.close()
    logwinlog(log)
def chatlog(address,u,msg,client):
    now=datetime.datetime.now()
    date=now.strftime('%Y-%m-%d')
    time=now.strftime('%H:%M:%S')
    log=date+' '+time+'='+u+';'+msg+';'+str(address)
    try:
        logfile=open(f'Logs\\chatlogs\\chatlog_{date}.txt','a')
    except:
        logfile=open(f'Logs\\chatlogs\\chatlog_{date}.txt','w')
    logfile.write(log+'\n')
    logfile.close()
    logwinlog(log)
def loginlog(desc,client,u,address):
    now=datetime.datetime.now()
    date=now.strftime('%Y-%m-%d')
    time=now.strftime('%H:%M:%S')
    try:
        logfile=open(f'Logs\\loginlogs\\loginlog_{date}.txt','a')
    except:
        logfile=open(f'Logs\\loginlogs\\loginlog_{date}.txt','w')
    desccodes={'Logged out':0,'Client disconnected':1,'Client connected':2,'creds received':3,'Existing login session request':4,'Successful login request':5,'Incorrect password login request':6,"Non-existing username login request":7,'Unable to contact':8,'Incorrect command':9,'Invalid client':10,'Server started':11,'Key altered':12,'Valid key':13}
    log=date+' '+time+'='+desc+';'+str(client)+';'+u+';'+str(desccodes[desc])
    logfile.write(log+'\n')
    logfile.close()
    logwinlog(date+' '+time+'='+u+';'+desc+';'+str(address)+';'+str(desccodes[desc]))

def loadpasswords():
    global uk
    global up
    up=np.load('creds/creds.npy',allow_pickle=True).item()
    uk=np.load('security/keys.npy',allow_pickle=True).item()

def getpasswords():
    global up
    global uk
    global onereg
    onereg=False
    def regist():
        global onereg
        onereg=True
        up[ue.get()]=pe.get()
        uk[ue.get()]=Fernet.generate_key()
        rep.config(text=ue.get()+':'+pe.get()+'\nCredantials registered')
        ue.delete(0,'end')
        pe.delete(0,'end')
        
    def stop():
        root.destroy()
        
    root=tk.Tk()
    root.geometry('300x250')
    root.iconphoto(False, tk.PhotoImage(file = 'statics/xlogo.png'))
    root.title(brand+' Server Setup')
    (tk.Label(root,text='You will now be registering usernames and passwords.',pady=5)).pack()
    (tk.Label(root,text='Username',pady=5)).pack()
    ue=tk.Entry(root)
    ue.pack()
    (tk.Label(root,text='Password',pady=5)).pack()
    pe=tk.Entry(root)
    pe.pack()
    (tk.Label(root,text='')).pack()
    rep=tk.Label(root,text='')
    rep.pack()
    (tk.Button(root,text='Register',padx=20,command=regist)).place(x=50,y=200)
    (tk.Button(root,text='Finish',padx=20,command=stop)).place(x=175,y=200)
    root.mainloop()
    if onereg:
        return None
    else:
        os.system('taskkill /IM pyw.exe /F')

if (open('bin/config.txt', 'r')).read()!='init@done0x':
    getpasswords()
    np.save('creds/creds.npy',up)
    np.save('security/keys.npy',uk)
    f=open('bin/config.txt', 'w')
    f.write('init@done0x')
    f.close()
    del f
    loadpasswords()

else:
    loadpasswords()
drawlog()
host = socket.gethostbyname(socket.gethostname())

while True:

    if checkedport:
        break
    else:
        continue

def removeclient(client ,u,address):
    try:
        broadcast('{} left the chat'.format(u))
    except:
        pass
    connectlog(address,u,client,'l')
    index = clients.index(client)
    clients.remove(client)
    client.close()
    username = clientsu[index]
    clientsu.remove(username)
    
def broadcast(message):
    for client in clients:
        send(client, message)
def tabber(u,message):
    edit=list(message)[:len(message)-1]
    print(edit)
    i=0
    while i in range(len(edit)):
        print('B')
        if edit[i]=='\n':
            print('A')
            edit.insert(i+1,(len(u)+2)*' ')
            print(edit)
            print('C')
        i+=1
    return (''.join(edit))
def handle(client,u,address):
    while True:
        if client in clients:
            try:
                message=receive(client)
                if message=='█▀█ █▄█ ▀█▀':
                    removeclient(client ,u,address)
                    break
                else:
                    message=tabber(u,message)
                    broadcast(u+': '+message)
                    chatlog(address,u,message,client)
            except Exception as e:
                print(e)
                removeclient(client ,u,address)
                break
        else:
            loginlog('Invalid client',client,user,address)
            client.close()


def joinserver():
    global port
    loginlog('Server started','','','')
    logwinlog('Your IP Address: '+host+'\nPort: '+str(port))
    while True:
        loadpasswords()
        client, address = server.accept()
        loginlog('Client connected',client,'',address)
        try:
            creds = client.recv(1024).decode('ascii')
            u,p=creds.split(',')[0],creds.split(',')[1]
            loginlog('creds received',client,u,address)
            if u in clientsu:
                client.send('al'.encode('ascii'))
                loginlog('Existing login session request',client,u,address)
                client.close()
                continue
            else:
                try:
                    if up[u]==p:
                        clients.append(client)
                        clientsu.append(u)
                        client.send('su'.encode('ascii'))
                        loginlog('Successful login request',client,u,address)
                        if keycheck(client):
                            loginlog('Valid key',client,u,address)
                            pass
                        else:
                            loginlog('Key altered',client,u,address)
                            i = clients.index(client)
                            clients.remove(client)
                            client.close()
                            username = clientsu[i]
                            clientsu.remove(username)
                            continue
                        broadcast((u+" joined the chat"))
                        connectlog(address,u,client,'j')
                    else:
                        client.send('ip'.encode('ascii'))
                        loginlog('Incorrect password login request',client,u,address)
                        client.close()
                        continue
                except KeyError:
                    client.send('nu'.encode('ascii'))
                    loginlog("Non-existing username login request",client,u,address)
                    client.close()
                    continue
        except:
            loginlog('Unable to contact',client,'',address)
            client.close()
            try:
                index = clients.index(client)
                clients.remove(client)
                username = clientsu[index]
                clientsu.remove(username)
            except:
                pass
            continue
        globals()['thread'+u] = threading.Thread(target=handle, args=(client,u,address))
        globals()['thread'+u].start()
joinserver()

