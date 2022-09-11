import datetime
import socket
import threading
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import scrolledtext
from time import sleep

brand='XarComm'
stage='Alpha'
version='1.0.0'

hostip=''
port=0

key=open('Security/key.txt').read()

a=1

def error(tl,title,message):
    root=tk.Toplevel(tl)
    root.iconphoto(False, tk.PhotoImage(file = 'statics/xlogo.png'))
    root.geometry('300x150')
    root.title(title)
    root.config(bg='white')
    (tk.Label(root,text=message,bg='white',pady=20,font=('Arial',10))).pack()
    (tk.Button(root,text='OK',padx=20,command=root.destroy)).pack()
    root.grab_set()
    
def invalidkey():
    root=tk.Tk()
    root.geometry('300x150')
    root.iconphoto(False, tk.PhotoImage(file = 'statics/xlogo.png'))
    root.title('ERROR')
    root.config(bg='white')
    (tk.Label(root,text='Invalid security key.\nChange key and restart program.',bg='white',pady=20,font=('Courier New',10))).pack()
    (tk.Button(root,text='OK',padx=20,command=root.destroy)).pack()
    root.mainloop()
def encrypt(msg,key):
    try:
        suite=Fernet(key.encode())
        return suite.encrypt(msg.encode()).decode()
    except:
        invalidkey()
def decrypt(msg,key):
    try:
        suite=Fernet(key.encode())
        return suite.decrypt(msg.encode()).decode()
    except:
        invalidkey()
def receive(client):
    enm = client.recv(1024).decode('ascii')
    return decrypt(enm,key)
def send(client, message):
    enm=encrypt(message,key)
    client.send(enm.encode('ascii'))
def keycheck(client):
    try:
        if receive(client)=='卐':
            client.send('k'.encode('ascii'))
            return True
        else:
            client.send('ik'.encode('ascii'))
            return False
    except:
        client.send('ik'.encode('ascii'))
        return False
def chatlog(message):
    now=datetime.datetime.now()
    date=now.strftime('%Y-%m-%d')
    time=now.strftime('%H:%M:%S')
    try:
        logfile=open(f'History\\chat_{date}.txt','a')
    except:
        logfile=open(f'History\\\chat_{date}.txt','w')
    logfile.write(message+'\n')
    logfile.close()
def log(desc,client,u):
    now=datetime.datetime.now()
    date=now.strftime('%Y-%m-%d')
    time=now.strftime('%H:%M:%S')
    try:
        logfile=open(f'Logs\\connectionlogs\\log_{date}.txt','a')
    except:
        logfile=open(f'Logs\\connectionlogs\\log_{date}.txt','w')
    desccodes={'Logged out':0,'Connected to server':1,'creds sent':2,'Existing login session request':3,'Successful login':4,'Incorrect password login request':5,"Non-existing username login request":6,'Incorrect command':7,"Data received":8,'Connection lost':9}
    log=date+' '+time+'='+desc+';'+str(client)+';'+u+';'+str(desccodes[desc])
    logfile.write(log+'\n')
    logfile.close()


def get():
    global client
    global a
    global master
    while True:
        try:
            now=datetime.datetime.now()
            date=now.strftime('%Y-%m-%d')
            time=now.strftime('%H:%M:%S')
            message = receive(client)
            chatlog(message)
            chat.config(state='normal')
            chat.insert('end',message+'\t\t\t\t\t\t\t\t'+date+' '+time+'\n')
            chat.yview('end')
            chat.config(state='disabled')
            i=int(a)
        except ConnectionResetError or ConnectionAbortedError:
            error(master,'ERROR',"An error occured while receiving your messages.\n Server might have shutdown")
            client.close()
            break
        except:
            client.close()
            exit()
        
def write():
    global client
    global a
    global master
    try:
        message = msge.get('1.0','end')
        send(client, message[0:len(message)-1])
        msge.delete('1.0','end')
        i=int(a)
    except ConnectionResetError or ConnectionAbortedError:
        error(master,'ERROR',"An error occured while sending your messages.\n Server might have shutdown")
        client.close()
        exit()
    except:
        client.close()
        exit()

while True:
    fs=False
    def sinfo():
        global fs
        global client
        global hostip
        global port
        global sres
        fs=False
        hostip=ipe.get()
        port=pe.get()
        try:
            try:
                port=int(port)
            except:
                sres.config(text='Invalid port')
                return None
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect((hostip, port))
            log('Connected to server',client,'')
            root.destroy()
            fs=True
        except:
            sres.config(text='Invalid server info')
        
    root=tk.Tk()
    root.geometry('300x160')
    root.iconphoto(False, tk.PhotoImage(file = 'statics/xlogo.png'))
    root.title(brand+' Server Connect')
    (tk.Label(root,text='Host IP',pady=5)).pack()
    ipe=tk.Entry(root)
    ipe.pack()
    (tk.Label(root,text='Port',pady=5)).pack()
    pe=tk.Entry(root)
    pe.pack()
    sres=tk.Label(root,text='',pady=5)
    sres.pack()
    (tk.Button(root,text='Connect',padx=20,command=sinfo)).pack()
    root.mainloop()
    
    if fs:
        logged=False
        keychecked=False
        def login():
            global logged
            global keychecked
            global rest
            global hostip
            global port
            global client
            u=ue.get()
            p=pe.get()
            try:
                try:
                    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    client.connect((hostip, port))
                except Exception as e:
                    print(e)
                    pass
                creds=','.join([u,p])
                client.send(creds.encode('ascii'))
                log('creds sent',client,u)
                response=client.recv(1024).decode('ascii')
                if response=='su':
                    log('Successful login',client,u)
                    logged=True
                    win.destroy()
                    if keycheck(client):
                        keychecked=True
                    else:
                        pass
                elif response=='ip':
                    rest.config(text='Incorrect password')
                    log('Incorrect password login request',client,u)
                    client.close()
                elif response=='nu':
                    rest.config(text='No such username exists')
                    log("Non-existing username login request",client,u)
                    client.close()
                elif response=='al':
                    rest.config(text='Username already logged on')
                    log('Existing login session request',client,u)
                    client.close()
                else:
                    rest.config(text='Incorrect command received from server')
                    log('Incorrect command',client,u)
                    client.close()
            except ConnectionAbortedError:
                rest.config(text='Connection lost!')
                log('Connection lost',client,u)
            except ConnectionResetError:
                rest.config(text='Connection lost!')
                log('Connection lost',client,u)
            except Exception as e:
                error(root,'Error','Could not login. Try again later.\n'+e)
                try:
                    rest.config(text='Could not login. Try again later.')
                except:
                    pass
                client.close()
            return None
        win=tk.Tk()
        win.geometry('300x190')
        win.title(brand+' Login')
        win.iconphoto(False, tk.PhotoImage(file = 'statics/xlogo.png'))
        (tk.Label(win,text='SERVER FOUND',pady=5)).pack()
        (tk.Label(win,text='USERNAME',pady=5)).pack()
        ue=tk.Entry(win)
        ue.pack()
        (tk.Label(win,text='PASSWORD',pady=5)).pack()
        pe=tk.Entry(win)
        pe.pack()
        rest=tk.Label(win,text='',pady=5)
        rest.pack()
        (tk.Button(win,text='LOGIN',padx=20,command=login)).pack()
        win.mainloop()
        if logged:
            if keychecked:
                break
            else:
                invalidkey()
                continue
        else:
            del win
            del root
            continue
    else:
        exit()
def newline():
    global msge
    msge.insert('end','')
r=False
master=tk.Tk()
master.geometry('715x300')
master.title(brand+' Chat')
master.iconphoto(False, tk.PhotoImage(file = 'statics/xlogo.png'))
(tk.Label(master,text='Chat:')).place(x=0,y=0)
chat=scrolledtext.ScrolledText(master,state='disabled')
chat.place(x=0,y=1,width=715,height=230)
(tk.Label(master,text='Type your message:')).place(x=0,y=230)
scroller=tk.Scrollbar(master)
scroller.place(x=610, y=250)
msge=tk.Text(master,yscrollcommand=scroller.set)
msge.place(x=0,y=250,width=610,height=40)
scroller.config(command=msge.yview)
(tk.Button(master,text='Send',pady=20,command=write)).place(x=630,y=250,width=80,height=40)
master.bind('<Return>',lambda event:write())
master.bind('<Shift-Key-Return>',lambda event:newline())
if r==False:
    receive_thread = threading.Thread(target=get)
    receive_thread.start()
    r=True
else:
    pass
master.mainloop()
try:
    send(client, '█▀█ █▄█ ▀█▀')
except:
    pass
a='a'



