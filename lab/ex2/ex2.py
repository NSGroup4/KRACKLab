import os
import subprocess

from PIL import Image, ImageTk
import tkinter as tk
from typing import Callable
from mn_wifi.net import Mininet_wifi
from mininet.log import info, setLogLevel
from mn_wifi.link import wmediumd
from mn_wifi.cli import CLI
import atexit

#Dep: ImageTk, tkinter, xclip

#GLOABL VARIABLES
class stepInfo:
    step: int
    title: str
    txt: str
    image: str | None
    imageX: int | None
    imageY: int | None
    hasCommand: bool
    commandBtnName: str | None
    buttonCommand: Callable[[],None] | None
    def __init__(self,title: str, step: int, txt: str, image: str | None, imageX: int | None, imageY: int | None, hasCommand: bool, commandBtnName: str | None, buttonCommand: Callable[[], None] | None):
        self.step=step
        self.title=title
        self.txt=txt
        self.image=image
        self.imageX=imageX
        self.imageY=imageY
        self.hasCommand=hasCommand
        self.commandBtnName=commandBtnName
        self.buttonCommand=buttonCommand

#WINDOW SETUP
window: tk.Tk = tk.Tk()
window.title("Laboratory 4: Exercise 2 - Exploit KRACK in a virtual environmnet")
window.geometry("650x600")
window.resizable(False, False)
currentStep = tk.IntVar(value=0)

#GLOBAL VAR
fakeAp = None
sta1 = None
net = None
exeBtn: None | tk.Button = None

#BUTTON ACTIONS
def openMininet():
    if(actionDictionary[2] is False):
        global fakeAp, sta1, net, exeBtn
        actionDictionary[2]=True 
        net=Mininet_wifi(link=wmediumd)

        info("Creating fakeAp and sta1\n")
        fakeAp = net.addStation("fakeAp", mac='00:00:00:00:00:01', ip='192.168.100.254/24', position='200,400,0')
        sta1 = net.addStation('sta1', position='200,450,0', ip='192.168.100.1', mac='00:00:00:00:01:00')

        info("Configuring wireless propagation model\n")
        net.setPropagationModel(model="logDistance", exp=3.5)

        info("Configure nodes\n")
        net.configureWifiNodes()

        info("Creating graph\n")
        net.plotGraph(min_x=0, min_y=0, max_x=1000, max_y=1000)

        info("Starting network")
        net.build()
        setLogLevel('info')

        if exeBtn is not None:
            exeBtn.config(fg="green")
            exeBtn=None

        

def openWireshark():
    if(actionDictionary[3] is False and actionDictionary[2] is True):
        actionDictionary[3]=True 
        if sta1 is not None:
            sta1.cmd('iw dev sta1-wlan0 interface add mon0 type monitor && ip link set mon0 up && wireshark -i mon0 -Y "eapol || ip.src==192.168.100.254 || ip.dst==192.168.100.254" -k &')
        global exeBtn
        if exeBtn is not None:
            exeBtn.config(fg="green")
            exeBtn=None

def openShell():
    if fakeAp is not None and sta1 is not None:
        fakeAp.cmd("xfce4-terminal --title Mininet-WiFi:fakeAp &")
        sta1.cmd("xfce4-terminal --title Mininet-WiFi:sta1 &")
    global exeBtn
    if exeBtn is not None:
        exeBtn.config(fg="green")
        exeBtn=None
        

def copyStartAttack():
    subprocess.call("echo \"./startAttack.sh\" | xclip -sel clip", shell=True)
    global exeBtn
    if exeBtn is not None:
        exeBtn.config(fg="green")
        exeBtn=None

def copyStartVictim():
    subprocess.call("echo \"./wpa_supplicant23 -i sta1-wlan0 -c \"wifiConfig.conf\"\" | xclip -sel clip", shell=True)
    global exeBtn
    if exeBtn is not None:
        exeBtn.config(fg="green")
        exeBtn=None

def openShellForPing():
    if sta1 is not None:
        result=sta1.cmd("ping -c 20 192.168.100.254")
        print(result)
    global exeBtn
    if exeBtn is not None:
        exeBtn.config(fg="green")
        exeBtn=None

def exit():
    if(net is not None):
        net.stop()
    quit()

atexit.register(exit)

#STEP DICTIONARY
stepDictionary: dict[int,stepInfo] = {
    1: stepInfo("Introduction (step 1/8)",1,"First, let's discuss about our network topology. In this exercise there will be 2 wireless station: \n\n - sta1, which simulated the victim; \n - fakeAp, a wireless station which will run a malicious Access Point created by a python script. \n\n The idea is that the script will create an Access Point to which sta1 will connect, then the same \n script will forward the repeated message 3 of the handshake to sta1 and, finally, it will analyze the \n 4th message of the handshake before this will be \"rejected\" by hostapd to see if sta1 \n reinstalled the key (and, consequentially, resetted the packet number) \n and/or installed an all-zero key.",None,None,None,False,None,None),
    2: stepInfo("Start Mininet WiFi (step 2/8)",2,"With the explanation out of the way, let's start our attack! \n\n Click the button below to start Mininet WiFi. \n The launcher will automatically create sta1 and fakeAp. The program will also generate a quick graph \n similar to the one you see in the image reported under the title of this section: \n the colored region represent the area reachable by the wireless network card of the two devices.","./img/graph.png",250,200,True,"Open Mininet",openMininet),
    3: stepInfo("Start Wireshark (step 3/8)",3,"Now that Mininet WiFi has been opened, it's a good idea to also open Wireshark. \n\n By pressing the button below, you will open an instance of the program which is already setup to \n capture EAPOL and ping packets sent by the Access Point to sta1 and viceversa. \n\n Specifically, it's important to observe the column CCMP packet number: this number \n (corresponding to the packet number), is used to encrypt data frames from the station to the Access Point \n and viceversa. Confidentiality of messages is \n guarantee as long as this number does not repeat, something that KRACK cause to happen.","./img/wireshark.png",400,200,True,"Open Wireshark",openWireshark),
    4: stepInfo("Open fakeAp and sta1 shell (step 4/8)",4,"Before proceeding, it is needed to open one shell for fakeAp and one for sta1 in order \n to be able to interact directly with the two devices. \n\n The shell for fakeAp is needed to activate the KRACK script, while the other is \n needed to make sta1 connect to the Access Point created on fakeAp by the script.",None,None,None,True,"Open fakeAp and sta1 shell",openShell),
    5: stepInfo("Start the KRACK attack script (step 5/8)",5,"In order to start the script it's necessary to copy the following command\n\n./startAttack.sh\n\nand pasting and executing it on the fakeAp shell. \n\n Tip: to copy in a terminal use ctrl+shift+v and NOT ctrl+v",None,None,None,True,"Copy command to clipboard",copyStartAttack),
    6: stepInfo("Connect sta1 to fakeAp (step 6/8)",6," To connect sta1, copy and execute on sta1 shell the following command: \n\n ./wpa_supplicant23 -i sta1-wlan0 -c \"wifiConfig.conf\" \n\n Please wait until you see the green message that is also reported in the picture before proceeding. \n\n To make the connection possible we use the actual component that is vulnerable \n to KRACK: wpa_supplicant v2.3. \n\n Tip: to copy in a terminal use ctrl+shift+v and NOT ctrl+v","./img/shell.png",550,200,True,"Copy command to clipboard",copyStartVictim),
    7: stepInfo("PING (step 7/8)",7,"To easily see the packet number reuse on Wireshark, it is useful to perform some PING to\n the Access Point. To do that open another shell for sta1 and ping using the following command:\n\n sta1 ping -c 14 192.168.100.254 \n\n This will make 14 ping to the Access Point and should be more than enough to see the problem. \n\n Pressing the button below will do what just described for you.",None,None,None,True,"Start ping",openShellForPing),
    8: stepInfo("Final results (step 8/8)",8,"If you performed all of the tasks without errors, you will see that the script detected a nonce reuse\n (printed in yellow/orange in the fakeAp shell).\n\n Additionally, you will see some packet number reuse on the \n CCMP packet number column each time a ping is performed after the  \nexchange of message 3 and 4. \n\n To see an example of the intended result, go back to step 3: you will\n find a picture for comparison.","./img/results.png",300,200,False,None,None)
}

actionDictionary: dict[int,bool] = {
    1: False,
    2: False,
    3: False,
    4: False,
    5: False,
    6: False,
    7: False,
    8: False,
}

def stepLoader(*args):
    stepToLoad=currentStep.get()
    clear()
    if stepToLoad==0:
        extWindow("KRACK simulation",'''Welcome! In this exercise you will execute a KRACK attack in a simulated environment \n \n In order to create a virtual environment, a special version of the popular network \n emulator will be used: Mininet. Specifically, a version adapted for simulating Access \n Point called Mininet-WiFi. \n\nThis wizard will help you through the necessary steps: click on the button below to start this journey! \n\n Tip: if you wrongly close something, just close this wizard \n and run it again. When an action completed succesfully you will see the text of the button \n colored in GREEN''',"Start the wizard",next)
    elif stepToLoad<=8:
        explanationWindow(stepDictionary[stepToLoad])
    else:
        extWindow("The End","Thank you for using our simulation. \n Click the button below to close everything.","Close",exit)

currentStep.trace_add("write",stepLoader)

window.protocol("WM_DELETE_WINDOW", exit)
window.configure()

def clear():
    for widget in window.winfo_children():
        widget.destroy()

def next():
    currentStep.set(currentStep.get()+1)

def previous():
    currentStep.set(currentStep.get()-1)

def extWindow(titleText: str, introText: str, buttonText: str, buttonCommand: Callable[[], None]):
    #Button
    btnWidth: int = 150
    btnHeight: int = 50

    #Labels
    titleWidth: int = 300
    titleHeight: int = 100
    titleY: int = 10
    introWidth: int = 600
    introHeight: int = 400
    introY: int = titleHeight+titleY+10

    #General window info
    window.update_idletasks()
    winWidth: int = window.winfo_width()
    winHeight: int = window.winfo_height()
    
    #Placing
    tk.Label(text=titleText, font=("Arial", 24, "bold")).place(width=titleWidth, height=titleHeight,x=(winWidth-titleWidth)/2, y=titleY)
    tk.Label(text=introText).place(width=introWidth,height=introHeight,x=(winWidth-introWidth)/2,y=introY)
    tk.Button(text=buttonText, command=buttonCommand).place(width=btnWidth,height=btnHeight,x=(winWidth-btnWidth)/2,y=winHeight-btnHeight-10)

def explanationWindow(step: stepInfo):

    if(step.hasCommand and (step.buttonCommand==None or step.commandBtnName==None)):
        raise Exception("explanationWindow: actionButton set but no callable or command button name")
    if(step.image and (step.imageX==None or step.imageY==None)):
        raise Exception("Image set but no image dimension set")

    global exeBtn

    titleText: str = step.title
    titleWidth: int = 600
    titleHeight: int = 100
    titleY: int = -3

    txtWidth: int = 600
    txtHeight: int = 215

    #General window info
    window.update_idletasks()
    winWidth: int = window.winfo_width()
    winHeight: int = window.winfo_height()

    #Button
    btnWidth: int = 185
    btnHeight: int = 50
    btnY: int = winHeight-btnHeight-10

    tk.Label(text=titleText, font=("Arial", 24, "bold")).place(width=titleWidth, height=titleHeight,x=(winWidth-titleWidth)/2, y=titleY)
    if (step.image!=None and step.imageX!=None and step.imageY!=None):
        img = Image.open(step.image)
        img = img.resize((step.imageX, step.imageY), Image.Resampling.LANCZOS)
        img = ImageTk.PhotoImage(img)
        label = tk.Label(window, image=img)
        label.image = img  # type: ignore #
        label.place(x=(winWidth-step.imageX)/2, y=titleY+titleHeight+2, width=step.imageX, height=step.imageY)
        tk.Label(text=step.txt, justify="left", anchor="w").place(x=(winWidth-txtWidth)/2, y=titleY+titleHeight+step.imageY+10)
    else:
        tk.Label(text=step.txt, justify="left", anchor="w").place(width=txtWidth, height=txtHeight+200, x=(winWidth-txtWidth)/2, y=titleY+titleHeight)
            
    tk.Button(text="Previous", command=previous).place(width=btnWidth, height=btnHeight,x=10,y=btnY)
    if(step.hasCommand and step.commandBtnName and step.buttonCommand):
        if ((step.step!=2 and step.step!=3) is True):
            exeBtn=tk.Button(text=step.commandBtnName, command=step.buttonCommand)
            exeBtn.place(width=btnWidth,height=btnHeight,x=(winWidth-btnWidth)/2,y=btnY)
        elif (actionDictionary[step.step] is False):
            exeBtn=tk.Button(text=step.commandBtnName, command=step.buttonCommand)
            exeBtn.place(width=btnWidth,height=btnHeight,x=(winWidth-btnWidth)/2,y=btnY)
    tk.Button(text="Next", command=next).place(width=btnWidth, height=btnHeight,x=winWidth-btnWidth-10,y=btnY)

def main():
    if(os.geteuid() == 0):
        stepLoader()
        window.mainloop()
    else:
        print("This script need superuser privileges in order to be run. Execute it with the following command: \n sudo python3 ex2.py")


if __name__ == "__main__":
    main()