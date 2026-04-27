#!/usr/bin/env python

from time import sleep
import subprocess
import os

from PIL import Image, ImageTk
import tkinter as tk
from typing import Callable

from mininet.log import setLogLevel, info
from mininet.term import makeTerm
from mn_wifi.net import Mininet_wifi
from mn_wifi.cli import CLI
from mn_wifi.link import wmediumd
from mn_wifi.wmediumdConnector import interference

import atexit

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
window.title("Laboratory 4: Exercise 3 - Attack a simulated FT handshake")
window.geometry("650x600")
window.resizable(False, False)
currentStep = tk.IntVar(value=0)

sta1 = None
fakeAp1 = None
net = None
exeBtn: None | tk.Button = None
terminal = "xterm"

def topology():
    if actionDictionary[1] is False:
        global sta1, fakeAp1, net, exeBtn
        actionDictionary[1] = True

        "Create a network."
        net = Mininet_wifi(link=wmediumd)

        info("*** Creating nodes\n")
        sta1 = net.addStation('sta1', ip='10.0.0.1/24', position='50,0,0',
                              encrypt='wpa2')    
        fakeAp1 = net.addStation('fakeAp1', mac="02:11:11:11:11:11", ip='10.0.0.101/24', position='0,30,0')

        info("*** Configuring wifi nodes\n")
        net.setPropagationModel(model="logDistance", sL=0.4, exp=3.5)
        net.configureWifiNodes()

        info("*** Plotting Graph\n")
        net.plotGraph(min_x=-100, min_y=-100, max_x=200, max_y=200)

        info("*** Starting network\n")
        net.build()

        # Monitor mode to see the traffick with wireshark
        sta1.cmd("ifconfig mon0 up")

        if exeBtn is not None:
            exeBtn.config(fg="green")
            exeBtn=None

def monitoring():
    if actionDictionary[1] is True and actionDictionary[4] is False:
        actionDictionary[4] = True

        if sta1 is not None:
            sta1.cmd('iw dev sta1-wlan0 interface add mon0 type monitor && ip link set mon0 up && wireshark -i mon0 -Y "wlan.da != ff:ff:ff:ff:ff:ff" -k &')
            
            global exeBtn
            if exeBtn is not None:
                exeBtn.config(fg="green")
                exeBtn=None

def openTerminal(target: bool, step: int, title: str): # True -> sta1, False -> FakeAp1
    global sta1, fakeAp1, exeBtn

    if target is True:
        t = sta1
    elif target is False:
        t = fakeAp1
    else:
        print("Invalid target")
        return

    if t is None:
        print("AP or station is down!")
        return


    res = makeTerm(t, title=title)
    print(res)

    if exeBtn is not None:
        exeBtn.config(fg="green")
        exeBtn = None

def generateTraffic():
    global sta1
    if sta1 is not None:
        if actionDictionary[6] is False:
            actionDictionary[6] = True
            res = sta1.cmd("arping -I sta1-wlan0 -c 10 10.0.0.101")
            print(res)
            actionDictionary[6] = False

def exit():
    if(net is not None):
        net.stop()
    quit()

atexit.register(exit)

#STEP DICTIONARY
stepDictionary: dict[int,stepInfo] = {
        1: stepInfo("Network topology (1/3)", 1, "For this exercise, we're going to need:\n- An access point\n- A station\n\nLike the previous exercise, we're going to create this topology using mininet wifi.\nAfter clicking the button a picture of the topology should appear", None, None, None, True, "Start mininet", topology),
        2: stepInfo("Network topology (2/3)", 2, "Click the button to open a terminal within the AP. Start it by running hostapd with this command:\n\n./hostapd hostapd.conf\n\n", None, None, None, True, "Open terminal on AP", lambda: openTerminal(False, 2, "AP")),
        3: stepInfo("Network topology (3/3)", 3, "Click the button to upen a terminal within the station. After that, use the following commands to:\n\n1 - Move within the correct context:\n  cd ../ex2/krackattack-scripts/krackattack\n\n 2 - Activate the python virtual environment:\n  source venv/bin/activate\n\n3 - Run wpa_supplicant wrapped in the attack script:\n  ./krack_ft.py ../../../wpa_supp -i sta1-wlan0 -c ../../../ex3/supplicant.conf\n\nAfter a brief moment it should connect to the AP", None, None, None, True, "Open terminal on station", lambda: openTerminal(True, 3, "STA - WPA_SUPPLICANT")),
    4: stepInfo("Monitor traffic", 4,"Click the button to open a monitoring interface and sniff the traffic with wireshark", None, None, None, True, "Open wireshark", monitoring),
    5: stepInfo("Trigger FT handshake", 5, "Open a new terminal on the station and manually cause the station to roam.\nUse the command\n  ./wpa_cli\nthen type\n  status\nto view informations about the connection. Then run\n  roam 02:11:11:11:11:11\nto trigger the FT handshake. If all went well, you should see the attack script re-sending the\nReassociation Request over and over in wireshark", None, None, None, True, "Open terminal on station", lambda: openTerminal(True, 5, "STA - WPA_SUPPLICANT")),
    6: stepInfo("Generate traffic and observe IV reuse", 6, "Click to generate traffic using arping. Check the traffic in wireshark: you should be seeing the\nInitialization Vector be reset to 1 after every reassociation request", None, None, None, True, "Generate traffic", generateTraffic),
}

actionDictionary: dict[int,bool] = {
    1: False,
    2: False,
    3: False,
    4: False,
    5: False,
    6: False,
}

# GUI logic
def stepLoader(*args):
    stepToLoad=currentStep.get()
    clear()
    if stepToLoad==0:
        extWindow("FT handshake\nattack simulation",''' ''',"Start the wizard",next)
    elif stepToLoad<=6:
        explanationWindow(stepDictionary[stepToLoad])
    else:
        extWindow("The End","Thank you for using our simulation. \n Click the button to close everything.","Close",exit)

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

# Main loop
def main():
    stepLoader()
    window.mainloop()

if __name__ == "__main__":
    main()
