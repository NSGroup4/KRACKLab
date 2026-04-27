from models.msgs import EncMSG,CloseMSG,HandshakeMSG,AssMSG
from utils.ascii_prints import print_ap
from utils.log import *

import socket
import pickle
import random
import string


class APState():
    IDLE = 0
    READY = 1
    INSTALLED = 2


class APSocket:
    def __init__(self, addr,port):
        self._ap = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._ap.bind((addr, port))
        self._dst = []
        self._repl = -1
        self._msgcount = 0
        self._state = APState.IDLE

        log(f"IP: {addr}", DEBUG)
        log(f"PORT: {port}\n\n", DEBUG)

    def send(self,resend=False):
        if self._state is APState.IDLE: return
        input("Press <enter> to send...\n")
        if not resend:
            self._msgcount+=1
        self._repl+=1
        msg = HandshakeMSG(self._repl,self.__generate_nonce(self._msgcount < 3),"GTK" if self._msgcount > 2 else "",self._msgcount)
        self.__send_msg(msg)
        log(msg.format_msg(send=True), DEBUG) 

    def receive(self,timeout=None):
        if self._state is APState.IDLE : return
        self._ap.settimeout(timeout)
        try:
            (msg,addr) = self.__get_msg()
            match msg:
                case HandshakeMSG() if msg.repl <= self._repl:
                    log(msg.format_msg(), DEBUG)
                    self._dst = addr
                    self._msgcount=msg.number
                    if self._msgcount > 3 :
                            log("Installing PTK & GTK\n",WATCH)
                            self._state = APState.INSTALLED

                case EncMSG() if self._state is APState.INSTALLED:
                    log(msg.format_msg(), DEBUG)

                case EncMSG() if not self._state is APState.INSTALLED:
                    log("Recived a encrypted message without installing PTK first\n Dropping...\n",WARNING)
                    self._state = APState.IDLE

                case CloseMSG():
                    log(msg.format_msg(), DEBUG)
                    self._state = APState.IDLE

                case _:
                    log("Recived a message in out of order\n Dropping...\n",WARNING)
                    self._state = APState.IDLE

        except socket.timeout:
            log("Message not received on time\n", WARNING)
    
    def listen_ass(self):
        self._repl = -1
        self._msgcount = 0
        self._ap.settimeout(1.0)
        try:
            (msg,addr) = self.__get_msg()
            if type(msg) is AssMSG:
                self._dst = addr
                self._state = APState.READY
                return True
            return False
        except socket.timeout:
            return False     

    def get_state(self):
        return self._state
    
    def close(self):
        if len(self._dst) > 0 :
            msg = CloseMSG("Connection terminated by AP")
            self.__send_msg(msg)
        self._ap.close()  

    def __get_msg(self):
        data, addr = self._ap.recvfrom(1024)
        msg = pickle.loads(data)
        return (msg,addr)

    def __send_msg(self, msg):
        serialized_msg = pickle.dumps(msg)
        self._ap.sendto(serialized_msg, (self._dst[0], self._dst[1]))
    
    def __generate_nonce(self,empty):
        characters = string.ascii_letters + string.digits
        return ''.join(random.choice(characters) if empty else "0" for i in range(16))

AP_RETRY_TIME = 30

def main():
    print_ap()
    try:
        AP = APSocket('127.0.0.1', 5001)

        while AP.get_state() is APState.IDLE:
            log('Listening for associations\n')
            if AP.listen_ass():

                log('[1/4] Sending the ANonce to client\n')
                AP.send()

                log('Waiting SNonce from client...\n')
                AP.receive()

                retry = False
                while AP.get_state() is APState.READY:
                    log("[3/4] Sending GTK to client\n")
                    AP.send(resend=retry)
                    retry = True
                    log('Waiting message 4 (ACK) from client...\n')
                    log(f'Waiting for {AP_RETRY_TIME}\n',DEBUG)
                    AP.receive(timeout=AP_RETRY_TIME)
                
                log('Connection Established\n',WATCH)

                while AP.get_state() is APState.INSTALLED:
                    log('Listening for messages...\n')
                    AP.receive()

    except KeyboardInterrupt:
        log("Interruption detected by user.", ERROR)

    finally:
        AP.close()
        log("Simulation is terminated\n",showtime=None)

if __name__ == "__main__":
    main()