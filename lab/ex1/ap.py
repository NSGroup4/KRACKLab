from models.msgs import EncMSG,CloseMSG,HandshakeMSG,AssMSG
from utils.ascii_prints import print_ap

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

        print(f"IP:{addr}")
        print(f"PORT:{port}")
        print(f"AP is definitely using: {self._ap.getsockname()}")

    def send(self,resend=False):
        if self._state is APState.IDLE : return
        input("Press <enter> to send...\n")
        if not resend:
            self._msgcount+=1
        key = ""
        if self._msgcount > 2:
            key ="GTK"
        self._repl+=1
        msg = HandshakeMSG(self._repl,self.__generate_nonce(self._msgcount < 3),key,self._msgcount)
        self.__send_msg(msg)
        print(msg.format_msg(send=True)) 

    def receive(self,timeout=None):
        if self._state is APState.IDLE : return
        self._ap.settimeout(timeout)
        try:
            (msg,addr) = self.__get_msg()
            print(msg)
            match msg:
                case HandshakeMSG() if msg.repl == self._repl:
                    print(msg.format_msg())
                    self._dst = addr
                    self._msgcount=msg.number
                    if self._msgcount > 3 :
                            print("Installing PTK & GTK\n")
                            self._state = APState.INSTALLED

                case EncMSG() if self._state is APState.INSTALLED:
                    print(msg.format_msg())

                case EncMSG() if not self._state is APState.INSTALLED:
                    print("Recived a encrypted message without installing PTK first\n Dropping...")
                    self._state = APState.IDLE

                case CloseMSG():
                    print(msg)
                    self._state = APState.IDLE

                case _:
                    print("Recived a message in out of order\n Dropping...")
                    self._state = APState.IDLE

        except socket.timeout:
            print("Message not received on time\n")
    
    def listen_ass(self):
        self._repl = -1
        self._msgcount = 0
        self._ap.settimeout(1.0)
        try:
            (msg,addr) = self.__get_msg()
            if type(msg) is AssMSG:
                self._dst = addr
                self._state = APState.READY
                print(self._dst)
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
        self._ap.sendto(pickle.dumps(msg), (self._dst[0], self._dst[1]))
    
    def __generate_nonce(self,empty):
        characters = string.ascii_letters + string.digits
        return ''.join(random.choice(characters) if empty else "0" for i in range(16))



def main():
    try:
        AP = APSocket('127.0.0.1', 5001)
        print_ap()

        while AP.get_state() is APState.IDLE:
            print('Listening for associations\n')
            if AP.listen_ass():

                print('[1/4] Sending the ANonce to client\n')
                AP.send()

                print('Waiting SNonce from client...\n')
                AP.receive()

                retry = False
                while AP.get_state() is APState.READY:
                    print("[3/4] Sending GTK to client\n")
                    AP.send(resend=retry)
                    retry = True
                    print('Waiting message 4 (ACK) from client...\n')
                    AP.receive(timeout=10)
                
                print('Connection Established\n')

                while AP.get_state() is APState.INSTALLED:
                    print('Listening for messages...')
                    AP.receive()

    except KeyboardInterrupt:
        print("Interruption detected by user.")

    finally:
        AP.close()
        print("Simulation is terminated\n")

if __name__ == "__main__":
    main()