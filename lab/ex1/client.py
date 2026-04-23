from models.msgs import *
from utils.ascii_prints import print_client

import socket
import pickle
import random
import string

class CState():
    SEARCHING = 0
    READY = 1
    INSTALLED = 2
    TERMINATED = 3


class ClientSocket:
    def __init__(self, addr,port):
        self._c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._c.bind((addr, port))
        self._dst = []
        self._repl = -1
        self._msgcount = 0
        self._state = CState.SEARCHING

        print(f"IP:{addr}")
        print(f"PORT:{port}")
        print(f"Client is definitely using: {self._c.getsockname()}")

    def send(self,data=False):
        if self._state is CState.TERMINATED : return
        input("Press <enter> to send...\n")
        if not data:
            self._msgcount+=1
            msg = HandshakeMSG(self._repl,self.__generate_nonce(self._msgcount < 3),"",self._msgcount)
            self.__send_msg(msg)
            print(msg.format_msg(send=True))
            if self._msgcount > 3 :
                print("Installing PTK & GTK\n")
                self._state = CState.INSTALLED
        else:
            msg = EncMSG("KRACKISREAL",0)
            self.__send_msg(msg)
            print(msg.format_msg(send=True))

    def receive(self,timeout=None):
        if self._state is CState.TERMINATED : return
        self._c.settimeout(timeout)
        try:
            (msg,addr) = self.__get_msg()

            match msg:
                case HandshakeMSG() if msg.repl > self._repl:
                    print(msg.format_msg())
                    self._dst = addr
                    self._msgcount=msg.number
                    self._repl=msg.repl
                    self._state = CState.READY
                
                case DassMSG() if self._state is CState.INSTALLED:
                    print("Disassociating...\n")
                    msg = CloseMSG("Connection terminated by Client")
                    self.__send_msg(msg)
                    self._dst = addr
                    self._state = CState.SEARCHING

                case CloseMSG():
                    print(msg)
                    self._state = CState.TERMINATED
                        
                case _:
                    print("Recived a message in out of order\n Dropping...")
                    self._state = CState.TERMINATED
                    
        except socket.timeout:
            print("Message not received on time\n")
    
    def ass_request(self):
        self._repl = -1
        self._msgcount = 0
        msg = AssMSG()
        if check_udp_port('127.0.0.1', 6000):
            self._dst = ['127.0.0.1', 6000] # in order to fake mitm at the beginning
            self.__send_msg(msg)
        self._dst = ['127.0.0.1', 5001]
        self.__send_msg(msg)
    
    def get_state(self):
        return self._state
    
    def close(self):
        if len(self._dst) > 0 :
            msg = CloseMSG("Connection terminated by Client")
            self.__send_msg(msg)
        self._c.close()  

    def __get_msg(self):
        data, addr = self._c.recvfrom(1024)
        msg = pickle.loads(data)
        return (msg,addr)
    
    def __send_msg(self, msg):
        self._c.sendto(pickle.dumps(msg), (self._dst[0], self._dst[1]))

    def __generate_nonce(self,empty):
        characters = string.ascii_letters + string.digits
        return ''.join(random.choice(characters) if empty else "0" for i in range(16))

def check_udp_port(ip, port, timeout=2):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(b'', (ip, port))
        data, addr = sock.recvfrom(1024)
        return True, # Open (Received Response)
    except socket.timeout:
        return None, # Open | Filtered (No Response)   
    except ConnectionResetError:
        return False, # Closed (ICMP Unreachable)
    except Exception as e:
        return False, f"Error: {e}"
    finally:
        sock.close()
    
def main():
    try:
        Client = ClientSocket('127.0.0.1', 5002)
        print_client()

        while Client.get_state() is not CState.TERMINATED:
            print('Searching for AP...\n')
            while Client.get_state() is CState.SEARCHING:
                Client.ass_request()

                print('Waiting ANonce from AP...\n')
                Client.receive(timeout=5)

            print('[2/4] Sending SNonce to AP...\n')
            Client.send()

            print("Waiting GTK from AP\n")
            Client.receive()
            while Client.get_state() is not CState.TERMINATED:
                print('[4/4] Sending message 4 (ACK) to AP...\n')
                Client.send()

                while Client.get_state() is CState.INSTALLED:
                    print("Sending some data to AP...")
                    Client.send(data=True)
                    print("Listening for some messages...")
                    Client.receive(timeout=5) # listen for some time

    except KeyboardInterrupt:
        print("Interruption detected by user.")

    finally:
        Client.close()
        print("Simulation is terminated\n")



if __name__ == "__main__":
    main()