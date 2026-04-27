from models.msgs import *
from utils.ascii_prints import print_client
from utils.log import *

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
        self._installed_nonce = 1
        self._state = CState.SEARCHING

        log(f"IP: {addr}", DEBUG)
        log(f"PORT: {port}\n\n", DEBUG)

    def send(self,data=False):
        if self._state is CState.TERMINATED : return
        input("Press <enter> to send...\n")
        if not data:
            self._msgcount+=1
            msg = HandshakeMSG(self._repl,self.__generate_nonce(self._msgcount < 3),"",self._msgcount)
            self.__send_msg(msg)
            log(msg.format_msg(send=True),DEBUG)
            if self._msgcount > 3 :
                log("Installing PTK & GTK\n",WATCH)
                self._state = CState.INSTALLED
                self._installed_nonce = 1
        else:
            msg = EncMSG("KRACKISREAL",self._installed_nonce)
            self.__send_msg(msg)
            log(msg.format_msg(send=True),DEBUG)
            self._installed_nonce +=1

    def receive(self,timeout=None):
        if self._state is CState.TERMINATED : return
        self._c.settimeout(timeout)
        try:
            (msg,addr) = self.__get_msg()

            match msg:
                case HandshakeMSG() if msg.repl > self._repl:
                    log(msg.format_msg(),DEBUG)
                    self._dst = addr
                    self._msgcount=msg.number
                    self._repl=msg.repl
                    self._state = CState.READY
                
                case DassMSG() if self._state is CState.INSTALLED:
                    log("Disassociating...\n",WATCH)
                    msg = CloseMSG("Connection terminated by Client")
                    self.__send_msg(msg)
                    self._dst = addr
                    self._state = CState.SEARCHING
                
                case DassMSG() if self._state is not CState.INSTALLED:
                    return

                case CloseMSG():
                    log(msg.format_msg(),DEBUG)
                    self._state = CState.TERMINATED
                        
                case _:
                    log("Recived a message in out of order\n Dropping..\n.", WARNING)
                    self._state = CState.TERMINATED
        except ConnectionResetError:
            log(f"Failed to contact the AP\n", ERROR)
            exit(1)
        except socket.timeout:
            log("Message not received on time\n",WARNING)
    
    def ass_request(self):
        self._repl = -1
        self._msgcount = 0
        msg = AssMSG()
        if self.__check_udp_port('127.0.0.1', 6000) == True:
            self._dst = ['127.0.0.1', 6000] # in order to fake mitm at the beginning
            self.__send_msg(msg)
        else:
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
        serialized_msg = pickle.dumps(msg)
        self._c.sendto(serialized_msg, (self._dst[0], self._dst[1]))

    def __generate_nonce(self,empty):
        characters = string.ascii_letters + string.digits
        return ''.join(random.choice(characters) if empty else "0" for i in range(16))

    def __check_udp_port(self, ip, port, timeout=2):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(b'', (ip, port))
            _, _ = sock.recvfrom(1024)
            return True # Open (Received Response)
        except socket.timeout:
            return None # Open | Filtered (No Response)   
        except ConnectionResetError:
            return False # Closed (ICMP Unreachable)
        except Exception as e:
            log(f"Error: {e}",ERROR)
            return False
        finally:
            sock.close()
    
CLIENT_LISTEN_TIME = 20

def main():
    print_client()
    try:
        Client = ClientSocket('127.0.0.1', 5002)

        while Client.get_state() is not CState.TERMINATED:
            log('Searching for AP...\n')
            Client.ass_request()
            while Client.get_state() is CState.SEARCHING:
                log('Waiting ANonce from AP...\n')
                Client.receive(timeout=5)

            log('[2/4] Sending SNonce to AP...\n')
            Client.send()

            log("Waiting GTK from AP\n")
            Client.receive()
            while Client.get_state() not in (CState.TERMINATED, CState.SEARCHING):
                log('[4/4] Sending message 4 (ACK) to AP...\n')
                Client.send()
                listen_time = 20
                while Client.get_state() is CState.INSTALLED:
                    log("Sending some data to AP...",showtime=False)
                    Client.send(data=True)
                    log("Listening for some messages...")
                    log(f"For {CLIENT_LISTEN_TIME} seconds", DEBUG)
                    Client.receive(timeout=CLIENT_LISTEN_TIME) # listen for some time

    except KeyboardInterrupt:
        log("Interruption detected by user.",ERROR)

    finally:
        Client.close()
        log("Simulation is terminated\n",showtime=None)



if __name__ == "__main__":
    main()