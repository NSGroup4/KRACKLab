from models.msgs import *
from utils.ascii_prints import print_mitm
from utils.log import *

import socket
import pickle
import time

CLIENT = ('127.0.0.1', 5002)
AP = ('127.0.0.1', 5001)

class MStates():
    IDLE = 0
    READY = 1
    INSTALLED = 2

class MitMSocket():
    def __init__(self,addr,port):
        self._m = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._m.bind((addr, port))
        self._dst = []
        self._current_msg = None
        self._reply_msgs = []
        self._state = MStates.IDLE

        log(f"IP: {addr}", DEBUG)
        log(f"PORT: {port}\n\n", DEBUG)
    
    def send(self):
        input("Press <enter> to send...\n")
        if self._state is MStates.READY:
            msg = self._reply_msgs.pop(0)
            log(msg.format_msg(send=True),DEBUG)
            self.__send_msg(msg)
            time.sleep(0.5) # to make sure that the message arrives to the client
            msg = self._reply_msgs.pop(0)
            log(msg.format_msg(send=True),DEBUG)
            self.__send_msg(msg)
            self._state = MStates.INSTALLED
        else:
            log(self._current_msg.format_msg(send=True),DEBUG)
            self.__send_msg(self._current_msg)
            self._current_msg = None


    def send_dass(self):
        msg = DassMSG()
        self._dst = CLIENT
        self.__send_msg(msg)

    def receive(self):
        self._m.settimeout(10)
        try:
            (msg,addr) = self.__get_msg()
            if msg is None: return
            self._dst = CLIENT if addr == AP else AP
            match msg:
                case HandshakeMSG():
                    log(msg.format_msg(),DEBUG)
                    if msg.number < 4:
                        self._current_msg = msg
                    else:
                        if not any(isinstance(x, HandshakeMSG) for x in self._reply_msgs): # only add the first msg4
                            log("Not replying msg4...\n",WATCH)
                            self._reply_msgs.append(msg)
                        else: # if i receive the second msg4 it means that the key has been reinstalled
                            log("Dropping second msg4...\n", WARNING)
                            self._state = MStates.READY
                        
                case AssMSG() | CloseMSG():
                    log(msg.format_msg(),DEBUG)
                    self._current_msg = msg

                case EncMSG():
                    log(msg.format_msg(),DEBUG)
                    if self._state is MStates.INSTALLED:
                        self._current_msg = msg
                    else:
                        log("Saving data message for later...\n",WATCH)
                        self._reply_msgs.append(msg)

                case _: # drop the packet
                    log("Out of interested packet detected\n Dropping...\n", WARNING)
        except ConnectionResetError:
            log(f"Failed to contact the {"Client" if addr == AP else "AP"}\n",ERROR)
            exit(1)
        except socket.timeout:
            log("Nothing received\n Retrying...\n",WARNING)

    def has_msg(self):
        return self._current_msg is not None or self._state is MStates.READY

    def close(self):
        if len(self._dst) > 0 :
            msg = CloseMSG("Connection terminated by AP (MitM)")
            self.__send_msg(msg)
        self._m.close() 

    def __get_msg(self):
        data, addr = self._m.recvfrom(1024)
        msg = None
        if len(data) > 0:
            msg = pickle.loads(data)
        return (msg,addr)
    
    def __send_msg(self, msg):
        serialized_msg = pickle.dumps(msg)
        self._m.sendto(serialized_msg, (self._dst[0], self._dst[1]))

def main():
    print_mitm()
    try:
        M = MitMSocket('127.0.0.1', 6000)

        log("Sending dissociation  frame to Client...\n")
        M.send_dass()

        M.receive() # eat the test frame sent by client

        log("Waiting for association frame to Client...\n")
        M.receive() # wait for association frame
        M.send() # send for association frame

        while True:
            while not M.has_msg():
                log("Receiving messages...\n")
                M.receive()
            log("Sending messages...\n",showtime=False)
            M.send()

    except KeyboardInterrupt:
        log("Interruption detected by user.",ERROR)
    finally:
        M.close()
        log("Simulation is terminated\n",showtime=False)

if __name__ == "__main__":
    main()