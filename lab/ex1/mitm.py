from models.msgs import *
from utils.ascii_prints import print_mitm

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

        print(f"IP:{addr}")
        print(f"PORT:{port}")
        print(f"MitM is definitely using: {self._m.getsockname()}")
    
    def send(self):
        input("Press <enter> to send...\n")
        if self._state is MStates.READY:
            msg = self._reply_msgs.pop(0)
            print(msg.format_msg(send=True))
            self.__send_msg(msg)
            time.sleep(0.5) # to make sure that the message arrives to the client
            msg = self._reply_msgs.pop(0)
            print(msg.format_msg(send=True))
            self.__send_msg(msg)
            self._state = MStates.INSTALLED
        else:
            print(self._current_msg.format_msg(send=True))
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
            print(addr)
            match msg:
                case HandshakeMSG():
                    if msg.number < 4:
                        print(msg.format_msg())
                        self._current_msg = msg
                    else:
                        if not any(isinstance(x, HandshakeMSG) for x in self._reply_msgs): # only add the first msg4
                            print(msg.format_msg())
                            print("Not replying msg4...\n")
                            self._reply_msgs.append(msg)
                        else: # if i receive the second msg4 it means that the key has been reinstalled
                            print(msg.format_msg())
                            print("Dropping second msg4...\n")
                            self._state = MStates.READY
                        
                case AssMSG() | CloseMSG():
                    print(msg.format_msg())
                    self._current_msg = msg

                case EncMSG():
                    print(msg.format_msg())
                    if self._state is MStates.INSTALLED:
                        self._current_msg = msg
                    else:
                        print("Saving message for later...\n")
                        self._reply_msgs.append(msg)

                case _: # drop the packet
                    print("Dropped")

        except socket.timeout:
            print("Nothing received\n Retrying...\n")

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
    try:
        print_mitm()
        M = MitMSocket('127.0.0.1', 6000)

        print("Sending dissociation  frame to Client.")
        M.send_dass()

        M.receive() # eat the test frame sent by client

        print("Waiting for association frame to Client.")
        M.receive() # wait for association frame
        M.send() # send for association frame

        while True:
            while not M.has_msg():
                print("Receiving messages...\n")
                M.receive()
            print("Sending messages...\n")
            M.send()

    except KeyboardInterrupt:
        print("Interruption detected by user.")
    finally:
        M.close()
        print("Simulation is terminated\n")

if __name__ == "__main__":
    main()