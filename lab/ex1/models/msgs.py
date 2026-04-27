from datetime import datetime

class HandshakeMSG:
    def __init__(self, repl, nonce, key, number):
        self.number = number
        self.repl=repl
        self.nonce = nonce
        self.key = key
    
    def __str__(self):
        return "HandshakeMSG"

    def format_msg(self, send=False):
        status = "Sending" if send else "Receiving"
        return (
            f"{self.__str__()} // {status}\n"
            f"Message number: {self.number}\n"
            f"Replay counter: {self.repl}\n"
            f"Nonce: {self.nonce}\n"
            f"Key: {self.key}\n"
        )

class EncMSG:
    def __init__(self,payload,nonce):
        self.nonce=nonce
        self.payload=payload
        self.time = datetime.now().strftime('[%H:%M:%S] ')

    def __str__(self):
        return "EncMSG"
    
    def format_msg(self, send=False):
        status = "Sending" if send else "Receiving"
        return (
            f"{self.__str__()} // {status}\n"
            f"Nonce used: {self.nonce:#010x}\n"
            f"Payload: {self.payload}\n"
            f"Time: {self.time}\n"
        )

class AssMSG: # ass requestS
    def __str__(self):
        return "AssMSG"
    
    def format_msg(self, send=False):
        status = "Sending" if send else "Receiving"
        return (
            f"{self.__str__()} // {status}\n"
        )


class DassMSG: # deass request
    def __str__(self):
        return "DassMSG"
    
    def format_msg(self, send=False):
        status = "Sending" if send else "Receiving"
        return (
            f"{self.__str__()} // {status}\n"
        )

    
class CloseMSG:
    def __init__(self,msg):
        self.msg = msg
    
    def __str__(self):
        return "CloseMSG"
    
    def format_msg(self, send=False):
        status = "Sending" if send else "Receiving"
        return (
            f"{self.__str__()} // {status}\n"
            f"{self.msg}\n"
        )


