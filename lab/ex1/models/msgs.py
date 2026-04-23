class HandshakeMSG:
    def __init__(self, repl, nonce, key, number):
        self.number = number
        self.repl=repl
        self.nonce = nonce
        self.key = key

    def format_msg(self, send=False):
        status = "Sending" if send else "Receiving"
        return (
            f"EAPOL PACKET\n"
            f"--{status}--\n"
            f"Message number: {self.number}\n"
            f"Replay counter: {self.repl}\n"
            f"Nonce: {self.nonce}\n"
            f"Key: {self.key}\n"
        )

class EncMSG:
    def __init__(self,payload,nonce):
        self.nonce=nonce
        self.payload=payload
    
    def format_msg(self, send=False):
        status = "Sending" if send else "Receiving"
        return (
            f"DATA PACKET\n"
            f"--{status}--\n"
            f"Nonce used: {self.nonce}\n"
            f"Payload: {self.payload}\n"
        )

class AssMSG: # ass requestS
    pass

class DassMSG: # deass request
    pass
    
class CloseMSG:
    def __init__(self,msg):
        self.msg = msg
    
    def __str__(self):
        return self.msg

