from datetime import datetime

DEBUG, INFO, WATCH, WARNING, ERROR = range(5)
COLORCODES = {  "gray"  : "\033[0;90m",
	            "green" : "\033[0;32m",
                "orange": "\033[0;33m",
                "red"   : "\033[0;31m" }

def log(msg,level=INFO, showtime=True):
	color = ""
	if level == DEBUG : 
		color= "gray"
		showtime = False
	if level == WARNING: color="orange"
	if level == ERROR: 
		color="red" 
		showtime = False
	if level == WATCH: color="green"
	print (f"{datetime.now().strftime('[%H:%M:%S] ') if showtime else ""}{COLORCODES.get(color, "") + msg + "\033[1;0m"}")