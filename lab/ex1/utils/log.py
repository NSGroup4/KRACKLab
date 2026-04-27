from datetime import datetime

DEBUG, INFO, WATCH, WARNING, ERROR = range(5)
COLORCODES = {  "gray"  : "\033[0;90m",
	            "green" : "\033[0;32m",
                "orange": "\033[0;33m",
                "red"   : "\033[0;31m" }

def log(msg,level=INFO, showtime=True):
	match level:
		case 0: # debug
			color= "gray"
			showtime = False
		case 2: # watch
			color="green"
		case 3: # warning
			color="orange"
		case 4: # error
			color="red" 
			showtime = False
		case _:
			color = ""

	print (f"{datetime.now().strftime('[%H:%M:%S] ') if showtime else ""}{COLORCODES.get(color, "") + msg + "\033[1;0m"}")