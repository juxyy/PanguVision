from rssi import main_sniff
from transfer import send_files,revc
import multiprocessing
import time
def transfer():
    while True:
        print(1)
        time.sleep(5) #向PC发送WiFi数据
        ip = '192.168.137.247'
        port = 7002
        send_files(ip, port)

p1 = multiprocessing.Process(target=main_sniff,args=(1,"xiaoyanff",0))
#p2 = multiprocessing.Process(target=transfer)
#p3 = multiprocessing.Process(target=revc)
p1.start()
#p2.start()
#p3.start()





