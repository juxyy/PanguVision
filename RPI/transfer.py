import zipfile
import os
import socket
import shutil




def compress_folder(input_folder, output_zip):
    with zipfile.ZipFile(output_zip, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(input_folder):
            for file in files:
                zipf.write(os.path.join(root, file), arcname=os.path.join(root[len(input_folder)+1:], file))

def send_files(ip, port):
    #复制VIO数据
    '''
    src_path = '/home/juxy/Desktop/device-detector-ble-main/vioData.json'
    dst_path = os.getcwd()+ '/RSSI'
    dst_file_path = os.path.join(dst_path, os.path.basename(src_path))
    shutil.copy(src_path, dst_file_path)
    '''
    compress_folder( 'RSSI/',  'RSSI.zip')
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((ip, port))
    with open( 'RSSI.zip', 'rb') as file:
        while True:
            data = file.read(1024)
            if not data:
                break
            client_socket.sendall(data)
    print('WiFi_and_VIO transmitted successfully!')
    client_socket.close()



def receive_file(filename,server_socket):
    conn, addr = server_socket.accept()
    try:
        os.remove(filename)
    except:
        pass
    with open(filename, 'wb') as file:
        while True:
            data = conn.recv(1024)
            if not data:
                break
            file.write(data)
    print('reuslt.json received successfully!')
    conn.close()
def revc():#挂起接收程序
    #jieshoujieguo 
    filename = 'deviceLocation.json'
    port = 7000
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', port))
    server_socket.listen(1)
    receive_file(filename,server_socket)    
    server_socket.close()
'''
ip = '192.168.2.134'
port = 12345
send_RSSI_file(ip, port)
'''


