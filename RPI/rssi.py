# -*- coding: utf-8 -*-
"""
Created on Sun Feb  5 10:27:11 2023

@author: JUXY
"""
from scapy.all import *
import numpy as np
import time
import math
import shlex
import subprocess
import threading
from threading import Thread
import json
import random
epsilon = 0.1
valid = True
devices = {}
#devices = {'0:sda:sda:sda':{'reward':1,'time':[41421421,231321,3213213],"mean_time":0.3333,"channel":2,"total":0}}
trust_de = ["7e:c2:94:d2:e6:03","a0:43:b0:2e:66:dc","c8:47:8c:42:00:49"]
devices_reward = {}
one_device = {}
channal_re = [-1]
channel_c = 1
flag = 0
file_name = "captured_packets"
Meter = 0
suffice_data = 1000000
pre_device_time={}

for i in range(15):
    channal_re.append(0)

"""根据MacLookup的数据库返回设备信息"""
def find_mac(mac_address):
    if mac_address == "ff:ff:ff:ff:ff:ff":
        return "Broadcast"
    try:
        val = mac.lookup(mac_address)
    except Exception as e:
        val = "NA"
        print(e)

    return val

def colletc_one(packet1):
    global  one_device
    print(packet1.dBm_AntSignal)
    if packet1[Dot11].addr2 not in one_device:
        one_device[packet1[Dot11].addr2] = {}
        one_device[packet1[Dot11].addr2]["channel"] = packet1.channel   #信道
        one_device[packet1[Dot11].addr2]["SSID"] = packet1[Dot11Elt].info.decode() #设备名称
        one_device[packet1[Dot11].addr2]["beacon_interval"] = packet1[Dot11Beacon].beacon_interval #信标率
        one_device[packet1[Dot11].addr2]['rssi'] = [packet1.dBm_AntSignal]   #信号强度
        one_device[packet1[Dot11].addr2]["time"] = [packet1.time]     #时间戳
        one_device[packet1[Dot11].addr2]["dBm_AntNoise"] = [packet1[RadioTap].dBm_AntNoise]  #信噪比
    else:
        one_device[packet1[Dot11].addr2]['rssi'].append(packet1.dBm_AntSignal)
        one_device[packet1[Dot11].addr2]["time"].append(packet1.time)
        one_device[packet1[Dot11].addr2]["dBm_AntNoise"].append(packet1[RadioTap].dBm_AntNoise)    
def collect_mul(packet1):
    if packet1[Dot11].addr2 not in devices: #d1记录wifi信息
        devices[packet1[Dot11].addr2] = {}#以源MAC作为索引
        devices[packet1[Dot11].addr2]["info"] = packet1[Dot11].info.decode("utf-8")
        devices[packet1[Dot11].addr2]["type"] = "AP"
        devices[packet1[Dot11].addr2]["channel"] = packet1.channel
        devices[packet1[Dot11].addr2]["time"] = [packet1.time]
        devices[packet1[Dot11].addr2]['rssi'] = [packet1.dBm_AntSignal]
        devices[packet1[Dot11].addr2]["beacon_interval"] = packet1[Dot11Beacon].beacon_interval
        devices[packet1[Dot11].addr2]["dBm_AntNoise"] = [packet1[RadioTap].dBm_AntNoise]
        devices[packet1[Dot11].addr2]["total"] = 1
    else:
            
        if devices[packet1[Dot11].addr2]["total"] > suffice_data :
            return 
        if 2<= len(devices[packet1[Dot11].addr2]["time"]) < suffice_data : 
            devices[packet1[Dot11].addr2]['rssi'].append(packet1.dBm_AntSignal)
            devices[packet1[Dot11].addr2]["time"].append(packet1.time)  #与下行值同列
            devices[packet1[Dot11].addr2]["dBm_AntNoise"].append(packet1[RadioTap].dBm_AntNoise)    
            devices[packet1[Dot11].addr2]["mean_time"] = (devices[packet1[Dot11].addr2]["mean_time"]+(devices[packet1[Dot11].addr2]["time"][-1]-devices[packet1[Dot11].addr2]["time"][-3])/2)/2
            devices[packet1[Dot11].addr2]["total"] += 1
        else:  #数量较少，无法计算平均值
            devices[packet1[Dot11].addr2]['rssi'].append(packet1.dBm_AntSignal)
            devices[packet1[Dot11].addr2]["time"].append(packet1.time)
            devices[packet1[Dot11].addr2]["dBm_AntNoise"].append(packet1[RadioTap].dBm_AntNoise)
            devices[packet1[Dot11].addr2]["total"] += 1
            try:
                devices[packet1[Dot11].addr2]["mean_time"] = (devices[packet1[Dot11].addr2]["time"][-1]-devices[packet1[Dot11].addr2]["time"][-2])
            except:
                pass

def method_filter_HTTP(packet1):
    global file_name,Meter
    if (
        (packet1.haslayer(Dot11))  #判断是否存在Dot11,wifi
        and (packet1[Dot11].type == 0)
        and (packet1[Dot11].subtype == 8)
    ):
        if packet1[Dot11].addr2 not in trust_de:
            return
        #print(packet1[Dot11].info.decode("utf-8"))
        print(packet1.dBm_AntSignal)
        wrpcap('%s_%f.pcap'%(file_name,Meter), packet1, append=True)
        collect_mul(packet1)
    return
def method_filter_HTTP_signal(packet1):
    global file_name
    if (
        (packet1.haslayer(Dot11))  #判断是否存在Dot11,wifi
        and (packet1[Dot11].type == 0)
        and (packet1[Dot11].subtype == 8)
    ):
        if packet1[Dot11].info.decode("utf-8") != file_name:
            return 
        wrpcap('%s_%.2f.pcap'%(file_name,Meter), packet1, append=True)
        #print(packet1.dBm_AntSignal)
        colletc_one(packet1)
    return
def method_filter_HTTP_check(packet1):
    global  channel_c,flag
    if (
        (packet1.haslayer(Dot11))  #判断是否存在Dot11,wifi
        and (packet1[Dot11].type == 0)
        and (packet1[Dot11].subtype == 8)
    ):
        if packet1[Dot11].info.decode("utf-8") != file_name:
            return 
        channel_c = packet1.channel
        flag = 1                    #只针对一个设备，剩下的到时再说
    return


def Change_Freq_channel(channel_c):
    print("Channel:", str(channel_c))
    command = "iwconfig wlan1mon channel " + str(channel_c)  #更换监测信道
    command = shlex.split(command)
    subprocess.Popen(command, shell=False)
    print("success")

def choose():
    global devices,devices_reward,channal_re
    exploration_flag = True if np.random.uniform() <= epsilon else False
    if exploration_flag or not valid:
        return np.random.randint(1,14)
    for i in range(1,14):
        channal_re[i] = 0          #重新置0,确定收集到的是最新的数据
    for src in devices:
        if devices[src]['total'] > suffice_data:   #针对该设备已经收集到足够设备
            devices_reward[src] = 0  #奖励设置为0
            continue
        else:
            if devices[src]['total'] <3:
                devices_reward[src] = 0  #数量不足，无法进行判断
            else:
                try:
                    T = pre_device_time[src]  #上一次收集的数据包时间
                except:
                    T = devices[src]['time'][-1]
                now = time.time()
                u = devices[src]['mean_time'] #检测到的平均时间
                devices_reward[src] =1 - ( T + u*math.ceil((now - T ) / u)  - now )/u   #奖励计算
                #print(devices_reward[src],devices[src]['channel'])
        channal_re[devices[src]['channel']] = max(channal_re[devices[src]['channel']],devices_reward[src])   #更新该信道的奖励值
    if len(devices) == 0:
        return np.random.randint(1,14)
    print(channal_re)
    c = np.argmax(channal_re)
    #channal_re[c] = 0
    return c
        
locky = threading.Lock()    
time_each_channel = 5   # each   

def clear_devices():
    global devices
    for key in devices.keys():
        pre_device_time[key] = devices[key]["time"][-1]
        devices[key]['rssi'] = []
        devices[key]["time"] = []
        devices[key]["dBm_AntNoise"] = []

def sniff(model_flag):#进行一轮嗅探，时间由time_each_channel确定
    global channel_c,locky
    t = Thread(target=Change_Freq_channel, args=(channel_c,))
    t.daemon = True
    locky.acquire()
    t.start()
    if model_flag == 0:
        ti = AsyncSniffer(iface="wlan1mon", prn=method_filter_HTTP_check, store=0)
    else:
        ti = AsyncSniffer(iface="wlan1mon", prn=method_filter_HTTP, store=0)
    ti.start()
    time.sleep(time_each_channel)
    ti.stop()
    locky.release()
def sniff_singal(sinff_time):
    global channel_c,locky
    t = Thread(target=Change_Freq_channel, args=(channel_c,))
    t.daemon = True
    locky.acquire()
    t.start()
    ti = AsyncSniffer(iface="wlan1mon", prn=method_filter_HTTP_signal, store=0)
    ti.start()
    time.sleep(sinff_time)
    ti.stop()
    locky.release()

def main_sniff(model_flag,filename = None,meter = None):
    global channel_c,flag,file_name,Meter,one_device,devices
    file_name = filename
    Meter = meter
    if file_name.endswith(".pcap"): #提供数据包，不再进行嗅探，只进行数据的提取操作
        pcap = PcapReader(file_name)
        while True:
            packet = pcap.read_packet()
            if packet is None:
                break
            print(packet.show())
            #colletc_one(packet)
        #tf = open("%s.json"%(file_name), "w")
        #json.dump(one_device,tf)
        #tf.close()
        return
    if model_flag == 0:  #针对单一设备进行测试，主要步骤找到信道的主要信道后就开始一直在信道进行检测
        channel_c = 1
        while True:
            print("Channel\t", channel_c)
            sniff(0)
            if flag == 0:
                channel_c+=1
            else:
                break
        sniff_singal(50)
        tf = open("%s_%.2f.json"%(file_name,Meter), "w")
        json.dump(one_device,tf)
        tf.close()
        #for key in devices.keys():
        #    print(devices[key],key)
        #print(channal_re)
    else:
        index = 1
        for channel_c in range(1,14):
            sniff(1)
        while True:
            for _ in range(20):
                channel_c = choose()
                print("Channel\t", channel_c)
                sniff(1)
            tf = open("RSSI/RSSI_%s.json"%(str(index)), "w")
            json.dump(devices,tf)
            clear_devices()
            tf.close()
            index +=1

