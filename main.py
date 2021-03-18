import socket
import threading
import scan_ui
from PyQt5 import QtCore, QtGui, QtWidgets
import sys
from scapy.all import *
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

lock = threading.Lock()
port_state = []
finished_port_state = []
threads = []

class MyScanner(QtWidgets.QWidget,scan_ui.Ui_dialog):
    def __init__(self):
        super(MyScanner, self).__init__()
        self.setupUi(self)
        self.StartScanButton.clicked.connect(self.scan_start)
        self.ClearButton.clicked.connect(self.clear)
        self.checkBox_open.stateChanged.connect(self.check_box_change)
        self.checkBox_closed.stateChanged.connect(self.check_box_change)
        self.ExitButton.clicked.connect(self.exit)
        self.host_name = self.HostName.toPlainText()
        self.host_address = self.HostAdress.toPlainText()
        self.port_range = [0, 65535]
        self.ip_range = [0, 255]
        self.ip_internet_number = self.Internetnumber.toPlainText()

    def scan_start(self):
        self.ScanSate.clear()
        self.host_name = self.HostName.toPlainText()
        self.host_address = self.HostAdress.toPlainText()
        self.ip_internet_number = self.Internetnumber.toPlainText()
        self.port_range[0] = int(self.PortMin.toPlainText())
        self.port_range[1] = int(self.PortMax.toPlainText())
        self.ip_range[0] = int(self.HostnumberMin.toPlainText())
        self.ip_range[1] = int(self.HostnumberMax.toPlainText())
        self.tcp_scan()

    def tcp_scan(self):
        global port_state,threads
        socket.setdefaulttimeout(1)
        for host in range(self.ip_range[0], self.ip_range[1] + 1):
            for port in range(self.port_range[0], self.port_range[1] + 1):
                if self.radio_tcpcon.isChecked():
                    t = threading.Thread(target=tcp_con_scanner,
                                         args=(str(self.ip_internet_number) + '.' + str(host), port))
                elif self.radio_tcpsyn.isChecked():
                    t = threading.Thread(target=tcp_syn_scanner,
                                         args=(str(self.ip_internet_number) + '.' + str(host), port))
                elif self.radio_tcpfin.isChecked():
                    t = threading.Thread(target=tcp_fin_scanner,
                                         args=(str(self.ip_internet_number) + '.' + str(host), port))
                elif self.radio_tcpnull.isChecked():
                    t = threading.Thread(target=tcp_null_scanner,
                                         args=(str(self.ip_internet_number) + '.' + str(host), port))
                elif self.radio_tcpxmas.isChecked():
                    t = threading.Thread(target=tcp_xmas_scanner,
                                         args=(str(self.ip_internet_number) + '.' + str(host), port))
                elif self.radio_udpscan.isChecked():
                    t = threading.Thread(target=udp_scanner,
                                         args=(str(self.ip_internet_number) + '.' + str(host), port))

                threads.append(t)
                t.start()
            for t in threads:
                t.join()

            port_state = sorted(port_state, key=lambda x: x[1])
            finished_port_state.append(port_state)
            threads.clear()
            self.ScanSate.clear()
            self.ScanSate.insertPlainText('Scan Finished : ' + str(port_state[0][3]))
            self.check_box_change()
            port_state = []

    def clear(self):
        global finished_port_state
        self.plainTextEdit.clear()
        self.ScanSate.clear()
        finished_port_state = []

    def check_box_change(self):
        self.plainTextEdit.clear()
        if self.checkBox_open.isChecked():
            for i in finished_port_state:
                for j in i:
                    if j[2] == 1:
                        self.plainTextEdit.insertPlainText(j[3] + '#Host : %s，Port %d open\n' % (j[0], j[1]))
        if self.checkBox_closed.isChecked():
            for i in finished_port_state:
                for j in i:
                    if j[2] == 0:
                        self.plainTextEdit.insertPlainText(j[3] + '#Host : %s，Port %d closed\n' % (j[0], j[1]))

    def exit(self):
        exit()

def tcp_con_scanner(host, port):
    global port_state
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        lock.acquire()
        port_state.append((host, port, 1, 'TCP CONNECT'))
        s.close()
        lock.release()
    except:
        lock.acquire()
        port_state.append((host, port, 0, 'TCP CONNECT'))
        lock.release()

def tcp_syn_scanner(host, port):
    s = sr1(IP(dst=host) / TCP(dport=port, flags='S'), timeout=2, verbose=0)
    lock.acquire()
    if s is None:
        port_state.append((host, port, 0, 'TCP SYN'))
    else:
        if s['TCP'].flags == 'SA':
            res_s = sr1(IP(dst=host) / TCP(dport=port, flags='R'), timeout=2, verbose=0)
            port_state.append((host, port, 1, 'TCP SYN'))
        elif s['TCP'].flags == 'R' or s['TCP'].flags == 'RA':
            port_state.append((host, port, 0, 'TCP SYN'))
    lock.release()

def tcp_fin_scanner(host, port):                                                        #windows下无论端口开放与否只回复RA 只适用于Linux系统
    s = sr1(IP(dst=host) / TCP(dport=port, flags='F'), timeout=5, verbose=0)
    lock.acquire()
    if s is None:
        port_state.append((host, port, 1, 'TCP FIN'))
    else:
        port_state.append((host, port, 0, 'TCP FIN'))
    lock.release()

def tcp_null_scanner(host, port):                                                       #windows下无论端口开放与否只回复RA 只适用于Linux系统
    s = sr1(IP(dst=host) / TCP(dport=port, flags=''), timeout=5, verbose=0)
    lock.acquire()
    if s is None:
        port_state.append((host, port, 1, 'TCP NULL'))
    elif s.haslayer(TCP):
        port_state.append((host, port, 0, 'TCP NULL'))
    lock.release()

def tcp_xmas_scanner(host, port):                                                       #windows下无论端口开放与否只回复RA 只适用于Linux系统
    s = sr1(IP(dst=host) / TCP(dport=port, flags='FPU'), timeout=5, verbose=0)
    lock.acquire()
    if s is None:
        port_state.append((host, port, 1, 'TCP XMAS'))
    elif s.haslayer(TCP):
        port_state.append((host, port, 0, 'TCP XMAS'))
    lock.release()

"""def tcp_ack_scanner(host, port):                                                                              #只能确定端口是否被过滤
    s = sr1(IP(dst=host) / TCP(dport=port, flags='A'), timeout=5, verbose = 0)                                 #type = 3 code = 1,Host Unreachable——主机不可达
    lock.acquire()                                                                                              #         code = 2,Protocol Unreachable——协议不可达
    if s is None:                                                                                               #        code = 3,Port Unreachable——端口不可达
        port_state.append((host, port, 2, 'TCP ACK'))                                                          #         code = 9,Destination network administratively prohibited——目的网络被强制禁止
    elif s.haslayer('TCP') and s['TCP'].flags == 'R':                                                         #         code = 10,Destination host administratively prohibited——目的主机被强制禁止
        port_state.append((host, port, 3, 'TCP ACK'))                                                          #         code = 13,Communication administratively prohibited by filtering——由于过滤，通信被强制禁止
    elif s.haslayer('ICMP') and int(s['ICMP'].type) == 3 and int(s['ICMP'].code) in [1, 2, 3, 9, 10, 13]:
        port_state.append((host, port, 2, 'TCP ACK'))
    lock.release()

def tcp_window_scanner(host, port):
    s = sr1(IP(dst=host) / TCP(dport=port, flags='A'), timeout=5, verbose = 0)
    lock.acquire()
    if s is None:
        port_state.append((host, port, 0, 'TCP Window'))
    elif s.haslayer('TCP') and s['TCP'].window == 0:
        port_state.append((host, port, 0, 'TCP Window'))
    elif s.haslayer('TCP') and s['TCP'].window > 0:
        port_state.append((host, port, 1, 'TCP Window'))
    lock.release()"""

def udp_scanner(host, port):
    s = sr1(IP(dst=host) / UDP(dport = port), timeout = 5, verbose = 0)
    lock.acquire()
    if s is None:
        port_state.append((host, port, 1, 'UDP SCAN'))                         #                           ICMP ERROR TYPE 3 CODE 1 2 9 10 13 port:filtered
    elif s.haslayer('ICMP'):
        port_state.append((host, port, 0, 'UDP SCAN'))
    else:
        port_state.append((host, port, 0, 'UDP SCAN'))
    lock.release()

if __name__ == '__main__':
    app =  QtWidgets.QApplication(sys.argv)
    ui = MyScanner()
    ui.show()
    sys.exit(app.exec_())