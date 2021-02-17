import scapy.all as scapy
from tkinter import *

class scan:

    def Arp(self, ip):
        self.ip = ip
        arp_r = scapy.ARP(pdst=ip)
        br = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
        request = br/arp_r
        answered, unanswered = scapy.srp(request, timeout=1)
        ip_list = []
        mac_list = []

        for i in answered:
            ip, mac = i[1].psrc, i[1].hwsrc
            ip_list.append(ip)
            mac_list.append(mac)
        return ip_list,mac_list

class _interface(scan):

    def __init__(self):
        self.toolbox()
        self.toolboxConfig()

    def toolbox(self):
        self.window = Tk()
        self.canvas = Canvas(bg="gray",width=520)
        self.iprange = Entry(width="30")
        self.addresList = Listbox(width="50",height="10")
        self.label = Label(text = "ip range" , fg = "white" , bg = "black")
        self.list = Button(text = 'scan' , command = self.show_list,bg="brown",width=10)
        self.frame = Frame()

    def show_list(self):
        self.addresList.delete(0,"end")
        self.addresList.insert(1,"             ip addres                                  mac addres  ")
        self.addresList.insert(2,"\n-------------------------------------------------------------")
        ip_list = []
        mac_list = []
        ipRange = self.iprange.get()
        ip_list,mac_list = scan.Arp(self,ipRange)
        append = ""

        for i in range(0 , len(ip_list)):
            if len(ip_list[i]) == 11:
                append = 10*" " + ip_list[i] + 31 * " " + mac_list[i]
            elif len(ip_list[i]) == 12:
                append = 10*" " + ip_list[i] + 29 * " " + mac_list[i]
            else :
                append = 10*" " + ip_list[i] + 28 * " " + mac_list[i]
            self.addresList.insert((i+3),append)

    def toolboxConfig(self):
        self.window.title("ARP SCANNER")
        self.window.resizable(width=False,height=False)
        self.window.geometry("514x185+100+100")
        self.canvas.pack()
        self.iprange.place(x=7 ,y=13)
        self.label.place(x=72,y=39)
        self.list.place(x=60,y=100)
        self.addresList.place(x=200,y=10)
        self.frame.pack(padx=5,pady=5)

if __name__ == '__main__' :
    interface = _interface()
    mainloop()