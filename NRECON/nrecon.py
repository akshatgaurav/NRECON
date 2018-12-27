
import requests
import colorama
from colorama import init
init(convert=True)
colorama.init(autoreset=True)
import xml.etree.ElementTree as ET
from threading import Thread
import threading

import sys 
import urllib
try:
	import nmap
except:
	print "Please install python nmap"
	sys.exit()

white = '\033[1;97m'
green = '\033[1;32m'
red = '\033[1;31m'
yellow = '\033[1;33m'
bad = '\033[1;31m[-]\033[1;m'
good = '\033[1;32m[+]\033[1;m'

def logo():
	hello="""
  
   _   _ ____  _____ ____ ___  _   _ 
  | \ | |  _ \| ____/ ___/ _ \| \ | |
  |  \| | |_) |  _|| |  | | | |  \| |
  | |\  |  _ <| |__| |__| |_| | |\  |
  |_| \_|_| \_\_____\____\___/|_| \_|                                       
"""
	print (red+hello)

logo()


try:
	def scan(target):
		#target= (sys.argv[1])
		print"Scanning..."
		nm = nmap.PortScanner()
		nn=nm.scan(target, arguments=' -vvv -sV --reason -p21,22,23,25,80,110,143,443,3306,3389 ')
		
		for host in nm.all_hosts():
			print ('---------------------------------------------------')
    		
     		print(green+'Host : {} ({})'.format(white+host, nm[host].hostname()))
      		print(green+'State : {}'.format(white+nm[host].state()))
    
    	   	for proto in nm[host].all_protocols():
        	 	print('----------')
         	 	print(green+'Protocol : {}'.format(white+proto))
 
        		lport = nm[host][proto].keys()
         		for port in lport:
         			print (green+'port : {}'.format(white+str(port))+'\t'+green+'state : {}'.format(white+str(nm[host][proto][port]['state']))+'\t'+green+'service : {}'.format(white+(nm[host][proto][port]['name']))+'\t'+green+'version : {}'.format(white+str(nm[host][proto][port]['product']) )+'-'+'{}'.format(nm[host][proto][port]['version'])+'-'+'{}'.format(nm[host][proto][port]['extrainfo'])       )
            		#print ('port : {}\tstate : {}'.format(port, nm[host][proto][port]['state']))
	
	        



	
	def scan_2(target):
		nm = nmap.PortScanner()
		nn=nm.scan(target, arguments=' -vvv -O   --script http-methods --script http-waf-detect,http-waf-fingerprint -p80,443 ')
		x= nm.get_nmap_last_output()
		root = ET.fromstring(x)
		print"------------------------------------"
		support=False
		waf=False
		waff=False
		for neighbor in root.iter('script'):
			if (neighbor.get('id')=='http-methods')&(support==False ):
				print green+"Allowed Methods for communication  "+white+neighbor.get('output')
				support=True
				print "----------------------"
			if (neighbor.get('id')=='http-waf-detect')&(waf==False ):
				print green+"WAF analysis"+"\n"+white+neighbor.get('output')
				waf=True
			if (neighbor.get('id')=='http-waf-fingerprint')&(waff==False ):
				print green+"WAF Fingerprint"+"\n"+white+neighbor.get('output')
				waf=True
		
		print "--------------------------------"
		print yellow+" OS Finger Printing Results"
		for neighbor in root.iter('osmatch'):
			print green+"Name :-"+white+neighbor.get('name')+green+"\t"+"Accuracy :-"+white+neighbor.get('accuracy')+"%"
		print "-----------------------"
		if support==False:
			print red+"NO support methods detected"


		if waf==False:
			print red+"NO WAF detected"
		print "-------------------"
	
	
	def header(target):
		print"--------------------"
		try:
			u = urllib.urlopen("https://"+target)
		except: 
			u=urllib.urlopen("http://"+target)
		response_headers = u.info()
		print green+"Http response header"+"\n"+white+str(response_headers)
		
		if 'x-frame-option' not in response_headers.keys():
			 print red+"Clickjacking protection is not in place"
		print"-------------------"

	def SQL(target):
		nm = nmap.PortScanner()
		nm.scan(target,arguments='-vvv --script http-sql-injection,http-xssed,http-dombased-xss,http-git -p80   ')
		x= nm.get_nmap_last_output()
		root=ET.fromstring(x)
		for neighbor in root.iter('script'):
			if neighbor.get('id')=='http-sql-injection':
				print green+"Scann results for SQL injection"
				print neighbor.get('output')
				print"----------------------"
			if neighbor.get('id')=='http-xssed':
				print green+"Scann results for XSS attack "
				print neighbor.get('output')
				print"----------------------"
			if neighbor.get('id')=='http-enum':
				print green+"Scann results for Interesting files and Folders"
				print neighbor.get('output')
				print"---------------------"
			if neighbor.get('id')=='http-dombased-xss':
				print green+"Scann results for DOM based XSS"
				print neighbor.get('output')
				print"---------------------"

			if neighbor.get('id')=='http-git':
				print green+"Scann results for git repositories"
				print neighbor.get('output')
				print"---------------------"	
		
	def WHOIS(target):
		nm = nmap.PortScanner()
		nm.scan(target,arguments='-sn --script whois-*   ')
		x= nm.get_nmap_last_output()
		root=ET.fromstring(x)
		print green+ "Information from WHOIS records"
		for neighbor in root.iter('script'):
			if neighbor.get('id')=='whois-ip':
				
				print neighbor.get('output')
				print"----------------------"
			if neighbor.get('id')=='whois-domain':
				
				print neighbor.get('output')
				print"----------------------"
			


	def robotes(url):
    		response=requests.get("https://"+url+"/robots.txt",allow_redirects=False)
    
    		print green+"Scanning for Robots.txt \n"+yellow+response.content


    		pathlist = []
    		for line in (urllib.urlopen("https://"+url+"/robots.txt")):
        		lineStr = str(line)
    
        		path = lineStr.split(': /')
    
        		if "Disallow" == path[0]:
                    		pathlist.append(path[1].replace("\n", "").replace("\r", ""))
        
                    		pathlist = list(set(pathlist))
        
    
    
    		length=len(pathlist)
    
    		if length==0:
        		print red+"Robot.txt file not found"
    		k=0
    		print green+"Checking Robot.txt file"
    		for x in range(length):
    
        		parms=pathlist[x]
        		response=requests.get("https://"+url+"/"+parms,allow_redirects=False)
			if response.status_code==200:
        			print good+sys.argv[1]+"/"+parms+" \t"+"status code: "+red+str(response.status_code)
        			x+1
			else:
				print bad+sys.argv[1]+"/"+parms+" \t"+"status code: "+red+str(response.status_code)
	        		x+1
	
			if response.status_code==200:
				k=(k+1)
		

    
    		if k:
			print green+"Number of accesable links are: "+yellow+str(k)

    		else:

			print red+"No Disallowed links are accesable"    
    



















	
		
except:
	print "Install python-nmap"

def main():	


	t1=Thread(target=header, args=(sys.argv[1], ))
	t1.start()
	
	t2=Thread(target=scan, args=(sys.argv[1], ))
	t2.start()
	
	t3=Thread(target=scan_2, args=(sys.argv[1], ))
	t3.start()	
	t3.join()
	t4=Thread(target=SQL, args=(sys.argv[1], ))
	t4.start()
	
	
	t5=Thread(target=robotes, args=(sys.argv[1], ))
	t5.start()
	t5.join()
	t6=Thread(target=WHOIS, args=(sys.argv[1], ))
	t6.start()
	
	




if __name__ == '__main__':
   
	main()
    
