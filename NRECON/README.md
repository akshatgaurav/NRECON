

#NRECON
It is a reconnaissance and scanning tool 


#Features
1. Port scanning
2. Scan for version of the services running at the ports.
3. Search for Robots.txt file.
4. Check weather disallowed links in the robots.txt file are accessible ao not.
5. Scan for the presencs of Web Application Firewall.
6. Scan for SQL injection.
7. Scan for DOM based XSS.
8. Connect to the XSSER database at  http://xssed.com/, to check whether the target has been previously reported fro xss vulnerability or not.
9. Allowed HTTP headers for communicatio e.g. GET, POST, OPTION, TRACE, PUT, DELETE.
10. Find the WHOIS records related with the domain.
11. Print the response header.
12. Scan for avaliable GIT repository.


##install

```bash
git clone https://github.com/akshatgaurav/NRECON.git
cd NRECON
sudo apt-get install python nmap
python nrecon.py <target>
```
Example:  python nrecon.py www.example.com

