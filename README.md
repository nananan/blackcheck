# BlackCheck

BlackCheck is a script to check if a domain or an ip is in some blacklist.

## Running

First to run the script, you need to install the library by running the following command:
```
$ pip install -r requirements.txt
```

If you need VirusTotal, you must insert you key api by adding the ```config.py``` file with the content:
API_Key_Virustotal="<YOUR_VIRUSTOTAL_KEY>"


Then, you can run:
```
$ python3 blackcheck.py 
usage: blackcheck.py [-h] (-i IP | -d DOMAIN) [-b] [-v] [-l URL_LIST] [-t THREADS]
blackcheck.py: error: one of the arguments -i/--ip -d/--domain is required
```