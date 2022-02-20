import requests, json
from requests.sessions import Session
import time, sys, argparse
from threading import Thread,local
import queue as Queue


def get_session():
    if not hasattr(thread_local,'session'):
        thread_local.session = requests.Session() # Create a new Session if not exists
    return thread_local.session

def check_url(to_search):
    '''get URL from queue until no url left in the queue'''
    session = get_session()
    global stop_threads
    while not q.empty():
        url = q.get()
        #print(url)
        if not stop_threads:
            try:
                with session.get(url,timeout=5) as response:
                    if to_search in response.text:
                        print("FOUND on " + str(url) + "\n" )
                        stop_threads = True
            except requests.Timeout as e:
                pass
        q.task_done()          # Tell the Queue, this url is done

def blacklist(to_search):
    '''Start 4 threads'''
    global thread_num

    for i in range(thread_num):
        t_worker = Thread(target=check_url(to_search))
        t_worker.start()
    q.join()                   # Main Thread wait until all url finished 

'''VirusTotal '''
def virustotal(to_search, what_search):
    #IP
    #url = "https://www.virustotal.com/api/v3/ip_addresses/ip"
    #Domain
    #url = "https://www.virustotal.com/api/v3/domains/domain"

    url = "https://www.virustotal.com/api/v3/%s/%s" % (what_search,to_search)
    print(url)
    
    headers = {"Accept": "application/json", "X-Apikey": API_Key_Virustotal} 
     
    response = requests.request("GET", url, headers=headers) 
     
    #print(response.json.data)
    json_data = json.loads(response.text)
    last_analysis_stats = json_data['data']['attributes']['last_analysis_stats']
    print("VirusTotal analysis stats:")
    print("Harmless: " + str(last_analysis_stats['harmless']))
    print("Malicius: " + str(last_analysis_stats['malicious']))
    print("Suspicious: " + str(last_analysis_stats['suspicious']))
    print("Undetected: " + str(last_analysis_stats['undetected']))
    print("Timeout: " + str(last_analysis_stats['timeout']))
    print("\n")


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='blackcheck.py') 
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-i', '--ip', dest='ip', type=str, help='IP to search')
    group.add_argument('-d', '--domain', dest='domain', type=str, help='Domain to search')
    parser.add_argument('-b', '--blacklist', dest='blacklist', action='store_true', help='Search on Blacklist')
    parser.add_argument('-v', '--virustotal', dest='virustotal', action='store_true', help='Search on VirusTotal')
    parser.add_argument('-l', '--list', dest='url_list', type=str, default="lists_url.txt", help='File with the url of blacklists')
    parser.add_argument('-t', '--thread', dest='threads', type=int, default=4, help='Number of thread')

    args = parser.parse_args()

    if not args.ip and not args.domain:
        #print("You must set an ip or a domain to search!")
        parser.print_help()
        sys.exit()

    to_search = args.ip or args.domain

    q = Queue.Queue(maxsize=0)            #Use a queue to store all URLs
    file_url = open(args.url_list, "r")
    count_url = 0
    for url in file_url:
        q.put(url.strip())

    thread_local = local()          #The thread_local will hold a Session object

    stop_threads = False
    thread_num = args.threads

    start = time.time()
    if args.blacklist:
        print("Start Blacklist search\n")
        blacklist(to_search)

    if args.virustotal:
        from config import API_Key_Virustotal
        print("Start VirusTotal\n")
        
        what_search = "ip_addresses" if args.ip else "domains"
        virustotal(to_search, what_search)

    end = time.time()
    print('Time work: %s seconds' % (end - start))





    
