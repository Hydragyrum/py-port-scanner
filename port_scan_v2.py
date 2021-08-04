import sys, socket, ipaddress, signal, argparse, random, string, struct, time, select, subprocess
import concurrent.futures

#### Handle Signals ####


class colours:
    red = "\033[91m"
    green = "\033[92m"
    blue = "\033[34m"
    orange = "\033[33m"
    purple = "\033[35m"
    end = "\033[0m"


def sigHandler(sig, frame):
    print(f"{colours.orange}\n[*] Exiting....{colours.end}\n")
    sys.exit(0)

class PingScanner:
    def ping(self, host):
        reponse = subprocess.call(["ping", host, "-c", "1"], stdout=subprocess.DEVNULL)
        is_alive = reponse == 0
        if is_alive:
            print(f"Host: {colours.purple}{host}{colours.end} is {colours.green}reachable{colours.end}")
        return is_alive

class PortScanner:
    def scan_port(self, ip, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = s.connect_ex((ip, port))

        if result == 0:
            print(f"{ip} : {port} {colours.green}OPEN{colours.end}")

    def scan(self, ip):
        ip_port_tuples = ((ip, port) for port in range(0, 65535))
        with concurrent.futures.ThreadPoolExecutor(max_workers=10000) as executor:
            executor.map(lambda p: self.scan_port(*p), ip_port_tuples)
            
class Scanner:
    def __init__(self):
        self.ping_scanner = PingScanner()
        self.port_scanner = PortScanner()
    
    def parse_args(self):
        parser = argparse.ArgumentParser(description="A simple, silly, over-the-top ping/port scanner made in Python")
        parser.add_argument("hosts", help="The target(s) IPs. May use CIDR notation to scan multiple hosts in parallel.")
        parser.add_argument("--force", "-f", default=False, action="store_true", help="Force port scan (ignore ping status).")
        args = parser.parse_args()
        self.args = args

    def scan_ip(self, host):
        ip = format(host)
        is_alive = True
        if (self.args.force == False):
             is_alive = self.ping_scanner.ping(ip)
        if is_alive:
            self.port_scanner.scan(ip)

    def scan(self):
        net4 = ipaddress.ip_network(self.args.hosts)
        with concurrent.futures.ThreadPoolExecutor(max_workers=256) as executor:
            executor.map(self.scan_ip, net4.hosts())


#### Run ####
if __name__ == "__main__":
    signal.signal(signal.SIGINT, sigHandler)
    scanner = Scanner()
    scanner.parse_args()
    scanner.scan()
