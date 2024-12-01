import socket
import ssl
import base64
import time
import winkerberos as kerberos
import argparse
import getpass

def cliWrapper():
    parser = argparse.ArgumentParser(description="Kerberos Proxy AuthN Tester")
    parser.add_argument('-sh', '--host', type=str, default="www.example.com", help=f"Server Host IP/FQDN (default: www.example.com)")
    parser.add_argument('-sp', '--port', type=int, default=443, help="Server Port (default: 443)")
    parser.add_argument('-pr', '--protocol', type=str, default="https", help="HTTP vs HTTPS schema (default: https)")
    parser.add_argument('-ps', '--proxy_server', type=str, default="192.168.1.195", help="Proxy IP/FQDN (default: 192.168.1.195)")
    parser.add_argument('-s', '--spn', type=str, default="HTTP/proxy.cloud.turbovci.co.uk", help="Service Principal Name (default: HTTP/proxy.cloud.turbovci.co.uk)")
    parser.add_argument('-pp', '--proxy_port', type=int, default="8080", help="Proxy Port (default: 8080)")
    parser.add_argument('-hm', '--http_method', type=str, default="GET", help="HTTP method (default: GET)")
    parser.add_argument('-hp', '--http_path', type=str, default="/", help="HTTP URI path (default: /)")
    parser.add_argument('-hu', '--http_user_agent', type=str, default="Kerberos Tester", help="HTTP user agent string (default: Kerberos Tester)")
    parser.add_argument('-cu', '--connect_user_agent', type=str, default="Kerberos Tester", help="CONNECT user agent string (default: Kerberos Tester)")   
    args = parser.parse_args()
    object = proxyCall(args.host, args.port, args.proxy_server, args.proxy_port, args.connect_user_agent, args.http_user_agent, args.protocol, args.http_method, args.http_path, args.spn)
    object.get_socket()

    
def get_kerb_token(sp):
    _, ctx = kerberos.authGSSClientInit(sp)
    kerberos.authGSSClientStep(ctx, "")
    token = kerberos.authGSSClientResponse(ctx)
    kerberos.authGSSClientClean(ctx)
    return token

def do_BASIC_AuthN():
    user = input("Enter user: ")
    passwd = getpass.getpass("Enter password: ")
    creds = user + ":" + passwd
    encodedBytes = base64.b64encode(creds.encode('utf-8'))
    encodedString = encodedBytes.decode('utf-8')
    encoded_creds = encodedString
    return encoded_creds

class proxyCall()::w

    def __init__(self, *args, tunneled=False):
        self.HOST = args[0]
        self.PORT = args[1]
        self.PROXY = args[2]
        self.PROXY_PORT = args[3]
        self.CONNECT_UA = args[4]
        self.HTTP_UA = args[5]
        self.proto = args[6]
        self.method = args [7]
        self.uri_path = args[8]
        self.spn = args[9]
        self.auth_round = False
        self.tunneled = tunneled

    def http_parser(self, headers, body):
        import re
        self.headers = headers
        self.headers_parsed = re.split(r'\r\n|\r|\n', headers)
        print(f"****HTTP RESPONSE HEADERS****\n") 
        for line in self.headers_parsed:
            print(f"{line}")
        print('\n')        
        self.body_decoded = body.decode('UTF-8')
        self.body_parsed = re.split('\r\n|\r|\n', self.body_decoded)
        print(f"****HTTP RESPONSE BODY****\n")  
        for line in self.body_parsed:
            print(line.strip('\r\n'))  

    def connect_response_parser(self, headers, body):
        import re
        self.headers = headers
        self.headers_parsed = re.split(r'\r\n|\r|\n', headers)
        print(f"****CONNECT RESPONSE HEADERS****\n") 
        for line in self.headers_parsed:
            print(f"{line}")
        print('\n')
        print(f"****CONNECT RESPONSE BODY****\n")    
        self.body_decoded = body.decode('UTF-8')
        self.body_parsed = re.split('\r\n|\r|\n', self.body_decoded)
        self.body_parsed = list(filter(None, self.body_parsed))
        for line in self.body_parsed:
            print(line)
        print('\n')    
        if "200" in self.headers:
            self.do_SSLhandshake()
        if "407" in self.headers:
            self.auth_round = True
            self.get_socket()    


    def connect_request_parser(self, request_headers):
        import re
        parsed = re.split(r'\r\n|\r|\n', request_headers) 
        for line in parsed:
            print(line)

    def get_socket(self):
        if not self.auth_round:
            print(f"##############################")
            print(f"Starting first round of authN")
            print(f"##############################\n")
            if self.proto == "https": 
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as self.sock:
                    self.sock.connect((self.PROXY, self.PROXY_PORT))
                    self.do_CONNECT()
            elif self.proto == "http":
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as self.sock:
                    self.sock.connect((self.PROXY, self.PROXY_PORT))
                    if self.method == "POST":
                        self.do_POST()
                    elif self.method == "GET":    
                        self.do_GET_with_auth()

        elif self.auth_round:
            print(f"##############################") 
            print(f"Starting second round of authN")
            print(f"##############################\n")
            if self.proto == "https":             
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as self.sock:
                    self.sock.connect((self.PROXY, self.PROXY_PORT))
                    self.do_CONNECT_with_auth()  
            elif self.proto == "http":
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as self.sock:
                    self.sock.connect((self.PROXY, self.PROXY_PORT))
                    self.do_GET_with_auth()


    def https_handler(self):
        response_bytes = b''
        while b'\r\n\r\n' not in response_bytes:
            response_bytes += self.ssl_socket.recv(1024)
        headers, body = response_bytes.split(b'\r\n\r\n', 1)
        headers = headers.decode()
        content_length = None
        for header in headers.split('\r\n'):
            if header.startswith('Content-Length'):
                content_length = int(header.split(': ')[1])
                break
        reminder = len(body)
        if content_length is not None:
            while reminder < content_length:
                chunk = self.ssl_socket.recv(1024)
                body += chunk
                reminder += len(chunk)   
        self.http_parser(headers, body)          

    def http_handler(self):
        response_bytes = b''
        while b'\r\n\r\n' not in response_bytes:
            response_bytes += self.sock.recv(1024)
        headers, body = response_bytes.split(b'\r\n\r\n', 1)
        headers = headers.decode()
        content_length = None
        for header in headers.split('\r\n'):
            if header.startswith('Content-Length'):
                content_length = int(header.split(': ')[1])
                break
        reminder = len(body)
        if content_length is not None:
            while reminder < content_length:
                chunk = self.sock.recv(1024)
                body += chunk
                reminder += len(chunk)   
        self.http_parser(headers, body)  

    def connect_handler(self):
        response_bytes = b''
        while b'\r\n\r\n' not in response_bytes:
            response_bytes += self.sock.recv(1024)
        headers, body = response_bytes.split(b'\r\n\r\n', 1)
        headers = headers.decode()
        content_length = None
        for header in headers.split('\r\n'):
            if header.startswith('Content-Length'):
                content_length = int(header.split(': ')[1])
                break
        reminder = len(body)
        if content_length is not None:
            while reminder < content_length:
                chunk = self.sock.recv(1024)
                body += chunk
                reminder += len(chunk)   
        self.connect_response_parser(headers, body)  

    def create_CONNECT(self, directive, creds):
        __CONNECT_with_creds = f"CONNECT {self.HOST}:{self.PORT} HTTP/1.1\r\n" \
                               f"HOST: {self.HOST}:{self.PORT}\r\n" \
                               f"User-Agent: {self.CONNECT_UA}\r\n" \
                               f"Proxy-Authorization: {directive} {creds}\r\n" \
                               f"\r\n"
        return __CONNECT_with_creds

    def do_CONNECT(self):
        __CONNECT = f"CONNECT {self.HOST}:{self.PORT} HTTP/1.1\r\n" \
                    f"HOST: {self.HOST}:{self.PORT}\r\n" \
                    f"User-Agent: {self.CONNECT_UA}\r\n" \
                    f"\r\n"     
        self.sock.send(__CONNECT.encode())
        self.connect_handler()

    def do_CONNECT_with_auth(self):
        try:        
            krb_blob = get_kerb_token(self.spn)
            connect = self.create_CONNECT(directive="Negotiate", creds=krb_blob)
            self.connect_request_parser(connect)
            self.sock.send(connect.encode())
            self.connect_handler()
        except Exception as kerberos_exception:
            print(kerberos_exception)
            self.kerberos_exception = kerberos_exception
            creds = do_BASIC_AuthN()
            connect = self.create_CONNECT(creds=creds, directive="BASIC")
            self.connect_request_parser(connect)
            self.sock.send(connect.encode())
            self.connect_handler()

    def do_SSLhandshake(self):
        if self.tunneled:
            print(f"Starting tunnel ....")
            while True:
                msg = f"foobar"
                self.sock.send(msg.encode())
        else:    
            ssl_context = ssl.create_default_context()
            self.ssl_socket = ssl_context.wrap_socket(self.sock, server_hostname=self.HOST)
            server_certs = self.ssl_socket.getpeercert(binary_form=False)
            print(f"****SSL DETAILS****")
            print(f"ISSUER: {server_certs['issuer']}\n")
            if self.method == "GET":
                self.do_GET()
            elif self.method == "POST":
                self.do_POST()
            else:
                self.do_GET()

    def do_POST(self):
        __post = f"{self.method} {self.uri_path} HTTP/1.1\r\n" \
                f"HOST: {self.HOST}:{self.PORT}\r\n" \
                f"User-Agent: {self.HTTP_UA}\r\n" \
                f"Proxy-Connection: Keep-Alive\r\n" \
                f"Content-Length: 2049\r\n" \
                f"Content-Type: multipart/form-data; boundary=EOF123\r\n" \
                f"\r\n" \
                f"EOF123\r\n" \
                f"Content-Disposition: form-data; name=\"Python_Upload_File\";filename=\"foobar\"\r\n" \
                f"Content-Type: application/octet-stream \r\n" \
                f"\r\n" \
                f"foobar\r\n" \
                f"\r\n" \
                f"EOF123\r\n" \
                f"\r\n"
        if self.proto == "https":
            self.ssl_socket.send(__post.encode())
            self.https_handler()
        elif self.proto == "http":
            self.http_handler()

    def do_GET(self):
        __get = f"{self.method} {self.uri_path} HTTP/1.1\r\n" \
                f"HOST: {self.HOST}:{self.PORT}\r\n" \
                f"User-Agent: {self.HTTP_UA}\r\n" \
                f"\r\n"
        if self.proto == "https":
            self.ssl_socket.send(__get.encode())
            self.https_handler()
        elif self.proto == "http":
            self.sock.send(__get.encode())
            self.http_handler()

    def do_GET_with_auth(self):
        __get = f"{self.method} {self.uri_path} HTTP/1.1\r\n" \
                f"HOST: {self.HOST}:{self.PORT}\r\n" \
                f"User-Agent: {self.HTTP_UA}\r\n" \
                f"Proxy-Authorization: BASIC {self.creds}\r\n" \
                f"\r\n"
        if self.proto == "https":
            self.ssl_socket.send(__get.encode())
            self.https_handler()
        elif self.proto == "http":
            self.sock.send(__get.encode())
            self.http_handler()
            self.b = "blah"
            return self.b   


if __name__ == "__main__":
    cliWrapper()
