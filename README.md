# Proxy_Kerberos_Auth_Tester
Tools like curl do not allow Kerberos to be negotiated if the PROXY FQDN does not equal to the SPN record. This tool workaround this limitation allows testing of Kerberos Proxy authN against many number of proxies sitting behind a load-balancer

# Run
python jcurl.py -h

# Pre-requisites
- Win client joined to domain
  - Point the client to explicit PROXY
- Win KDC to provide the TGT and SGT to the client
  - setspn -A HTTP/someproxy.domain.local <username>
- Explicit proxy using Proxy-Authenticate authN method supporting NEGOTIATE directive
