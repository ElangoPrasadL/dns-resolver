Implemented a DNS resolver and a DNSSEC protected DNS resolver as well.

# DNS-resolver:
In response to an input query, the resolver will
first contact the root server, then the top-level domains, all the way down to the
corresponding name server to resolve the DNS query.
The IP address of the root servers are accessed from
https://www.iana.org/domains/root/servers.
Built a dig-like tool called “mydig”. The mydig tool takes as input: (1) name of the
domain you want to resolve and (2) type of DNS resolution. The type represents
the DNS query type. 
When run as “./mydig <name> <type>”, the tool displays the results
“similar” to the results from the dig tool.
The output is of the following form
./mydig www.cnn.com A
QUESTION SECTION:
 www.cnn.com. IN A

 ANSWER SECTION:
 www.cnn.com. 262 IN A 151.101.209.67

 Query time: 24 msec
 WHEN: Fri Feb 2 10:26:27 2018 
 MSG SIZE rcvd: 84

# DNSSEC-enabled

DNSSEC is a recent extension to the DNS protocol that guarantees the integrity of DNS. It
was officially deployed in July of 2010 (though drafts started as early as 2004) and
requires work from both DNS name servers as well as DNS resolvers to function properly.
For a DNS resolver that uses the DNSSEC
protocol, send a query to the root with a special flag set that
indicates that the DNSSEC protocol is being used. After each resolution,
verify the integrity of the DNS response. DNSSEC uses fundamental principles from
public-private key cryptography.
The fundamental components of DNSSEC are as follows:
a. RRSET: the actual DNS query data, i.e. the fully qualified domain name and IP pair
b. DNSKEY: the public key of the DNS nameserver
c. RRSIG: the digital signature of the RRSET, as signed by the corresponding private
key of the DNSKEY. Can be verified (decrypted) by the DNSKEY.
d. DS: Delegation Signer. DS helps establishes a chain of trust starting at the root.
The program takes a domain name as input and output
according to three cases:
1- DNSSEC is configured and everything is verified (output the verified IP Address). A
good example of a DNSSec that is supported is Verisign. https://dnssecdebugger.verisignlabs.com/verisigninc.com
2- DNSSEC is not enabled (output “DNSSEC not supported”)
3- DNSSEC is configured but the digital signature could NOT be verified. An example
is http://www.dnssec-failed.org/, a site run by Comcast to specifically test whether or not
your resolver has implemented DNSSEC correctly. They have a DNSKEY registered with
.org that cannot resolve the digital signature at the www.dnssec-failed.org nameserver.
In this case, output “DNSSec verification failed”.
