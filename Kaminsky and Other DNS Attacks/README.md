# Task 1 - Modifying HOSTS file
Assume that you have already compromised a machine. Modify the HOSTS file to redirect the user to a malicious site whenever the user tries to access *www.example.com*. Please try this technique to redirect *www.example.com* to any IP address that you choose.

# Task 2 - Directly spoof response to the user
In this attack, the victim’s machine has not been compromised, so attackers cannot directly change the DNS query process on the victim’s machine. However, if attackers are on the same local area network as the victim, they can still achieve a great damage.

When a user types the name of a web site (a host name, such as www.example.com) in a web browser, the user’s computer will issue a DNS request to the DNS server to resolve the IP address of the host name. After hearing this DNS request, the attackers can spoof a fake DNS response. The fake DNS response will be accepted by the user’s computer if it meets the following criteria:
* The source IP address must match the IP address of the DNS server.
* The destination IP address must match the IP address of the user’s machine.
* The source port number (UDP port) must match the port number that the DNS request was sent to (usually port 53).
* The destination port number must match the port number that the DNS request was sent from.
* The UDP checksum must be correctly calculated.
* The transaction ID must match the transaction ID in the DNS request.
* The domain name in the question section of the reply must match the domain name in the question section of the request.
* The domain name in the answer section must match the domain name in the question section of the DNS request.
* The User’s computer must receive the attacker’s DNS reply before it receives the legitimate DNS response.

To satisfy all these criteria but the last one, the attackers can sniff the DNS request message sent by the victim; they can then create a fake DNS response, and send back to the victim, before the real DNS server does.

Netwox tool 105 provide a utility to conduct such sniffing and responding.

Tip: in the Netwox/Netwag tool 105, you can use the “filter” field to indicate the IP address of your target. For example, in the scenario showing below, you can use "src host 192.168.0.100".

# Tasks 3 & 4 - DNS Server Cache Poisoning Attack

# Kaminsky Attack