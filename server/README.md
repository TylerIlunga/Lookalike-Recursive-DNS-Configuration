# Lookalike Recursive DNS (server(s))

## Protocol usage

The protocol issued in the [RFC 1035](https://tools.ietf.org/html/rfc1035) document will be used to construct a proper DNS message.

That same message will contain an answer to a given query upon response.

However, if a record for the given domain, or IP address, does not exist in the recursive server's record cache (map), the recursive server will make a recursive call to two additional servers:

1. A root server

2) A foreign name server

This is done in order to fetch the proper record for the given domain/IP.

Implementation inspiration comes from _section 2.2. Common configurations_ of the [RFC 1035](https://tools.ietf.org/html/rfc1035).

## Spinning up servers

You can spin up the servers by executing the following:

```
docker-compose up
```

To Spin down

```
^C or docker-compose down
```

The Docker daemon must be active in order for the script to execute successfully.

Besides the resolver, the additional servers do not run on the same port to avoid local deployment issue.

## Message syntax

### Resolver and Recursive Server

- I strongly advise reviewing section 4.1 Messages of [RFC 1035](https://tools.ietf.org/html/rfc1035). It breaks down, in-depth, exactly how DNS messages should be formatted. Both the Resolver and the Recursive Server expect this specific format.

### Root Server

- The root server expects an ascii string that is withholds two important values separated by a colon (":"). The values, in order, are the given domain, or IP, and the query type (both which should be found in the DNS message).

* Example: "facebook.com:0"

### Name Server

- The name server expects the given domain, or IP, and the query type (both which should be found in the DNS message) as bytes. IP addresses are stored in a DNS Zone Map as raw bytes so simply decoding the bytes to an ascii string would not give the same results as in the root server.

## Security and Privacy concerns

Realistically, each server could be running as a process on separate nodes, and without proper replication, failover solutions, and/or security policies/mechanisms, any one of those nodes can serve as a single point of failure, or a threat, in the serial pipeline. For example, let's say the root server is taken offline. That could happen for several reasons. Intercepting the root server's traffic, one can spoof the impending bytes, sent back as a response, such that the given address of a name server, containing the actual IP of the requested domain, points to one of their malicious servers instead. A step towards preventing this can be encrypting traffic between nodes with TLS/SSL. Also, attackers could redirect a huge amount of traffic, using a botnet of infected nodes for example, to the root server so that the recursive server can never obtain the IP for one of the name servers. Using services such as Cloudflare, one can enable great DDOS prevention for a tradeoff of a bill every month. Furthermore, if the attacker can shell into one of the nodes running any of the server processes (Resolver, Recursive Server, Root Server, and/or Name Server) they could modify the written software for whatever malicious intent they have. For example, one could modify the recursive server's logic to never flush the cache so they can send several requests and have the process exceed its memory allocation limits. Also, they could modify the cache such that the domain points to a malicious server governed by the attacker. By having a strong password for your ssh keys, that could be one step towards solving that issue. Also, creating new users with minimal privilege can help one move away from allowing for new sessions to be created with root user privilege.
