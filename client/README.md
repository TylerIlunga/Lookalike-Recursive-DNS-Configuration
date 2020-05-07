# Lookalike Recursive DNS Client

## Primary Function of the client

1. Sending the DNS query
2. Redirecting the response back to the issuer.

## Guide

- python client.py -h

## How to run the client

- python client.py host port

## How to use the client

- The client will prompt the user to choose between the following two options:

1. Standard Query
2. Inverse Query

- Next the user will be prompted to choose between the following two options:

1. Enter in a string of bytes containing the DNS query message
2. Depending on the query type
   a) Standard: Enter in the domain, the top level domain, and the ip address assigned to the target machine
   b) Inverse: Enter in the ip address assigned to the target machine

_Review the [RFC 1035](https://tools.ietf.org/html/rfc1035) to review how the incoming query should be formatted if you decide to choose entering a string of bytes. If you choose to enter in a string of bytes. The DNS message is not formatted for you. The DNS query given is very important for the implementation to process the bytes correctly, if the message is invalid, the prompted response will be invalid._
