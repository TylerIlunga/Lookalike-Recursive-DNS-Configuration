**CMSI 355** Networks, Spring 2020

# Assignment 0414
We conclude the programming work for this course with a full-function, top-to-bottom network-based application. This particular writeup is for the application’s server side.

## Background Reading
The full tic-tac-toe servers listed in Dr. Toal’s [Python](https://cs.lmu.edu/~ray/notes/pythonnetexamples#tictactoe), [JavaScript](https://cs.lmu.edu/~ray/notes/jsnetexamples#tictactoe), and [WebSockets](https://cs.lmu.edu/~ray/notes/websockets/) pages are the closest samples that we now have for a full-function server. Multiple good practices are present there which are worth modeling:
* Machine-interpretable protocol messages (that are still human-readable enough for _nc_ interaction…with some imagination!)
* Clear server feedback when given invalid input
* Scalable strategy for high connection volume (i.e., games operate “independently” after two players connect, and release resources on their own upon conclusion)
* Straightforward protocol documentation (though more than that may be needed for more sophisticated applications)

Library/framework reference documentation will continue to prove useful; don’t hesitate to go into greater depth based on what you saw in the one-shot assignments:
* Python: [socketserver](https://docs.python.org/3/library/socketserver.html), [socket](https://docs.python.org/3/library/socket.html)
* JavaScript: [net](https://nodejs.org/api/net.html)
* WebSockets: [ws](https://github.com/websockets/ws), [Python WebSockets](https://websockets.readthedocs.io/)

For deeper background and details, Chapters 3 and 4 of the Comer book continue to apply for this assignment. The real-world protocols in Chapter 4 can now be viewed as a set of examples and case studies that might be useful when making design decisions about your own protocol.

## For Submission: Full-Function Application Server
Develop a full-function network application server, complete with a well-defined protocol, per-client state management, robust data validation and error-handling, and decent scalability. The server may be runnable with _nc_ (or an _nc_-like WebSockets client) but can prioritize efficient client _application_ interactions over human-usable direct communication.

The server may build upon code that was written for the earlier assignments, or it may be completely new (but presumably based on things you learned with those simpler servers). You may also team up for this server.

If your server is an implementation of a real-world protocol, make sure to discuss scope with me. Some protocols, if implemented in full, are well beyond the scope of this assignment. We can define a subset that will be commensurate with the other application servers being developed by the class.

The server should reflect the best practices described in the following sections.

### Good Protocol Design
* _Machine-interpretable messages:_ Make sure that network clients don’t need to work too hard in order to interpret and act upon messages from the server
* _Access to application state:_ Make sure that the protocol provides sufficient data to clients so that they can give the user complete information and feedback on what’s happening with the application
* _Helpful server feedback:_ Make sure that the server gives the client clear responses that communicate any results from the client’s messages to server—e.g., whether the messages were valid, whether the operation requested/implied by the messages were fulfilled, whether more information is needed, etc. Again, remember that the network client is the intermediary between your application and the user—the more your client knows about what your server is doing, the better it can communicate the state of the application to the human user

### Robust Implementation and Reasonable Scalability
* _Threaded operation:_ Make sure that multiple clients can interact with your server without unnecessarily waiting for other clients to finish (except for when your application and protocol actually _call for_ some waiting on each other based on what the application needs, such as when one client is waiting for a second client to join a game)
* _Appropriate limits and checks:_ Watch out for resource use in your application server and watch out for unnecessarily unbounded situations (e.g., number of users in a chat room; size of state data being tracked in memory; closing concluded socket connections)—always project, “what if a huge number of requests hits my server at the same time?” and plan your server’s activities to accommodate that possibility
* _Server-side error-handling:_ Ensure that unexpected server situations don’t terminate the server; use proper exception handling and logging so that if things do go wrong, you have enough information as a starting point for tracking things down

### Good Documentation
* _Application overview:_ Provide documentation that describes the awesome things that your application server is meant to do over a network
* _Protocol usage:_ Give prospective client developers (including yourselves!) sufficient information on how to interact with the server and how to interpret its responses
* (if applicable) _Message syntax:_ For full-blown applications, many directives will have parameters, specific formats, data types, etc.—make sure that information for this is fully available so that prospective client developers know how to validate data going to and from your server
* _Security and privacy concerns:_ We’re doing our server in “early Internet style” 😅 where data will be sent over the network in the clear. Industrial-strength hardening is also unlikely to happen (unless you totally rock it with Locust and are able to act upon any discoveries there). Provide a quick statement on the security and privacy implications of these characteristics, as well as any other related limitations that you think that your server has in this area.

To highlight the importance of these characteristics, some of them are direct sources of the grade for the assignment.

## Deployment to AWS
Having the source code to a network server is great; having a live instance available is even better. To complete the assignment, make sure that an instance of your server is running on an EC2 instance on AWS, publicly accessible by its default hostname with the appropriate port being open and ready to accept connections. (with that information included in your server’s documentation)

Server resource use and demand should stay well within the AWS free tier. In the unlikely event that your server has such high resource demands that it runs the risk of incurring undesirable costs, make sure that it is easy to start and stop as needed. I can give you a public key that will allow me to do this so that I can start and stop it as needed for grading purposes.

## Locust Task Suite is Optional, Extra Credit
A Locust task suite is not required for this assignment due to the anticipated increased sophistication of the application server. However, extra credit will be granted if you do produce a non-trivial one. Note that if you decide to implement your application server with WebSockets, you will need to use the [Python WebSockets library](https://websockets.readthedocs.io) to perform your Locust tasks.

If you do implement a Locust swarm, do _not_ run this against your deployed AWS instance—_that_ may very well incur costs! Although it would be nice to see AWS’s scalability in action, the possible cost of such activities isn’t a good fit for this course 😅 So keep your Locust swarms local to your own computers.

## How to Turn it In
* Commit your server code to the _server_ folder of this repository.
* Commit your server documentation to the _README.md_ file in the _server_ folder. Specifically address _at least_ the three items listed in the [Good Documentation](#good-documentation) section. Provide illustrations and diagrams if necessary or beneficial, too!
* Make sure your AWS deployment is up and running (or, if it is resource hungry, at least ready to start)—include the public hostname and port of your server in the _README.md_ file.
* For teams, _make sure to commit your own work as yourself._ Pair programming is allowed but make sure that the committer is the team member who is primarily responsible for that part of the code; other team members should clearly play the role of “other set of eyes” only, for the parts that you’re leading.
* If you implement a Locust task suite, provide the same artifacts as the one-shot assignments:
    * _locustfile.py_: _Must_ represent a set of tasks that reasonably corresponds to anticipated real-world usage—this is a prerequisite before the other items are counted
    * Exported Locust CSVs: statistics, response times, failures, exceptions
    * _locust-notes.md_: Markdown file containing your commentary on load test results (answering the same questions as the one-shot assignments)
    * (if distributed Locust was done) Web app screenshots: Web app images showing the results of distributed Locust execution

## Specific Point Allocations

This assignment covers outcomes _2a_—_2c_, _3a_, _3b_, and _4a_–_4f_ as described in the [syllabus](http://dondi.lmu.build/spring2020/cmsi355/cmsi355-spring2020-syllabus.pdf). For this particular assignment, graded categories are as follows:

| Category | Points | Outcomes |
| -------- | -----: | -------- |
| Network protocol | 60 points total | |
| • Machine-interpretable messages | 20 points | _2b_, _2c_, _3a_, _3b_, _4a_–_4d_ |
| • Access to application state | 20 points | _2b_, _2c_, _3a_, _3b_, _4a_–_4d_ |
| • Helpful server feedback | 20 points | _2b_, _2c_, _3a_, _3b_, _4a_–_4d_ |
| Robustness and scalability | 60 points total | |
| • Threaded operation | 20 points | _3a_, _3b_, _4a_–_4d_ |
| • Limits and checks | 20 points | _3a_, _3b_, _4a_–_4d_ |
| • Error handling | 20 points | _3a_, _3b_, _4a_–_4d_ |
| Documentation | 40 points total | |
| • Application overview | 5 points | _4c_, _4d_ |
| • Protocol usage | 15 points | _3a_, _3b_, _4c_, _4d_ |
| • Message syntax and/or other content | 7 points | _3a_, _3b_, _4c_, _4d_ |
| • Security and privacy concerns | 10 points | _2b_, _2c_, _3a_, _3b_, _4c_, _4d_ |
| • AWS server information | 3 points | _3a_, _3b_, _4c_, _4d_ |
| AWS deployment | 40 points total | |
| • Ease of startup/shutdown | 10 points | _2a_, _4d_ |
| • Proper configuration (ports, public IP) | 15 points | _2a_, _4d_ |
| • Functions as expected | 15 points | _2a_, _2c_, _3a_, _3b_, _4d_ |
| Locust artifacts | up to 20 points extra credit | |
| • Non-trivial task suite (prerequisite for others) | 10 points | _2a_, _2c_, _3a_, _3b_, _4a_–_4d_|
| • CSV results | 2 points | _2a_ |
| • Commentary | 4 points | _2a_, _2b_ |
| • Distributed Locust screenshots (if applicable) | 4 points | _2a_ |
| Version Control | deduction only | _4e_ |
| Punctuality | deduction only | _4f_ |
| **Total** | **200** |
