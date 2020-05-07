**CMSI 355** Networks, Spring 2020

# Assignment 0505
If we have a full-function server, then we must also match it with a full-function client. Although a good chunk of the client might not directly relate to networking in particular, every aspect of the client contributes to successful interaction between your application’s user(s) and your overall service.

## Background Reading
In a way, successful network client design is pretty much about successful interaction design in general, so background readings from a design aspect would correspond with general interaction design background readings as well. However, some principles/concepts that are _particularly_ suited to network clients include:
* Feedback
* Errors: good error messages, preventing errors
* Speak the user’s language
Look these up or review them to get pointers on good design decisions for your client.

For command-line clients, given that the user has _domain knowledge_ of the underlying application, programs like _curl_, _git_, _dig_, _ssh_, _scp_, _npm_, and _yarn_ are feature-rich and fairly straightforward to use. Again, the tasks that these programs perform are pretty technical to begin with so the assumption is that the user is conceptually familiar with what they do to begin with—but once that understanding is there, they are quite capable at what they do and generally pretty usable.

In terms of client _implementation_, the sample code so far illustrates the core network code, with the most sophisticated one being the tic-tac-toe web client for the WebSockets version of the tic-tac-toe server, which is [embedded in Dr. Toal’s WebSockets page](https://cs.lmu.edu/~ray/notes/websockets/) from CodePen.

## For Submission: Full-Function Network Client
Develop a full-function network client to interact with your full-function server. For pure socket servers, this will have to be a text-based application—but you’d be surprised with what you can do with them on modern terminals! Servers that have been ported to WebSockets may be paired with web app clients.

The client application must demonstrate the full feature set of your network protocol. If it is a text-based program, it must be easy to set up and run right from a clone of your repository. If it is a web app, it should be easy to run both locally from a repository clone _and_ available on the Internet via AWS.

From an implementation perspective, the client must provide a _complete intermediary layer_ between the human user and your server. In other words: _no blind relays or echos_ as well as _good error handling_:
* Make sure that your client validates and checks all user input before deciding to send it to the server—at its best, user input should not have to expose any protocol details at all, allowing the human user to focus purely on data, content, and actions within the application.
* Make sure that your client interprets all server responses in order to provide understandable, actionable information to the human user. As with user input, server response specifics should ideally never be exposed directly to the human user—the client should focus on the data/content of the responses and not their mechanical details or syntax. The sole exception to this guideline would be specific messages from the server that are known to carry content that is directly meant to be seen by the user.
* Make sure that your client can gracefully handle possible unexpected events such as dropped connections, long delays, or erroneous server messages. Keep the user well-informed without overwhelming them with technical information; recover gracefully when possible or, if recovery is not possible, exit gracefully with a clear statement for why things had to end prematurely.

Beyond these criteria, the client should simply work well and be usable, providing a pleasant and effective interaction with your service. Finally, a basic _README.md_ file should introduce users to the client, key application concepts, and its user interface. It is less of a reference document than the server _README.md_ and more of a user manual and feature showcase.

### Web Client Deployment to AWS
If you have chosen to implement your client as a web app, make sure to also deploy it to AWS as a public website so that running it is as simple as pointing a web browser to its hostname. React applications can be served from Amazon S3 with little additional configuration. Other types of web apps can run from an EC2 instance.

### How to Turn it In
* Commit your client code to the _client_ folder of this repository.
* Commit your client documentation to the _README.md_ file in the _client_ folder. As stated earlier, this document should be addressed to human users more specifically, showing off what your application and do as well as giving them enough information to use your client effectively.
* If your client is a web app, make sure that your AWS deployment is up and running—include the web app’s URL in the _README.md_ file.
* For teams, _make sure to commit your own work as yourself._ Pair programming is allowed but make sure that the committer is the team member who is primarily responsible for that part of the code; other team members should clearly play the role of “other set of eyes” only, for the parts that you’re leading.

## Specific Point Allocations
This assignment covers outcomes _2b_, _2c_, _3a_, _3b_, and _4a_–_4f_ as described in the [syllabus](http://dondi.lmu.build/spring2020/cmsi355/cmsi355-spring2020-syllabus.pdf). For this particular assignment, graded categories are as follows:

| Category | Points | Outcomes |
| -------- | -----: | -------- |
| Client separation of concerns | 50 points total | |
| • User input validation | 20 points | _2b_, _2c_, _3a_, _3b_, _4a_–_4d_ |
| • Server response interpretation | 20 points | _2b_, _2c_, _3a_, _3b_, _4a_–_4d_ |
| • Unexpected error handling | 10 points | _2b_, _2c_, _3a_, _3b_, _4a_–_4d_ |
| Client interaction design | 40 points total | |
| • General usability | 10 points | _3b_, _4a_–_4d_ |
| • Feedback (particularly for network activities) | 10 points | _3b_, _4a_–_4d_ |
| • Error prevention | 10 points | _3b_, _4a_–_4d_ |
| • Error reporting | 10 points | _3b_, _4a_–_4d_ |
| Documentation | 10 points total | |
| • Client overview | 3 points | _4c_, _4d_ |
| • Client execution and/or URL | 2 points | _3a_, _3b_, _4c_, _4d_ |
| • Client usage | 5 points | _3a_, _3b_, _4c_, _4d_ |
| Version Control | deduction only | _4e_ |
| Punctuality | deduction only | _4f_ |
| **Total** | **100** |
