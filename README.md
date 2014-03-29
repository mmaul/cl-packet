CL-PACKET
---------

Packet Codec and Protocol Analysis Library

FEATURES
========
*Packet Codec, Ethernet, ARP IPv4, and UDP Protocol  sections is provided by packet.lisp by Luke Gorrie

* IPv6 Packet Codec

* DNS Protocl Analysis and Logging to redis db and syslog

* Packet sniffing from the wire via Plokami

NOTES
=====
This library in in now way ready for primetime. However it does provide
useful functionality. There is currently something wrong with babel on load
you may get 

```
The value #:~A-CODE-POINT-COUNTER is not of the expected type STRING.
   [Condition of type TYPE-ERROR]
```

Just select the ACCEPT restart

An example of most of the usage functionalty can be seen in packet-analyzer.lisp

It can be exercised with the following, which will log UDP DNS requests to
syslog and a redis database. Note redis-server should be running and
user running must be able to access interface, ether by running a root or by granting with setcap.

```
On Linux
setcap cap_net_raw,cap_net_admin=eip <path to your lisp executable>
```

For more information on setcap see http://packetlife.net/blog/2010/mar/19/sniffing-wireshark-non-root-user/

Running dns packet analyzer
```
(ql:quickload :cl-packet)
(ql:quickload :cl-packet-analyzer)
(in-package :packet.analyzer)
(analyze "eth1" "udp port 53" #'dns-logger-analyzer)
```

Generate some traffic
```
host cliki.net
```

Output to syslog
```
Mar 29 14:16:57 pos COMMON-LISP-USER[4262] ﻿query[64555] cliki.net IN MX from ^192.168.1.110 
Mar 29 14:16:57 pos COMMON-LISP-USER[4262] ﻿query[64555] cliki.net IN MX from ^192.168.1.1 
Mar 29 14:16:57 pos COMMON-LISP-USER[4262] ﻿answer[64555] cliki.net 85400 IN MX 10 a.mx.cliki.net from ^192.168.1.1 to ^192.168.1.110
Mar 29 14:16:57 pos COMMON-LISP-USER[4262] ﻿answer[64555] cliki.net 85400 IN MX 19864 20.mx.cliki.net from ^192.168.1.1 to ^192.168.1.110
```
Todo
=====
Finish TCP Codec
Add more protocol analyzers


AUTHOR
Michael Maul


LICENSE
=======
The MIT License (MIT)

Copyright (c) 2014 Michael Maul

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
