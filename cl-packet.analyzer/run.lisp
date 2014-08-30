(require :cl-packet.analyzer)
;(swank:start-server :port 1234)
(cl-packet.analyzer:analyzer2 "eth1" "ip and udp port 53")
