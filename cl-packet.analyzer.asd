#+sbcl (declaim (sb-ext:muffle-conditions sb-ext:compiler-note))
(asdf:defsystem #:cl-packet.analyzer
  :serial t
  :description "Packet analyzer functionality
    Features:
      * Collection of raw network traffic
      * Packet analsis of select protocols
      * storage
  "
  :author "Mike Maul <mike.maul@gmail.com>"
  :license "BSD"
  :depends-on (
               #:alexandria
               #:cl-annot
               #:plokami
               #:iterate
               #:lparallel
               #:cl-syslog
               #:flexi-streams
               #:split-sequence
               #:cl-variates
               #:cl-redis
               #:cl-influxdb
               #:cl-packet
               #:geoip
               #:simple-date-time
               #:apply-argv
               )
  :components ((:module "cl-packet.analyzer"
			:serial t
                        :components 
			((:file "package")
			 (:file "utilities")
			 (:file "dns-logger")
                         (:file "analyzer")
                         
			 ;(:file "run-analyzer")
			 )
                        )))

