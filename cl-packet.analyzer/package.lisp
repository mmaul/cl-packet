(defpackage :cl-packet.analyzer.util
  (:use :common-lisp
        :packet
        )
  (:export :fmap :ensure-printable :nums-to-printable-string :remd :hexdump :normalize-ipv4-ipv6 :epoch-to-human-time)
  )

(defpackage :cl-packet.analyzer.logger
  (:use :common-lisp
        :cl-packet
        :packet.dns.codec
        :cl-influxdb
	:cl-geoip
        :cl-packet.analyzer.util
        :redis
	:cl-influxdb 
        )
  (:shadowing-import-from :cl-syslog.udp :udp-logger :ulog :log)
  (:import-from :flexi-streams :string-to-octets :octets-to-string)
  (:shadow buffer)
  (:export dns-logger dns-stream-logger dns-udp-syslog-logger dns-redis-logger dns-influxdb-logger 
           log-dns-packet)
  )

(defpackage :cl-packet.analyzer
  (:nicknames :analyzer)
  (:use :common-lisp
        :cl-variates
        :plokami
        :iterate
        :lparallel
        :lparallel.queue
        :packet
        :packet.dns.codec
        
	:cl-geoip
        :cl-packet.analyzer.logger
        :cl-packet.analyzer.util
        :cl-packet.analyzer.util 
        )
  (:shadowing-import-from :cl-syslog.udp :udp-logger :ulog :log)
  (:import-from :flexi-streams :string-to-octets :octets-to-string)
  (:shadow buffer)
  (:shadowing-import-from :iterate
                          repeat)
  (:shadowing-import-from :alexandria
                          copy-file
                          copy-stream
                          curry
                          copy-array
                          )
  )



