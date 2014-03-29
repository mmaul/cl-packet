;;;; explore.asd



(asdf:defsystem #:cl-packet
  :serial t
  :description "Extension of Luke Gorrie's packet.lisp.
    Features:
      * DNS codec and client on top of packet
      * DNS Client
      * Packet capture analysis
      * Traffic summarization and logging
      * IPv6 Implemented mostly
    Planned
      * Implement TCP and IPv6 in packet
  "
  :author "Mike Maul <mike.maul@gmail.com>"
  :license "BSD"
  :depends-on (
               #:alexandria
               #:cl-annot
               #:cl-syslog
               #:flexi-streams
               #:split-sequence
               )
  :components (
               (:file "package")
               (:file "packet")
               (:file "packet-ipv6"
                      :depends-on ("packet"))
               (:file "packet-util")
               (:file "packet-dns-codec")
               (:file "packet-dns-client")
               ))

(asdf:defsystem #:cl-packet-analyzer
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
               #:cl-packet
               )
  :components ((:module "packet-analyzer"
			:serial t
                        :components ((:file "package")
                          (:file "packet-analyzer"))
                        )))


(asdf:defsystem :cl-packet-tests
  :description "tests for cl-packet library"
  :version "0.1.0"
  :author "Mike Maul <mike.maul@gmail.com>"
  :licence "MIT"
  :encoding :utf-8
  :depends-on ("cl-packet" "nst")
  :components ((:module "tests"
			:serial t
			:components ((:file "package")
				     (:file "tests")
				     ))))
(defmethod asdf:perform ((op asdf:test-op)
                         (system (eql (asdf:find-system :cl-packet))))
  (asdf:load-system :cl-packet-tests)
  (funcall (find-symbol (symbol-name :run-tests) :cl-packet-tests)))

