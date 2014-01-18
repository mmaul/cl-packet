;;;; explore.asd



(asdf:defsystem #:cl-packet
  :serial t
  :description "Extension of Luke Gorrie's packet.lisp.
    Features:
      * DNS codec and client on top of packet
      * DNS Client
      * Packet capture analysis
      * Traffic summarization and logging
    Planned
      * Implement TCP and IPv6 in packet
  "
  :author "Mike Maul <mike.maul@gmail.com>"
  :license "BSD"
  :depends-on (#:cls
               #:alexandria
               #:cl-annot
               #:plokami
               #:iterate
               #:lparallel
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
               (:file "packet-analyzer")
               

               ))

