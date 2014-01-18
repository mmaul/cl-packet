;;;; explore.lisp

(in-package #:packet.dns.client)
(annot:enable-annot-syntax)

@export
(defun dns-lookup (name)
  (let ((sock (usocket:socket-connect "8.8.8.8" 53 :protocol :datagram))
        (p (with-buffer-output () (shove-dns-header (make-dns-header :id 123 :qr nil :aa nil :qdcount/zcount 1 :ancount/prcount  0 :arcount 0 :ad t)) (shove-dns-question (make-dns-question :qname name :qtype 1 :qclass 1))))
        )
    (usocket:socket-send sock p (length p))
    (decode-dns (usocket:socket-receive sock (make-array '(1500) :element-type '(unsigned-byte 8))1500)
                )
    )
  )
