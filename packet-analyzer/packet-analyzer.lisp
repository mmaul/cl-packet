(in-package #:packet.analyzer)
(annot:enable-annot-syntax)

(when (not lparallel:*kernel*)
  (setf lparallel:*kernel* (lparallel:make-kernel 4)))
(udp-logger "127.0.0.1")

(defun fmap (fns v) "Apply list of fns to value v"
  (mapcar (lambda (f) (funcall f v))fns))

@export
(defun analyze (intf filt analyzer &key (secs nil) (nbio nil) (timeout 5)
                     (snaplen 1500) (promisc t))
  "

  ##Parameters##
  intf - Interface
  filt - BPF filter
  analyzer - function
  "
  (let ((pcap (make-pcap-live intf :promisc promisc :nbio nbio
                              :timeout timeout :snaplen snaplen))
        )
    (set-filter pcap filt)
    (let ((channel (make-channel))
          (queue (make-queue))
          )
      (submit-task channel (curry analyzer queue))
      (loop
       with start = (get-universal-time)
       while (or  (not secs) (<  (- (get-universal-time) start) secs)) do
       (capture pcap -1
                (lambda (sec usec caplen len buffer)
                  (push-queue  (copy-array buffer) queue)
                  ))
       ;; Better to use select/epoll/kqueue on pcap-live-descriptor
       (sleep 0.01)))
    (stop pcap))
  )

@export
(defun dns-logger-analyzer (queue)
  (loop do
        (destructuring-bind (eth ip udp payload) (decode (pop-queue queue))
          (let* ((pkt (decode-dns-payload payload))
                 
                 (q (dns-packet.questions pkt))
                 (a (dns-packet.answers pkt))
                 (n (dns-packet.authorities pkt))
                 (d (dns-packet.additionals pkt))
                 (h (DNS-PACKET.HEADER pkt)))
            (loop for qp in q do
                  (ulog (format nil "query[~a] ~a ~a ~a from ~a ~%"
                                            (dns-header.id h)
                                            (dns-question.qname qp)
                                            (dns-question.qclass qp)
                                            (dns-question.qtype qp)
                                            (if (eq (type-of ip) 'ipv6-header)
                                                (ipv6-header.source ip) 
                                              (ipv4-header.source ip)))))
            
            (loop for ns in n do
                  (ulog (format nil "authority[~a] ~a ~a ~a ~a ~a from ~a to ~a~%"
                                 (dns-header.id h)   (dns-answer.name ns)
                                 (dns-answer.ttl ns) (dns-answer.class ns)
                                 (dns-answer.type ns) (dns-answer.rdata ns)
                                 (if (eq (type-of ip) 'ipv6-header)
                                                (ipv6-header.source ip) 
                                   (ipv4-header.source ip))
                                 (if (eq (type-of ip) 'ipv6-header)
                                     (ipv6-header.dest ip) 
                                   (ipv4-header.dest ip))
                                  ))
                  )
            (loop for an in a do
                  (ulog (format nil "answer[~a] ~a ~a ~a ~a ~a from ~a to ~a~%"
                                 (dns-header.id h)   (dns-answer.name an)
                                 (dns-answer.ttl an) (dns-answer.class an)
                                 (dns-answer.type an) (dns-answer.rdata an)
                                 (if (eq (type-of ip) 'ipv6-header)
                                                (ipv6-header.source ip) 
                                   (ipv4-header.source ip))
                                 (if (eq (type-of ip) 'ipv6-header)
                                     (ipv6-header.dest ip) 
                                   (ipv4-header.dest ip))
                                  ))
                  )
            (loop for ad in d do
                  (ulog (format nil "additional[~a] ~a ~a ~a ~a ~a from ~a to ~a~%"
                                 (dns-header.id h)   (dns-answer.name ad)
                                 (dns-answer.ttl ad) (dns-answer.class ad)
                                 (dns-answer.type ad) (dns-answer.rdata ad)
                                 (if (eq (type-of ip) 'ipv6-header)
                                                (ipv6-header.source ip) 
                                   (ipv4-header.source ip))
                                 (if (eq (type-of ip) 'ipv6-header)
                                     (ipv6-header.dest ip) 
                                   (ipv4-header.dest ip))
                                  ))
                  )
            nil))))
@export
(defun dns-logger-analyzer1 (queue)
  (loop do
        (print (decode (pop-queue queue))
)))




