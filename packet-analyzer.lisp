(in-package #:packet.analyzer)
(annot:enable-annot-syntax)

(when (not lparallel:*kernel*)
  (setf lparallel:*kernel* (lparallel:make-kernel 4)))
(udp-logger "127.0.0.1" 514)


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
        (destructuring-bind (eth ipv4 udp payload) (decode (pop-queue queue))
          (let* ((pkt (decode-dns-payload payload))
                 
                 (q (dns-packet.questions pkt))
                 (a (dns-packet.answers pkt))
                 (h (DNS-PACKET.HEADER pkt)))
            (loop for qp in q do
                  (ulog (format nil "query[~a] ~a from ~a ~%"
                                            (dns-header.id h)
                                            (dns-question.qname qp)
                                            (ipv4-header.source ipv4))))
            (loop for an in a do
                  (ulog (format nil "answer[~a] ~a ~a ~a ~a ~a from ~a to ~a~%"
                                 (dns-header.id h)   (dns-answer.name an)
                                 (dns-answer.ttl an) (dns-answer.class an)
                                 (dns-answer.type an) (dns-answer.rdata an)
                                 (ipv4-header.dest ipv4) (ipv4-header.source ipv4)))
                  )
            nil))))




