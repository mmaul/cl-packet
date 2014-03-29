(in-package #:packet.analyzer)
(annot:enable-annot-syntax)

(when (not lparallel:*kernel*)
  (setf lparallel:*kernel* (lparallel:make-kernel 4))
  (setf *debug-tasks-p* nil)
  )
(udp-logger "127.0.0.1")

(defun fmap (fns v) "Apply list of fns to value v"
  (mapcar (lambda (f) (funcall f v))fns))

(declaim (inline ensure-printable))
(defun ensure-printable (c)
  (declare (fixnum c)(optimize (speed 3)(safety 0)(debug 0)))
  (let ((i (char-code c)))
    (if (and  (>= i 32) (< i 127)) c #\.)))

(declaim (inline nums-to-printable-string))
(defun nums-to-printable-string (nums)
  (declare (type list nums))
  (coerce (mapcar (lambda (c) (ensure-printable (code-char c))) nums) 'string))

(declaim (inline remd))
(defun remd (w l)
  (declare (fixnum l w) (optimize (speed 3) (safety 0) (debug 0)))
  (if (< l w)
      (let ((z (+ (* w 2) (- w 1))) (r (+ (* l 2) (- l 1))))
        (+ (- z r)0))
    0))

@export
(defun hexdump (seq &key (w 16) (s t))
  (declare (type sequence seq)(fixnum w)(optimize (speed 3)(safety 0)(debug 0)))
  (let* ((d (if (typep seq 'list) seq (map 'list #'identity seq)))
         (l (length d))
         (e (if (> w l) l w)))
    (when (> l 0)
      (dotimes (a (+ (ceiling (/ l e)) 0))
        (let* ((cur (* a w))
               (end (+ cur e))
               (end1 (if (> end l) l end)))
          (format s "~4,'0X ~{~2,'0X ~}~a~a~%"
                  cur (subseq d cur end1) 
                  (make-string (remd w (- end1 cur)) 
                               :initial-element #\Space)
                  (nums-to-printable-string (subseq d cur end1))))))))

@export
(defun analyze (intf filt analyzer &key (secs nil) (nbio nil) (timeout 5)
                     (snaplen 2048) (promisc t))
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

(defun normalize-ipv4-ipv6 (ip dir)
  "Returns representation from ipv4 or ipv6 header
  dir selected source or dest"
  (ecase dir
    ( :source
      (if (eq (type-of ip) 'ipv6-header)
          (ipv6-header.source ip) 
        (ipv4-header.source ip)))
    ( :dest
      (if (eq (type-of ip) 'ipv6-header)
          (ipv6-header.dest ip) 
        (ipv4-header.dest ip))))
  )

@export
(defun dns-logger-analyzer (queue &key (log-only t) (db-only nil))
  (loop do
        (destructuring-bind (eth ip udp payload) (decode (pop-queue queue))
          (let* ((pkt (decode-dns-payload payload)))
            (when (not  db-only) (dns-logger eth ip udp payload))
            (when (not log-only) (dns-db     eth ip udp pkt))
            ))))

@export
(defun dns-logger (eth ip udp payload)
  (let* ((pkt (decode-dns-payload payload))
         (h (DNS-PACKET.HEADER pkt)))
    (labels (
             (log-rrs (n ss) (dolist (s ss)
                             (ulog (format nil "~a[~a] ~a ~a ~a ~a ~a from ~a to ~a~%"
                                           n (dns-header.id h)   (dns-answer.name s)
                                           (dns-answer.ttl s) (dns-answer.class s)
                                           (dns-answer.type s) (dns-answer.rdata s)
                                           (normalize-ipv4-ipv6 ip :source)
                                           (normalize-ipv4-ipv6 ip :dest)
                                           ))
                             )))
      (dolist  (qp  (dns-packet.questions pkt))
        (ulog (format nil "query[~a] ~a ~a ~a from ~a ~%"
                      (dns-header.id h)
                      (dns-question.qname qp)
                      (dns-question.qclass qp)
                      (dns-question.qtype qp)
                      (normalize-ipv4-ipv6 ip :source))))
      (log-rrs "authority"  (dns-packet.authorities pkt))
      (log-rrs "answer"     (dns-packet.answers pkt))
      (log-rrs "additional" (dns-packet.additionals pkt)))
    nil)
  )

#||
Database Arcitecture
Pseudo table list
Timestamp:id

domain:result

pseudo key
ns->domain

set
ns:domain -> nsserver
||#



@export
(defun dns-db (eth ip udp dns-pkt)
  (let* ((q (dns-packet.questions dns-pkt))
         (a (dns-packet.answers dns-pkt))
         (n (dns-packet.authorities dns-pkt))
         (d (dns-packet.additionals dns-pkt))
         (h (DNS-PACKET.HEADER dns-pkt)))
    (redis:with-connection ()
      (redis:with-pipelining
       (dolist (au n)
         (when (eql (dns-answer.type au) 'PACKET.DNS.CODEC::NS)
             (red-sadd (concatenate 'string "ns/" (dns-answer.name au))
                       (dns-answer.rdata au)))
         (dolist (an a)
           (when  (find (dns-answer.type  an) '(PACKET.DNS.CODEC::AAAA  PACKET.DNS.CODEC::PTR
                             PACKET.DNS.CODEC::CNAME PACKET.DNS.CODEC::NS
                             PACKET.DNS.CODEC::TXT   PACKET.DNS.CODEC::SOA)
                     )
           (red-sadd (concatenate 'string "an/" (dns-answer.name an))
                     (dns-answer.rdata an)
                     )
           (red-sadd (concatenate 'string "sc/" (dns-answer.name an))
                     (normalize-ipv4-ipv6 ip :source)
                     ))
         )
         )))))

