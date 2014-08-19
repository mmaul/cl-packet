(in-package #:cl-packet.analyzer)
(annot:enable-annot-syntax)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Configuration and setup
(when (not lparallel:*kernel*)
  (setf lparallel:*kernel* (lparallel:make-kernel 4))
  (setf *debug-tasks-p* nil)
  )
(udp-logger "10.244.6.26" :port 5353)
  ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
  ;; Influx DB connection params
(defparameter *db* "DNS")
(defparameter *app-user* "dns")
(defparameter *app-password* "xpOSrffs12")
(defparameter *dns-db* (make-instance 'influxdb :database *db* 
				   :user *app-user*
				   :password *app-password*))


(defun epoch-to-human-time (&optional epoch)
  "
  Syslog timestamp formatter defaults to current time.
  Optional arg epoch as epoch seconds
  Example format:2013-12-14T21:09:57.0Z-5
  "
  (let ((v (if epoch (simple-date-time:from-posix-time epoch)
             (simple-date-time:now))))
    (format nil "~a ~a:~a.~d EDT"
            (simple-date-time:yyyy-mm-dd v)
            (simple-date-time:|hh:mm| v)
            (simple-date-time:SECOND-OF v)
            (simple-date-time:MILLISECOND-OF v)
            )))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Task Handlers

@export
(defun dns-task-manager (analyzer queue)
  (let ((geodb (cl-geoip:load-db (asdf:system-relative-pathname 'geoip "GeoLiteCity.dat"))))
    (loop do
	 (destructuring-bind (eth ip udp payload) (decode (pop-queue queue))
	   (handler-case  
	       (let* ((pkt (decode-dns-payload payload)))
		 (funcall analyzer eth ip udp pkt :geodb geodb)
		 )
	     (error (e) (progn 
			  (ulog (format nil " ~a[~a]" e payload))))
	     )))))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Analyzers
@export
(defun dns-writer (stream eth ip udp pkt)
  (declare (ignore eth) (ignore udp))
  "Writes to console and syslog"
  (handler-case
      (let* ((h (DNS-PACKET.HEADER pkt)))
	(labels (
		 (log-rrs (n ss) (dolist (s ss)
				   (format stream "~a[~a] ~a ~a ~a ~a ~a from ~a to ~a~%"
                                           n (dns-header.id h)   (dns-answer.name s)
                                           (dns-answer.ttl s) (dns-answer.class s)
                                           (dns-answer.type s) (dns-answer.rdata s)
                                           (normalize-ipv4-ipv6 ip :source)
                                           (normalize-ipv4-ipv6 ip :dest)
                                           )
				   )))
	  (dolist  (qp  (dns-packet.questions pkt))
	    (format stream "query[~a] ~a ~a ~a from ~a ~%"
		    (dns-header.id h)
		    (dns-question.qname qp)
		    (dns-question.qclass qp)
		    (dns-question.qtype qp)
		    (normalize-ipv4-ipv6 ip :source)))
	  (log-rrs "authority"  (dns-packet.authorities pkt))
	  (log-rrs "answer"     (dns-packet.answers pkt))
	  (log-rrs "additional" (dns-packet.additionals pkt)))
	nil)
    (error (e) ( format t "ERROR:~a~%~%" e))
    )
  )



@export
(defun dns-logger (eth ip udp pkt)
  (declare (ignore eth) (ignore udp))
  "Writes to syslog"
  (let* ((h (DNS-PACKET.HEADER pkt)))
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


@export
(defun dns-db (eth ip udp dns-pkt)
  (declare (ignore eth) (ignore udp))
  (let* ((a (dns-packet.answers dns-pkt))
         (n (dns-packet.authorities dns-pkt)))
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



@export
(defun dns-influx-db (eth ip udp dns-pkt &key (geodb nil) (query nil))
  (declare (ignore eth) (ignore udp))
  (let* ((q-list (dns-packet.questions dns-pkt))
         (a-list (dns-packet.answers dns-pkt))
         (n-list (dns-packet.authorities dns-pkt))
         (d-list (dns-packet.additionals dns-pkt))
         (h (dns-packet.header dns-pkt))
	 (d-ip (octet-vector-to-int-4  (ipv4-address.octets (ipv4-header.dest ip)))) 
	 (s-ip (octet-vector-to-int-4  (ipv4-address.octets (ipv4-header.source ip)))) 
	 (d-geocode (if geodb (cl-geoip:get-record geodb (ccl:ipaddr-to-dotted d-ip)) nil))
	 (s-geocode (if geodb (cl-geoip:get-record geodb (ccl:ipaddr-to-dotted s-ip)) nil))
	 )
    (flet ((do-write-points (name in) 
	     
	     (write-points 
			     *dns-db* 
			     (list (list (cons :NAME  name) 
					 (cons :COLUMNS '(id client client_ip server server_ip opcode rcode qname type class ttl rdlength rdata client_cc server_cc ans_cc))
					 (cons :points (list (list (dns-header.id h) 
								   d-ip
								   (print-ipv4-address (ipv4-header.dest ip) nil 0)
								   s-ip
								   (print-ipv4-address (ipv4-header.source ip) nil 0)
								   (symbol-name (dns-header.opcode h))
								   (symbol-name (dns-header.rcode h))
								   (string-downcase (dns-answer.name in))
								   (symbol-name (dns-answer.type in))
								   (symbol-name (dns-answer.class in))
								   (dns-answer.ttl in)
								   (dns-answer.rdlength in)
								   (format nil "~a" (dns-answer.rdata in))
								   (if d-geocode (cl-geoip:record-country-code d-geocode) "")
								   (if s-geocode (cl-geoip:record-country-code s-geocode) "")
								   (if (and  geodb (eql 'PACKET.DNS.CODEC::A (dns-answer.type in))) 
								       (let ((ans-geocode 
									      (cl-geoip:get-record geodb 
												   (format nil "~a" 
													   (dns-answer.rdata in)))))
									 (if ans-geocode (cl-geoip:record-country-code ans-geocode) "")
									 
									 ))))) ))
			     
			     
			     )))
      (if ( dns-header.qr dns-pkt)
	  (progn
	    (dolist (a a-list) (do-write-points "answers" a))
	    (dolist (n n-list) (do-write-points "authorities" n))
	    (dolist (d d-list) (do-write-points "additionals" d)))
	(when query
	  (dolist (q q-list) ;opcode type class query
		 (write-points 
		  *dns-db*
		  `(((:NAME . "queries")
		     (:COLUMNS id client server opcode qtype qclass qname)
		     ,(cons :POINTS (list
				     (list (dns-header.id h) 
					   (normalize-ipv4-ipv6 d-ip :source)
					   (normalize-ipv4-ipv6 s-ip :source)
					   (symbol-name (dns-header.opcode h))
					   (symbol-name (dns-question.qtype q))
					   (symbol-name (dns-question.qclass q))
					   (string-downcase (dns-question.qname q))
					   ))))))
		 )))
      
      )
    
    
    ))

(defun dns-json-logger (eth ip udp dns-pkt &key (geodb nil))
  (declare (ignore eth) (ignore udp))
  (let* ((q-list (dns-packet.questions dns-pkt))
         (a-list (dns-packet.answers dns-pkt))
         (n-list (dns-packet.authorities dns-pkt))
         (d-list (dns-packet.additionals dns-pkt))
         (h (dns-packet.header dns-pkt))
	 (d-ip (octet-vector-to-int-4  (ipv4-address.octets (ipv4-header.dest ip)))) 
	 (s-ip (octet-vector-to-int-4  (ipv4-address.octets (ipv4-header.source ip)))) 
	 (d-geocode (if geodb (cl-geoip:get-record geodb (ccl:ipaddr-to-dotted d-ip)) nil))
	 (s-geocode (if geodb (cl-geoip:get-record geodb (ccl:ipaddr-to-dotted s-ip)) nil))
	 (timestamp (epoch-to-human-time))
	 
	 )
    (flet ((do-write-points (in section) 
	     (let ((json-string 
		    (cl-json:encode-json-to-string
		     (list 
			    (cons :timestamp timestamp)
			    (cons :id     (dns-header.id h))
			    (cons :section section)
			    (cons :d_ip   (ccl:ipaddr-to-dotted d-ip))
			    (cons :sip    (ccl:ipaddr-to-dotted s-ip))
			    (cons :opcode (symbol-name (dns-header.opcode h)))
			    (cons :rcode  (symbol-name (dns-header.rcode h)))
			    (cons :qname  (string-downcase (dns-answer.name in)))
			    (cons :type   (symbol-name (dns-answer.type in)))
			    (cons :class  (symbol-name (dns-answer.class in)))
			    (cons :ttl    (dns-answer.ttl in))
			    (cons :rlen   (dns-answer.rdlength in))
			    (cons :rdata  (format nil "~a" (dns-answer.rdata in)))
			    (cons :d_cc   (if d-geocode (cl-geoip:record-country-code d-geocode) ""))
			    (cons :s_cc   (if s-geocode (cl-geoip:record-country-code s-geocode) ""))
			    (cons :a_cc   (if (and  geodb (eql 'PACKET.DNS.CODEC::A (dns-answer.type in))) 
					      (let ((ans-geocode 
						     (cl-geoip:get-record geodb 
									  (format nil "~a" 
										  (dns-answer.rdata in)))))
						(if ans-geocode (cl-geoip:record-country-code ans-geocode) ""))
					      ""
					      )
				  ))))) 
	       (cl-syslog.udp:ulog-bare json-string)
	       
	       )))
      ;(break)
      (if ( dns-header.qr dns-pkt)
	  (progn
	    (dolist (a a-list) (do-write-points a "answer"))
	    (dolist (n n-list) (do-write-points n "authority"))
	    (dolist (d d-list) (do-write-points d "additional")))
	(progn
	  (dolist (q q-list) ;opcode type class query
		 (cl-syslog.udp:ulog-bare
		  (cl-json:encode-json-to-string
		   (list 
			  (cons :timestamp timestamp)
			  (cons :id     (dns-header.id h))
			  (cons :section "query")
			  (cons :d_ip   (ccl:ipaddr-to-dotted d-ip))
			  (cons :sip    (ccl:ipaddr-to-dotted s-ip))
			  (cons :opcode (symbol-name (dns-header.opcode h)))
			  (cons :qname (string-downcase (dns-question.qname q)))
			  (cons :type (symbol-name (dns-question.qtype q)))
			  (cons :class (symbol-name (dns-question.qclass q)))
			  (cons :d_cc   (if d-geocode (cl-geoip:record-country-code d-geocode) ""))
			  (cons :s_cc   (if s-geocode (cl-geoip:record-country-code s-geocode) ""))
			  )))
		 )))
      
      )
    
    
    ))

(defun dns-kv-logger (eth ip udp dns-pkt &key (geodb nil))
  (declare (ignore eth) (ignore udp))
  (let* ((q-list (dns-packet.questions dns-pkt))
         (a-list (dns-packet.answers dns-pkt))
         (n-list (dns-packet.authorities dns-pkt))
         (d-list (dns-packet.additionals dns-pkt))
         (h (dns-packet.header dns-pkt))
	 (d-ip (octet-vector-to-int-4  (ipv4-address.octets (ipv4-header.dest ip)))) 
	 (s-ip (octet-vector-to-int-4  (ipv4-address.octets (ipv4-header.source ip)))) 
	 (d-geocode (if geodb (cl-geoip:get-record geodb (ccl:ipaddr-to-dotted d-ip)) nil))
	 (s-geocode (if geodb (cl-geoip:get-record geodb (ccl:ipaddr-to-dotted s-ip)) nil))
	 (timestamp (epoch-to-human-time))
	 
	 )
    (flet ((do-write-points (in section) 
	     (let ((json-string 
		    (cl-json:encode-json-to-string
		     (list 
			    (cons :timestamp timestamp)
			    (cons :id     (dns-header.id h))
			    (cons :section section)
			    (cons :d_ip   (ccl:ipaddr-to-dotted d-ip))
			    (cons :sip    (ccl:ipaddr-to-dotted s-ip))
			    (cons :opcode (symbol-name (dns-header.opcode h)))
			    (cons :rcode  (symbol-name (dns-header.rcode h)))
			    (cons :qname  (string-downcase (dns-answer.name in)))
			    (cons :type   (symbol-name (dns-answer.type in)))
			    (cons :class  (symbol-name (dns-answer.class in)))
			    (cons :ttl    (dns-answer.ttl in))
			    (cons :rlen   (dns-answer.rdlength in))
			    (cons :rdata  (format nil "~a" (dns-answer.rdata in)))
			    (cons :d_cc   (if d-geocode (cl-geoip:record-country-code d-geocode) ""))
			    (cons :s_cc   (if s-geocode (cl-geoip:record-country-code s-geocode) ""))
			    (cons :a_cc   (if (and  geodb (eql 'PACKET.DNS.CODEC::A (dns-answer.type in))) 
					      (let ((ans-geocode 
						     (cl-geoip:get-record geodb 
									  (format nil "~a" 
										  (dns-answer.rdata in)))))
						(if ans-geocode (cl-geoip:record-country-code ans-geocode) ""))
					      ""
					      )
				  ))))) 
	       (cl-syslog.udp:ulog-bare (subseq json-string 1  (- (length json-string)1) ))
	       
	       )))
      ;(break)
      (if ( dns-header.qr dns-pkt)
	  (progn
	    (dolist (a a-list) (do-write-points a "answer"))
	    (dolist (n n-list) (do-write-points n "authority"))
	    (dolist (d d-list) (do-write-points d "additional")))
	(progn
	  (dolist (q q-list) ;opcode type class query
	    (let ((json-string
		   (cl-json:encode-json-to-string
		   (list 
			  (cons :timestamp timestamp)
			  (cons :id     (dns-header.id h))
			  (cons :section "query")
			  (cons :d_ip   (ccl:ipaddr-to-dotted d-ip))
			  (cons :sip    (ccl:ipaddr-to-dotted s-ip))
			  (cons :opcode (symbol-name (dns-header.opcode h)))
			  (cons :qname (string-downcase (dns-question.qname q)))
			  (cons :type (symbol-name (dns-question.qtype q)))
			  (cons :class (symbol-name (dns-question.qclass q)))
			  (cons :d_cc   (if d-geocode (cl-geoip:record-country-code d-geocode) ""))
			  (cons :s_cc   (if s-geocode (cl-geoip:record-country-code s-geocode) ""))
			  ))))
	      (cl-syslog.udp:ulog-bare (subseq json-string 1  (- (length json-string)1) )))
	    
	    
	    )))
      
      )
    
    
    ))
(defun dns-csv-logger (eth ip udp dns-pkt &key (geodb nil) (authority nil) (additional nil) (query t) (answer t))
  (declare (ignore eth) (ignore udp))
  (let* ((q-list (dns-packet.questions dns-pkt))
         (a-list (dns-packet.answers dns-pkt))
         (n-list (dns-packet.authorities dns-pkt))
         (d-list (dns-packet.additionals dns-pkt))
         (h (dns-packet.header dns-pkt))
	 (d-ip (octet-vector-to-int-4  (ipv4-address.octets (ipv4-header.dest ip)))) 
	 (s-ip (octet-vector-to-int-4  (ipv4-address.octets (ipv4-header.source ip)))) 
	 (d-geocode (if geodb (cl-geoip:get-record geodb (ccl:ipaddr-to-dotted d-ip)) nil))
	 (s-geocode (if geodb (cl-geoip:get-record geodb (ccl:ipaddr-to-dotted s-ip)) nil))
	 (timestamp (epoch-to-human-time)))
    (flet ((do-write-points (in section) 
	     (let ((json-string 
		    (format nil "~{~A~^,~}~%"
			    (list 
			     timestamp
			     (dns-header.id h)
			     section
			     (ccl:ipaddr-to-dotted d-ip)
			     (ccl:ipaddr-to-dotted s-ip)
			     (symbol-name (dns-header.opcode h))
			    (symbol-name (dns-header.rcode h))
			    (string-downcase (dns-answer.name in))
			    (symbol-name (dns-answer.type in))
			    (symbol-name (dns-answer.class in))
			    (dns-answer.ttl in)
			    (dns-answer.rdlength in)
			    (format nil "~a" (dns-answer.rdata in))
			    (if d-geocode (cl-geoip:record-country-code d-geocode) "")
			    (if s-geocode (cl-geoip:record-country-code s-geocode) "")
			    (if (and  geodb (eql 'PACKET.DNS.CODEC::A (dns-answer.type in))) 
					      (let ((ans-geocode 
						     (cl-geoip:get-record geodb 
									  (format nil "~a" 
										  (dns-answer.rdata in)))))
						(if ans-geocode (cl-geoip:record-country-code ans-geocode) ""))
					      
					      
					      ""
					      ))))) 
	       	       
	       (cl-syslog.udp:ulog-bare json-string)
	       
	       )))
      (if ( dns-header.qr dns-pkt)
	  (progn
	    (when answer (dolist (a a-list) (do-write-points a "answer")))
	    (when authority (dolist (n n-list) (do-write-points n "authority")))
	    (when additional (dolist (d d-list) (do-write-points d "additional"))))
	  (when query
	    (dolist (q q-list) ;opcode type class query
	      (cl-syslog.udp:ulog-bare
	       (format nil "~{~A~^,~}"
		       (list  timestamp
			      (dns-header.id h)
			      "query"
			      (ccl:ipaddr-to-dotted d-ip)
			      (ccl:ipaddr-to-dotted s-ip)
			      (symbol-name (dns-header.opcode h))
			      (string-downcase (dns-question.qname q))
			      (symbol-name (dns-question.qtype q))
			      (symbol-name (dns-question.qclass q))
			      (if d-geocode (cl-geoip:record-country-code d-geocode) "")
			      (if s-geocode (cl-geoip:record-country-code s-geocode) "")
			      )))
	      )))
      
      
      )
	 
	 
	 )
    
    )
  
  

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Main Entry points
@export
(defun analyzer (intf filt analyzer &key (secs nil) (nbio nil) (timeout 5)
                     (snaplen 4096) (promisc t))
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
      (submit-task channel (curry #'dns-task-manager analyzer queue))
      (loop
       with start = (get-universal-time)
       while (or  (not secs) (<  (- (get-universal-time) start) secs)) do
       (capture pcap -1
                (lambda (sec usec caplen len buffer)
		  (declare (ignore sec) (ignore usec) (ignore caplen) (ignore len))
                  (push-queue  (copy-array buffer) queue)
                  ))
       ;; Better to use select/epoll/kqueue on pcap-live-descriptor
       (sleep 0.01)))
    (stop pcap))
  )
@export
(defun analyzer2 (intf filt &key (num -1) (secs nil) (nbio nil) (timeout 5)
                     (snaplen 4096) (promisc t))
  "

  ##Parameters##
  intf - Interface
  filt - BPF filter
  analyzer - function
  "
  (let ((pcap (make-pcap-live intf :promisc promisc :nbio nbio
                              :timeout timeout :snaplen snaplen ))
        (geodb (cl-geoip:load-db (asdf:system-relative-pathname 'geoip "GeoLiteCity.dat")))
	(cnt 0)
	)
    (set-filter pcap filt)
    (loop
       with start = (get-universal-time)
       while (and  (or (not secs) (<  (- (get-universal-time) start) secs)) 
		   (or  (< num 0) (and (> num 0) (< cnt num)))) do
       (capture pcap num 
                (lambda (sec usec caplen len buffer)
		  (declare (ignore sec) (ignore usec) (ignore caplen) (ignore len))
		  (handler-case 
		      (destructuring-bind (eth ip udp payload) (decode buffer)
				  (let ((pkt (decode-dns-payload payload)))
				    (dns-influx-db  eth ip udp pkt :geodb geodb :query nil)
				    ;;;; splunk (dns-csv-logger eth ip udp pkt :geodb geodb :query nil) 
				    ;(dns-csv-logger eth ip udp pkt :geodb geodb :query nil) 
				    ;(dns-kv-logger eth ip udp pkt :geodb geodb) 
				    ;(dns-json-logger eth ip udp pkt :geodb geodb) 
				    ;(dns-logger eth ip udp pkt)
				    ))
		    (error (e) (progn 
				 (ulog (format nil " ~a[~a]" e buffer))
				 (format t "ERROR ~a~%~a~%" e (hexdump buffer))
				 ))
		    
		    )
		  ;(break)
		  (when (> num 0) (setq cnt (+ cnt 1)))
                  ))
       ;; Better to use select/epoll/kqueue on pcap-live-descriptor
	 (when nbio (sleep 0.00001)))
    (stop pcap))
  )



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Depreciated


