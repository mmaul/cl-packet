(in-package #:cl-packet.analyzer)
(annot:enable-annot-syntax)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Configuration and setup
(when (not lparallel:*kernel*)
  (setf lparallel:*kernel* (lparallel:make-kernel 4))
  (setf *debug-tasks-p* nil)
  )

  ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
  ;; Influx DB connection params
(defparameter *db* "DNS")
(defparameter *app-user* "dns")
(defparameter *app-password* "xpOSrffs12")
(defparameter *dns-db* (make-instance 'influxdb :database *db* 
				   :user *app-user*
				   :password *app-password*))



(defun init-udp-logger ()
  ;(udp-logger "10.244.6.26" :port 5353)
  (udp-logger "127.0.0.1" :port 514)
  )

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Task Handlers

@export
(defun dns-task-manager (analyzer queue)
  (let ((geodb (cl-geoip:load-db (asdf:system-relative-pathname 'geoip "GeoLiteCity.dat"))))
    (loop do
	 (destructuring-bind (eth ip udp payload) (decode (pop-queue queue))
	   (let* ((pkt (decode-dns-payload payload)))
		 (funcall log-dns-packet analyzer eth ip udp pkt geodb nil)
		 )
           ;
           ;
           ;(handler-case (error (e) (progn (format t " ~a[~a]" e payload))))
           ))))


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
		  (destructuring-bind (eth ip udp payload) (decode buffer)
				  (let ((pkt (decode-dns-payload payload)))
				    (dns-influx-db  eth ip udp pkt :geodb geodb :query nil)
				    ;;;; splunk (dns-csv-logger eth ip udp pkt :geodb geodb :query nil) 
				    ;(dns-csv-logger eth ip udp pkt :geodb geodb :query nil) 
				    ;(dns-kv-logger eth ip udp pkt :geodb geodb) 
				    ;(dns-json-logger eth ip udp pkt :geodb geodb) 
				    ;(dns-logger eth ip udp pkt)
				    ))
                  ;(handler-case  (error (e) (progn (format t " ~a[~a]" e buffer) (format t "ERROR ~a~%~a~%" e (hexdump buffer)))))
		  ;(break)
		  (when (> num 0) (setq cnt (+ cnt 1)))
                  ))
       ;; Better to use select/epoll/kqueue on pcap-live-descriptor
	 (when nbio (sleep 0.00001)))
    (stop pcap))
  )

(defun analyzer2 (intf filt logger &key (num -1) (secs nil) (nbio nil) (timeout 5)
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
		  (destructuring-bind (eth ip udp payload) (decode buffer)
				  (let ((pkt (decode-dns-payload payload)))
				    (log-dns-packet logger  eth ip udp pkt  geodb nil)
				    ;(dns-csv-logger eth ip udp pkt :geodb geodb :query nil) 
				    ;(dns-kv-logger eth ip udp pkt :geodb geodb) 
				    ;(dns-json-logger eth ip udp pkt :geodb geodb) 
				    ;(dns-logger eth ip udp pkt)
				    ))
                  ;(handler-case  (error (e) (progn (format t " ~a[~a]" e buffer) (format t "ERROR ~a~%~a~%" e (hexdump buffer)))))
		  ;(break)
		  (when (> num 0) (setq cnt (+ cnt 1)))
                  ))
       ;; Better to use select/epoll/kqueue on pcap-live-descriptor
	 (when nbio (sleep 0.00001)))
    (stop pcap))
  )



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Depreciated


