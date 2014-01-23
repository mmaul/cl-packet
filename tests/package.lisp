(defpackage :cl-packet-tests
  (:use :cl)
  ;(:import-from :cl-packet :get-priority :get-facility 
  ;		invalid-priority invalid-facility) 
  ;(:import-from :cl-packet )
                                        ;(:shadowing-import-from :cl-syslog.udp :log)
  (:use :cl-packet)
  (:export :run-tests))

(in-package :cl-packet-tests)

(defun run-tests ()
  (let ((*print-pretty* t))
    (nst:nst-cmd :run-package #.*package*)))
