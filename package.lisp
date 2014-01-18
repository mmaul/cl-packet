;;;; package.lisp

(defpackage :packet
  (:use :common-lisp
        :cl-annot
        :cl-annot.class
        )
  ;; Note: exports are defined with cl-addon @export , see source
)
(defpackage :packet.util
  (:use :common-lisp
        :cl-annot))

(defpackage :packet.dns.codec
  (:use :common-lisp
        :cl-annot
        :cl-annot.class
        :packet
        )
  
  (:import-from :flexi-streams :string-to-octets :octets-to-string)
  (:import-from :split-sequence :split-sequence)
  ;; Note: exports are defined with cl-addon @export , see source
  )

(defpackage :packet.dns.client
  (:use :common-lisp
        :cl-annot
        :cl-annot.class
        :packet
        :packet.dns.codec
        )
  
  (:import-from :flexi-streams :string-to-octets :octets-to-string)
  (:import-from :split-sequence :split-sequence)
  ;; Note: exports are defined with cl-addon @export , see source
  )

(defpackage :packet.analyzer
  (:nicknames :pa)
  (:use :common-lisp
        :cl-variates
        :plokami
        :iterate
        :lparallel
        :lparallel.queue
        :packet
        :packet.dns.codec
        )
  (:shadowing-import-from :cl-syslog.udp :udp-logger :ulog :log)
  ;(:import-from :alexandria :curry)
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
  

(defpackage :cl-packet
  (:use :common-lisp
        :packet
        :packet.dns.codec
        :packet.dns.client
        :packet.analyzer
        )
    (:shadowing-import-from :cl-syslog.udp :udp-logger :ulog :log))
