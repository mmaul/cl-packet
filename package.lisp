;;;; package.lisp

(defpackage :packet
  (:use :common-lisp
        :cl-annot
        :cl-annot.class
        )
  (:import-from :split-sequence :split-sequence)
  (:import-from :alexandria :emptyp :lastcar)
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


  

(defpackage :cl-packet
  (:use :common-lisp
        :packet
        :packet.dns.codec
        :packet.dns.client
        )
  )
