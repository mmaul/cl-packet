;;; packet-ipv6 IPv6 Packet Handling
(in-package #:packet)
(annot:enable-annot-syntax)

;; Shamelesly stolen from iolib
(defun ensure-number (value &key (start 0) end (radix 10) (type t) (errorp t))
  (let ((parsed
         (typecase value
           (string
            (ignore-errors (parse-integer value :start start :end end
                                          :radix radix :junk-allowed nil)))
           (t value))))
    (cond
      ((typep parsed type) parsed)
      (errorp (error 'parse-error)))))


(deftype ub16 () '(unsigned-byte 16))
@export
;; Shamelesly stolen from iolib
 (defun colon-separated-to-vector (string)
  "Convert a colon-separated IPv6 address to a (SIMPLE-ARRAY (UNSIGNED-BYTE 16) 8)."
  (check-type string string "a string")
  (when (< (length string) 2)
    (error 'parse-error))
  (flet ((handle-trailing-and-leading-colons (string)
           (let ((start 0)
                 (end (length string))
                 (start-i 0)
                 (trailing-colon-p nil)
                 (tokens-from-leading-or-trailing-zeros 0))
             (when (char= #\: (char string 0))
               (incf start)
               (unless (char= #\: (char string 1))
                 (setq start-i 1)
                 (setq tokens-from-leading-or-trailing-zeros 1)))
             (when (char= #\: (char string (- end 1)))
               (setq trailing-colon-p t)
               (unless (char= #\: (char string (- end 2)))
                 (incf tokens-from-leading-or-trailing-zeros))
               (decf end))
             (values start end start-i trailing-colon-p
                     tokens-from-leading-or-trailing-zeros)))
         ;; we need to use this instead of dotted-to-vector because
         ;; abbreviated IPv4 addresses are invalid in this context.
         (ipv4-string-to-ub16-list (string)
           (let ((tokens (split-sequence #\. string)))
             (when (= (length tokens) 4)
               (let ((ipv4 (map 'vector
                                (lambda (string)
                                  (let ((x (ignore-errors
                                             (parse-integer string))))
                                    (if (or (null x) (not (<= 0 x #xff)))
                                        (error 'parse-error)
                                        x)))
                                tokens)))
                 (list (dpb (aref ipv4 0) (byte 8 8) (aref ipv4 1))
                       (dpb (aref ipv4 2) (byte 8 8) (aref ipv4 3)))))))
         (parse-hex-ub16 (string)
           (ensure-number string :type 'ub16 :radix 16)))
    (multiple-value-bind (start end start-i trailing-colon-p extra-tokens)
        (handle-trailing-and-leading-colons string)
      (let* ((vector (make-array 8 :element-type 'ub16 :initial-element 0))
             (tokens (split-sequence #\: string :start start :end end))
             (empty-tokens (count-if #'emptyp tokens))
             (token-count (+ (length tokens) extra-tokens)))
        (unless trailing-colon-p
          (let ((ipv4 (ipv4-string-to-ub16-list (lastcar tokens))))
            (when ipv4
              (incf token-count)
              (setq tokens (nconc (butlast tokens) ipv4)))))
        (when (or (> token-count 8) (> empty-tokens 1)
                  (and (zerop empty-tokens) (/= token-count 8)))
          (error 'parse-error))
        (loop for i from start-i and token in tokens do
              (cond
                ((integerp token) (setf (aref vector i) token))
                ((emptyp token) (incf i (- 8 token-count)))
                (t (setf (aref vector i) (parse-hex-ub16 token)))))
        vector))))



@export
(defun vector-to-colon-separated (vector &optional (case :downcase))
  "Convert an (SIMPLE-ARRAY (UNSIGNED-BYTE 16) 8) to a colon-separated IPv6
address. CASE may be :DOWNCASE or :UPCASE."
  
  (check-type case (member :upcase :downcase) "either :UPCASE or :DOWNCASE")
  (let ((s (make-string-output-stream)))
    (flet ((find-zeros ()
                       (let ((start (position 0 vector :start 1 :end 7)))
                         (when start
                           (values start
                                   (position-if #'plusp vector :start start :end 7)))))
           (princ-subvec (start end)
                         (loop :for i :from start :below end
                               :do (princ (aref vector i) s) (princ #\: s))))
      (cond
       
       (t
        (let ((*print-base* 16) (*print-pretty* nil))
          (when (plusp (aref vector 0)) (princ (aref vector 0) s))
          (princ #\: s)
          (multiple-value-bind (start end) (find-zeros)
            (cond (start (princ-subvec 1 start)
                         (princ #\: s)
                         (when end (princ-subvec end 7)))
                  (t (princ-subvec 1 7))))
          (when (plusp (aref vector 7)) (princ (aref vector 7) s))))))
    (let ((str (get-output-stream-string s)))
      (ecase case
        (:downcase (nstring-downcase str))
        (:upcase (nstring-upcase str))))))


@export-structure
(defstruct (ipv6-address (:conc-name #:ipv6-address.)
                         (:print-function print-ipv6-address))
  (quads 0 :type  (SIMPLE-ARRAY (UNSIGNED-BYTE 16) 8)))


@export
(defun simple-print-ipv6-address (address stream depth)
  "Print IPv4 addresses as in ^192.168.0.1."
  (declare (ignore depth))
  (format stream "~{~X~X~^:~}" (coerce (ipv6-address.quads address) 'list)))
  

@export
(defun print-ipv6-address (address stream depth)
  "Print IPv4 addresses as in ^192.168.0.1."
  (declare (ignore depth))
  ( format stream "~A" (vector-to-colon-separated (ipv6-address.quads  address)))
)
#||
From RFC-2460
IPv6 Header Format


   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version| Traffic Class |           Flow Label                  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Payload Length        |  Next Header  |   Hop Limit   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   +                                                               +
   |                                                               |
   +                         Source Address                        +
   |                                                               |
   +                                                               +
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   +                                                               +
   |                                                               |
   +                      Destination Address                      +
   |                                                               |
   +                                                               +
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   Version              4-bit Internet Protocol version number = 6.

   Traffic Class        8-bit traffic class field.  See section 7.

   Flow Label           20-bit flow label.  See section 6.

   Payload Length       16-bit unsigned integer.  Length of the IPv6
                        payload, i.e., the rest of the packet following
                        this IPv6 header, in octets.  (Note that any





Deering & Hinden            Standards Track                     [Page 4]

 
RFC 2460                   IPv6 Specification              December 1998


                        extension headers [section 4] present are
                        considered part of the payload, i.e., included
                        in the length count.)

   Next Header          8-bit selector.  Identifies the type of header
                        immediately following the IPv6 header.  Uses the
                        same values as the IPv4 Protocol field [RFC-1700
                        et seq.].

   Hop Limit            8-bit unsigned integer.  Decremented by 1 by
                        each node that forwards the packet. The packet
                        is discarded if Hop Limit is decremented to
                        zero.

   Source Address       128-bit address of the originator of the packet.
                        See [ADDRARCH].

   Destination Address  128-bit address of the intended recipient of the
                        packet (possibly not the ultimate recipient, if
                        a Routing header is present).  See [ADDRARCH]
                        and section 4.4.
||#

;;;### decoder

@export
(defun grab-ipv6-address ()
  "Grab a vector of NUM octets."
  (let ((num 16)
        (start (bit-octet *decode-position*)))
    (incf *decode-position* (* num 8))
    
    (make-ipv6-address :quads (coerce  (subseq *decode-buffer* start (+ num start)) '(SIMPLE-ARRAY (UNSIGNED-BYTE 16) )
				       
				       ))))

@export
(defun grab-ipv6-address1 ()
  "Grab a vector of NUM octets."
  (make-ipv6-address :quads (make-array '(8) :element-type '(unsigned-byte 16)
                                        :initial-contents (loop for i from 1 to 8 collect (grab-bits 16)))))

  

@export-structure
(defstruct (ipv6-header (:conc-name #:ipv6-header.))
  (version         nil :type (or null (unsigned-byte 4)))
  (traffic-class            nil :type (or null (unsigned-byte 8)))
  (flow-label             nil :type (or null (unsigned-byte 20)))
  (payload-length       nil :type (or null (unsigned-byte 16)))
  (next-header              nil :type (or null (unsigned-byte 8)))
  (hop-limit           nil :type (or null (unsigned-byte 8)))
  (source          nil :type (or null ipv6-address))
  (dest            nil :type (or null ipv6-address)))

@export
(defun grab-ipv6-header ()
  (make-ipv6-header :version (grab-bits 4)
                    :traffic-class (dpb (grab-bits 4) (byte 4 4) (grab-bits 4))
                    :flow-label (grab-bits 20)
                    :payload-length (octet-vector-to-int-2 (grab-octets 2))
                    :next-header (get-protocol  (grab-octet))
                    :hop-limit (grab-octet)
                    :source (grab-ipv6-address1)
                    :dest (grab-ipv6-address1)
                                    )
                  )






















