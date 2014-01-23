;;; packet-dns.lisp -- Extension of Packet library for DNS Protocol
;;; Parsing
(in-package :packet.dns.codec)
(annot:enable-annot-syntax)

(defvar *dns-qr-names* '((0 . :request) (1 . :response))
  "Mapping between DNS QR bit and their symbolic names.")
(defparameter *debug* nil)
(defun dns-QR (qr)
  "Return the symbolic name for QR, if appropriate."
  (if *resolve-protocols*
      (lookup qr *dns-qr-names* :errorp nil)
      qr))

;labels          63 octets or less
;names           255 octets or less
;TTL             positive values of a signed 32 bit number.
;UDP messages    512 octets or less

(defvar *dns-opcode-names* '((0 . :query)  (1 . :iquery) (2 . :status) (3 . :na)
                             (4 . :notify) (5 . :update) (6 . :na)     (7 . :na)
                             (8 . :notify) (9 . :update) (10 . :na)    (11 . :na)
                             (12 . :na)    (13 . :na)    (14 . :na)    (15 . :na)
                             )
  
                     "Mapping between DNS opcodes bit and their symbolic names.")

                                        ; |AA|TC|RD|RA| Z|AD|CD|

(defun lookup-opcode (oc )
  (let ((ocf (assoc oc *dns-opcode-names*)))
    (if ocf (cdr ocf) nil)))
     
(defparameter req-body #(170 52 129 128 0 1 0 1 0 0 0 0 3 101 112 97 3 103 111 118 0 0 1 0 1 192 12 0 1 0 1 0 0 0 60 0 4 134 67 21 34))


(defvar *dns-rcode-fixed* '(
           (0 .   :NoError)   ;No Error                           [RFC 1035]
           (1 .   :FormErr)   ;Format Error                       [RFC 1035]
           (2 .   ServFail)   ;Server Failure                     [RFC 1035]
           (3  .  NXDomain)   ;Non-Existent Domain                [RFC 1035]
           (4 .   NotImp)     ;Not Implemented                    [RFC 1035]
           (5 .   Refused)    ;Query Refused                      [RFC 1035]
           (6  .  YXDomain)   ;Name Exists when it should not     [RFC 2136]
           (7 .   YXRRSet)    ;RR Set Exists when it should not   [RFC 2136]
           (8 .   NXRRSet)    ;RR Set that should exist does not  [RFC 2136]
           (9 .   NotAuth)    ;Server Not Authoritative for zone  [RFC 2136]
           (10 .   NotZone)   ;Name not contained in zone         [RFC 2136]
           (17 .   BADKEY)    ;Key not recognized                 [RFC 2845]
           (18 .   BADTIME)   ;Signature out of time window       [RFC 2845]
           (19 .   BADMODE)   ;Bad TKEY Mode                      [RFC 2930]
           (20 .   BADNAME)   ;Duplicate key name                 [RFC 2930]
           (21 .   BADALG)))   ;Algorithm not supported            [RFC 2930]

(defvar *dns-qtype*
  '( (1 . A)      ;a host address
    (2 . NS)     ;an authoritative name server
    (3 . MD)     ;a mail destination (Obsolete - use MX)
    (4 . MF)     ;a mail forwarder (Obsolete - use MX)
    (5 . CNAME)  ;the canonical name for an alias
    (6 . SOA)    ;marks the start of a zone of authority
    (7 . MB)     ;a mailbox domain name (EXPERIMENTAL)
    (8 . MG)     ;a mail group member (EXPERIMENTAL)
    (9 . MR)     ;a mail rename domain name (EXPERIMENTAL)
    (10 . NULL)  ;a null RR (EXPERIMENTAL)
    (11 . WKS)   ;a well known service description
    (12 . PTR)   ;a domain name pointer
    (13 . HINFO) ;host information
    (14 . MINFO) ;mailbox or mail list information
    (15 . MX)    ;mail exchange
    (16 . TXT)   ;text strings
    (28 . AAAA)  ;AAAA record
    (33 . SRV)
    (41 . EDNS0)
    (43 . DS)
    (46 . RRSIG)   ;text strings
    (48 . DNSKEY)   ;text strings
    ( 252 . AXFR) ; A request for a transfer of an entire zone
    ( 253 . MAILB) ;A request for mailbox-related records (MB, MG or MR)
    ( 254 . MAILA) ;A request for mail agent RRs (Obsolete - see MX)
    ( 255 . ANY)) ;A request for all records
  )

(defvar *dns-class* 
  '( (1 .  IN);             1 the Internet
     (2 . CS);              2 the CSNET class(Obsolete)
     (3 . CH);              3 the CHAOS class
     (4 . HS))) ;           4 Hesiod [Dyer 87]

(defun lookup-rcode (rc &key ( rr nil))
  (let ((rcf (assoc rc *dns-rcode-fixed*)))
    (cond
     (rcf (cdr rcf))
     ((and  (>= 11 rc) (<= rc 15)) :na)    ; Available for assignment
     ((= 16 rc) (if rr  :BADVERS :badsig)) ; Bad OPT Version  [RFC 2671] 
                                           ; 16 BADSIG TSIG SignatureFailure 
                                           ; [RFC 2845]
     ((and (>= rc 22) (<= rc 3840)) :na) ;
     ((and (>= rc 3841) (<= rc 4095)) :pu)
     ((and (>= rc 4096) (<= rc 65535)) :na)
     (t :err)
     ))
  )


@export
(defun ipv4-address->int (addr)
  "Takes octet vector and converst to integer"
  (dpb (elt addr 0) (byte 8 24) (dpb (elt addr 1) (byte 8 16)
                                     (dpb (elt addr 2) (byte 8 8) (elt addr 3)))))

;( ( IN A (lambda (r) (make-ipv4-address :octets r))    )
;( IN CNAME (FLEXI-STREAMS::STRING-TO-OCTETS )
;     ( IN MX)
;     ( IN NS))
@export-structure
(defstruct (dns-header (:conc-name #:dns-header.))
  (id     nil :type (or null (unsigned-byte 16)))
  (qr   nil :type bool) ;Query or request flag
  (opcode nil :type (or null (unsigned-byte 8) symbol))
  (aa   nil :type bool)
  (tc   nil :type bool)
  (rd   nil :type bool)
  (ra   nil :type bool)
  (z    nil :type bool)
  (ad   nil :type bool)
  (cd   nil :type bool)
  (rcode   nil :type (or null symbol))
  (qdcount/zcount 0 :type integer) 
  (ancount/prcount 0 :type integer) 
  (nscount/upcount 0 :type integer)
  (arcount 0 :type integer))

@export-structure
(defstruct (dns-question (:conc-name #:dns-question.))
  (qname nil :type (or nil string))
  (qtype nil :type (or nil symbol))
  (qclass nil :type (or nil symbol)))

@export-structure
(defstruct (dns-answer (:conc-name #:dns-answer.))
  (name nil :type (or nil string))
  (type nil :type (or nil symbol)) 
  (class nil :type (or nil symbol)) 
  (ttl 0 :type integer)
  (rdlength 0 :type integer)
  (rdata nil))

@export-structure
(defstruct (dns-packet (:conc-name #:dns-packet.))
  (header nil :type (or nil dns-header))
  (questions nil :type list)
  (answers nil :type list)
  (authorities nil :type list)
  (additionals nil :type list)
  )

@export
(defun grab-label ()
  (let ((l '()) (len  (elt (grab-octets 1) 0)))
    (when *debug* (format t "~%[grab-label ~3d]~%" len))
    (loop 
     for i from 0 to (-  len 1) 
     do
     (let ((p packet::*decode-position*)
           (c (code-char (elt (grab-octets 1) 0))))
       (when *debug* (format t "~4d ~3d ~a~%"  (octet-bit p) (char-code c) c))
       (setf l (cons c l))
       ))
    (concatenate 'string (reverse l))))

@export
(defun shove-label (l)
  (let ((v (FLEXI-STREAMS::STRING-TO-OCTETS l)))
    (shove-octet (length v)) (shove-vector v)))
#|
he compression scheme allows a domain name in a message to be
represented as either:
   - a sequence of labels ending in a zero octet
   - a pointer
   - a sequence of labels ending with a pointer
Pointers can only be used for occurances of a domain name where the
format is not class specific.  If this were not the case, a name server
or resolver would be required to know the format of all RRs it handled.
As yet, there are no such cases, but they may occur in future RDATA
formats.

If a domain name is contained in a part of the message subject to a
length field (such as the RDATA section of an RR), and compression is
used, the length of the compressed name is used in the length
calculation, rather than the length of the expanded name.
|#
@export
(defun grab-domain-name ()
  (when *debug*
    (print (list "**GRAB DOMAIN NAME**" packet::*decode-buffer*
                 packet::*decode-position*)))
  (format nil "~{~A~^.~}" (remove-if #'null 
  (loop
   with last = nil
   until last
   for p = (elt packet::*decode-buffer*
                (packet::bit-octet packet::*decode-position*))
   collect
   (cond
    ((= p 0)
     (incf packet::*decode-position* 8)
     (setf last t)
     '())
    ( (= 192 (logand #b11000000 p))
      (incf packet::*decode-position* 8)
      (let ((ptr  (elt (grab-octets 1) 0))
            (cpo packet::*decode-position*))
        (when *debug* (format t "jump ~a->~a~%"  ( bit-octet cpo) ptr)) 
        (setf packet::*decode-position* (+  (octet-bit ptr) 0))
        (let ((nm (grab-domain-name)))
          (setf packet::*decode-position* cpo)
          (setf last t)
          nm)
        ))
    (t (grab-label)))
   )
  )))

@export
(defun shove-domain-name (name)
  "Naive does not do compression"
  (dolist (l (split-sequence #\. name))
    (shove-label l))
  (shove-octet 0)
  )

@export
(defun grab-dns-header ()
  (make-dns-header
   :id (octet-vector-to-int-2 (grab-octets 2))
   :qr (grab-bitflag)
   :opcode (lookup-opcode  (grab-bits 4))
   :aa (grab-bitflag)
   :tc (grab-bitflag)
   :rd (grab-bitflag)
   :ra (grab-bitflag)
   :z  (grab-bitflag)
   :ad (grab-bitflag)
   :cd (grab-bitflag)
   :rcode (lookup-rcode (grab-bits 4))
   :qdcount/zcount (octet-vector-to-int-2 (grab-octets 2))
   :ancount/prcount   (octet-vector-to-int-2 (grab-octets 2))
   :nscount/upcount  (octet-vector-to-int-2(grab-octets 2))
   :arcount  (octet-vector-to-int-2 (grab-octets 2))
   ))

(defmacro bool->binary (v)
  `(if ,v 1 0))

@export
(defun shove-dns-header (hdr)
  (with-slots ( id qr opcode aa tc rd ra z ad cd rcode qdcount/zcount
                   ancount/prcount nscount/upcount arcount) hdr
    (shove-bits id 16)
    (shove-bits (bool->binary qr) 1)
    (shove-bits (bool->binary opcode) 4)
    (shove-bits (bool->binary aa) 1)
    (shove-bits (bool->binary tc) 1)
    (shove-bits (bool->binary rd) 1)
    (shove-bits (bool->binary ra) 1)
    (shove-bits (bool->binary z) 1)
    (shove-bits (bool->binary ad) 1)
    (shove-bits (bool->binary cd) 1)
    (shove-bits (bool->binary rcode) 4)
    (shove-bits qdcount/zcount 16)
    (shove-bits ancount/prcount 16)
    (shove-bits nscount/upcount 16)
    (shove-bits arcount 16)
    ))

@export
(defun grab-dns-questions (hdr)
  (labels ((grab-dns-question (n)
    (if (> n 0)
        (append (list (make-dns-question
                       :qname (grab-domain-name)
                       :qtype (lookup (octet-vector-to-int-2 (grab-octets 2))
                                      *dns-qtype* :errorp nil)
                       :qclass (lookup (octet-vector-to-int-2 (grab-octets 2))
                                       *dns-class* :errorp nil)
                       )) (grab-dns-question (- n 1)))
      nil)))
    (grab-dns-question (dns-header.qdcount/zcount hdr))))


@export
(defun shove-dns-question (hdr)
  "Takes a sequence of dns-question structs and packs into vector"
  (with-slots (qname qtype qclass)
      hdr
    (shove-domain-name qname)
    (shove-bits qtype 16)
    (shove-bits qclass 16)
    )
  )

(defun prnt (l) (format t "> ~a:~a~%" (packet::bit-octet packet::*decode-position*) l)l )
@export
(defun llookup (key alist &key (errorp t) (reversep nil))
  "Lookup the value of KEY in ALIST.
If the key is not present and ERRORP is true then an error is
signalled; if ERRORP is nil then the key itself is returned."
  (let ((entry (funcall (if reversep #'rassoc #'assoc) key alist)))
    (print (type-of  key ))
    (cond (entry  (funcall (if reversep #'car #'cdr) entry))
          (errorp (error "Key ~S is not present in ~A." key alist))
          (t      key))))

@export
(defun ipv6-octets-to-string (o)
  (format nil "~{~x~x~^:~}" (coerce o 'list))
  )
@export
(defun grab-dns-answers (hdr &key times)
  (when *debug* (print (list  "------------- (grab-dns-answers) ------------" times)))
  (labels (
    (grab-dns-answer (n) 
      (if (> n 0)
          (let* (
                (domain-name (grab-domain-name))
                (rec-type (lookup (octet-vector-to-int-2
                                          (grab-octets 2))
                                         *dns-qtype* :errorp nil) )
                (rec-class  (lookup (octet-vector-to-int-2 (grab-octets 2))
                                    *dns-class* :errorp nil))

                (ttl  (octet-vector-to-int-4 (grab-octets 4)))
                (rdlength (octet-vector-to-int-2
                                          (grab-octets 2)))
                (rdata (case rec-type
                                    ('a (make-ipv4-address :octets (grab-octets rdlength)))
                                    ('cname (grab-domain-name))
                                    ('aaaa (ipv6-octets-to-string (grab-octets rdlength)))
                                    ('mx (format nil "~d ~a" (octet-vector-to-int-2 (grab-octets 2)) (grab-domain-name)))
                                    ('ns (grab-domain-name))
                                    ('ptr (grab-domain-name))
                                    ; SOA: mname  cname serial refresh retry
                                    ;      expire min
                                    ('soa (format nil "~a ~a ~a ~a ~a ~a ~a"
                                                  (grab-domain-name) (grab-domain-name)
                                                  (octet-vector-to-int-4  (grab-octets 4))
                                                  (octet-vector-to-int-4  (grab-octets 4))
                                                  (octet-vector-to-int-4  (grab-octets 4))
                                                  (octet-vector-to-int-4  (grab-octets 4))
                                                  (octet-vector-to-int-4  (grab-octets 4))
                                                  ))
                                    ('txt (format nil "\"~a\"" (FLEXI-STREAMS:OCTETS-TO-STRING (grab-octets rdlength) :start 0 :end rdlength)))
                                    (otherwise (grab-octets rdlength))
                                    )
                       )
                )
            (append (list (make-dns-answer
                           :name domain-name
                           :type rec-type
                           :class rec-class
                           :ttl ttl
                           :rdlength  rdlength
                           :rdata rdata)
                          
                          )
                    (restart-case
                               (grab-dns-answer (- n 1))                
                               (skip-name nil))

                    )
            )
        nil
        ))
    )
(grab-dns-answer (if times times (dns-header.ancount/prcount hdr)))
    )
  

  #||
     (restart-case (grab-dns-answer (if times times (dns-header.ancount/prcount hdr)))
                  (skip-name () '( "ERROR"))
  )
  ||#
 )
@export
(defun shove-dns-answer (answer)
  (when *debug* (print "------------- (shove-dns-answers) ------------")) 
  (with-slots (name type class ttl rdlength rdata) answer
    (shove-domain-name name)
    (shove-bits type 16)
    (shove-bits class 16)
    (shove-bits ttl 32)
    (shove-bits rdlength 16)
    (shove-vector rdata)
    
    )

  (define-condition malformed-dns-entry-error (error)
    ((text :initarg :text :reader text))))

@export
(defun decode-dns-raw (p)
  (handler-bind ((malformed-dns-entry-error
                  #'(lambda (c) (print "WTF")
                      (invoke-restart 'skip-name)))
                 (simple-error
                  #'(lambda (c) (print "XXX")
                      (invoke-restart 'skip-name))))
    (let* ((dec (decode p))
         (l3 (elt dec 1))
         (l4 (elt dec 2)) )
      (if (or (= (udp-header.src-port l4 ) 53)
             (= (udp-header.dest-port l4 ) 53))
          (progn  
            (packet:with-buffer-input (elt dec 3)
               (let ((hdr (grab-dns-header )))
                   (format t "NSCOUNT ~A~%" (dns-header.nscount/upcount hdr))                         
                   (list l3 l4 (make-dns-packet :header hdr
                                                :questions (grab-dns-questions hdr)
                                                :answers (grab-dns-answers hdr)
                                                :authorities (grab-dns-answers hdr
                                                 :times
                                                 (dns-header.nscount/upcount hdr))
                                                :additionals (grab-dns-answers hdr
                                                 :times
                                                 (dns-header.arcount hdr))
                                                ))
                   )))
        nil
        ))))

@export
(defun decode-dns-payload (p)
  (packet:with-buffer-input p
    (let ((hdr (grab-dns-header )))
      (when *debug* (print hdr))
      (make-dns-packet :header hdr
                       :questions (grab-dns-questions hdr)
                       :answers (grab-dns-answers hdr)
                       :authorities (grab-dns-answers hdr
                          :times
                          (dns-header.nscount/upcount hdr))
                       :additionals (grab-dns-answers hdr
                                                 :times
                                                 (dns-header.arcount hdr))
                       )
      ) )
  )
@export
(defun decode-dns (p)
  (print "decode-dns")
  (let* ((dec (decode p))
         (l3 (elt dec 1))
         (l4 (elt dec 2)) )
    (if (or (= (udp-header.src-port l4 ) 53)
            (= (udp-header.dest-port l4 ) 53))
        (decode-dns-payload (elt dec 3))
      nil)))
