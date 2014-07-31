(in-package #:cl-packet.analyzer)
(annot:enable-annot-syntax)


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Utilities
(defun fmap (fns v) "Apply list of fns to value v"
  (mapcar (lambda (f) (funcall f v))fns))

(declaim (inline ensure-printable))
(defun ensure-printable (c)
  "Remove non printable characters. In the case of non printable characters
a #\period is subsituted
"
  (declare (fixnum c)(optimize (speed 3)(safety 0)(debug 0)))
  (let ((i (char-code c)))
    (if (and  (>= i 32) (< i 127)) c #\.)))

(declaim (inline nums-to-printable-string))
(defun nums-to-printable-string (nums)
  "Comverts list of fix num to their ascii equivalant"
  (declare (type list nums))
  (coerce (mapcar (lambda (c) (ensure-printable (code-char c))) nums) 'string))

(declaim (inline remd))
(defun remd (w l)
  (declare (fixnum l w) (optimize (speed 3) (safety 0) (debug 0)))
  (if (< l w)
      (let ((z (+ (* w 2) (- w 1))) (r (+ (* l 2) (- l 1))))
        (+ (- z r)0))
    0))

(declaim (ftype (function (buffer) (SIMPLE-BASE-STRING 2)) hexdump))
@export
(defun hexdump (seq &key (w 16) (s t))
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

