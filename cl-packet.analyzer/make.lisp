;; make.lisp
;; Standalone application builder helper for Clozure Common Lisp
;; ccl64 -l ~/.lisp/make.lisp -- <package dir> <package-name> <init function>
;; <package dir> is spected to contain a system definition of
;;  <package name>.asd
(require 'asdf)
(if  (= 3 (length  CCL::*UNPROCESSED-COMMAND-LINE-ARGUMENTS*))
    (progn
      (defconstant app-pathname
           (make-pathname :directory
                          (elt CCL::*UNPROCESSED-COMMAND-LINE-ARGUMENTS* 0)))
      (defconstant app (elt CCL::*UNPROCESSED-COMMAND-LINE-ARGUMENTS* 1))
      (defconstant initfn (elt CCL::*UNPROCESSED-COMMAND-LINE-ARGUMENTS* 2))
      (setf asdf:*central-registry* '(*default-pathname-defaults*
                                      (directory-namestring app-pathname)))
      (asdf:operate 'asdf:load-op (intern app))
      (ccl:save-application (merge-pathnames app-pathname
                                               (make-pathname :name app))
       :toplevel-function
       (lambda ()
         (handler-case
          (progn
            (funcall (find-symbol (string-upcase initfn)
                                  (string-upcase app)))
            (ccl:quit 0))
          (error (err)
                 ;; put it back if you perfer :quit over :quit-quietly
                 (format *error-output* "~&~A~%" err)
                 (ccl:quit 1))))
       :error-handler :quit-quietly :mode #o644 :purify t
       :prepend-kernel t))
  (format t "make.lisp <pkgdir> <package name> <init function>~%")
  )
