(in-package :packet.util)
(annot:enable-annot-syntax)

@export
(defun packet-curry (function &rest args)
    (lambda (&rest more-args)
      (apply function (append args more-args))))

@export
(defmacro suck-it-in (pkg)
  "Exports all symbols from <pkg>"
  ` (let ((pack (find-package ,pkg)))
  (do-all-symbols (sym pack) (when (eql (symbol-package sym) pack) (export sym))))
    )
