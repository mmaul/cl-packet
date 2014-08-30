;(require :cl-packet.analyzer)
;(swank:start-server :port 1234)
;(cl-packet.analyzer:analyzer2 "eth1" "ip and udp port 53")
(in-package :cl-packet.analyzer)
(annot:enable-annot-syntax)

@export
(defun init ()
  (let ((args ccl::*command-line-argument-list*))
    (if (> (length args) 2)
        (let ((intf (elt args 1))
              (filter (elt args 2))
              )
	  (cl-packet.analyzer:analyzer2 intf filter)
          
          )
	(cl-packet.analyzer:analyzer2 "eth1" "ip and udp port 53")
	)
    
    )
  (when (not *interactive*) (ccl:quit))
  )
