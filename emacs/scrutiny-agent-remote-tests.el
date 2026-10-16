;;; scrutiny-agent-remote-tests.el --- ERT tests for the one-call setup  -*- lexical-binding: t; -*-

;; This file is part of scrutiny-agent (GPLv3).

;;; Commentary:

;; What `scrutiny-agent-remote-setup' loads, checked in a fresh Emacs
;; because `features' cannot be unloaded in this one.
;;
;; The scenario behind these tests: a user's init runs
;; `(require 'scrutiny-agent-remote)' and the setup call, and later a
;; package manager (straight.el, package.el) puts newer copies of
;; project, xref, flymake or jsonrpc on `load-path'.  If the setup had
;; loaded the built-in copies, the first `(require 'eglot)' -- eglot
;; uses `require-with-check' on Emacs 30 -- fails with
;;
;;   Feature `project' is now provided by a different file .../project.elc
;;
;; and there is no LSP at all.  So the setup may not load any of them.
;;
;; Run:  emacs -Q --batch -L emacs -l emacs/scrutiny-agent-remote-tests.el \
;;         -f ert-run-tests-batch-and-exit

;;; Code:

(require 'ert)
(require 'cl-lib)
(require 'scrutiny-agent-remote)
(require 'scrutiny-agent-eglot)

(defconst scrutiny-agent-remote-tests--shadowable
  '(project xref eglot flymake jsonrpc external-completion)
  "Libraries that ship with Emacs, that eglot requires with
`require-with-check', and that users install newer copies of.")

(defconst scrutiny-agent-remote-tests--setup-form
  '(scrutiny-agent-remote-setup
    '(("devbox" :transport "tsh ssh devbox sh" :roots ("src")))))

(defun scrutiny-agent-remote-tests--emacs (forms)
  "Evaluate FORMS in order in a fresh batch Emacs.
The Emacs running the tests is used, with this tree on `load-path'.
Returns (STATUS . OUTPUT)."
  (let ((dir (file-name-directory
              (locate-library "scrutiny-agent-remote"))))
    (with-temp-buffer
      (let ((status
             (apply #'call-process
                    (expand-file-name invocation-name invocation-directory)
                    nil t nil
                    "-Q" "--batch" "-L" dir
                    (mapcan (lambda (form)
                              (list "--eval" (prin1-to-string form)))
                            forms))))
        (cons status (buffer-string))))))

(defun scrutiny-agent-remote-tests--shadow-project ()
  "A directory holding a copy of the installed project.el.
Stands in for straight's build/project (or an ELPA project-N.N dir):
the same library, from a different file."
  (let* ((dir (file-truename (make-temp-file "scra-shadow-project" t)))
         (src (find-library-name "project")))
    (with-temp-file (expand-file-name "project.el" dir)
      (auto-compression-mode 1)
      (insert-file-contents src))
    dir))

(ert-deftest scrutiny-agent-remote-setup-loads-nothing-shadowable ()
  "The one-call setup loads none of the libraries eglot checks.
Loading them would pin the built-in copies into `features' before
the user's package manager has a say."
  (let ((result (scrutiny-agent-remote-tests--emacs
                 `((require 'scrutiny-agent-remote)
                   ,scrutiny-agent-remote-tests--setup-form
                   (princ (format "loaded=%S\n"
                                  (cl-remove-if-not
                                   #'featurep
                                   ',scrutiny-agent-remote-tests--shadowable)))))))
    (should (equal 0 (car result)))
    (should (string-match-p "^loaded=nil$" (cdr result)))))

(ert-deftest scrutiny-agent-remote-setup-before-package-manager ()
  "Init order: our setup, then a second project.el appears, then eglot.
This is the straight.el failure verbatim: eglot must load, from the
new project, and find our contacts registered."
  (let* ((shadow (scrutiny-agent-remote-tests--shadow-project))
         (result
          (scrutiny-agent-remote-tests--emacs
           `((require 'scrutiny-agent-remote)
             ,scrutiny-agent-remote-tests--setup-form
             (add-to-list 'load-path ,shadow)
             (require 'eglot)
             (princ (format "project-from=%s\n"
                            (file-name-directory
                             (symbol-file 'project-current 'defun))))
             (princ (format "registered=%S\n"
                            (and (assoc '(python-mode python-ts-mode)
                                        eglot-server-programs)
                                 t)))))))
    (should-not (string-match-p "different file" (cdr result)))
    (should (equal 0 (car result)))
    (should (string-match-p (concat "^project-from="
                                    (regexp-quote (file-name-as-directory
                                                   shadow))
                                    "$")
                            (cdr result)))
    (should (string-match-p "^registered=t$" (cdr result)))))

(ert-deftest scrutiny-agent-remote-eglot-setup-is-idempotent ()
  "Running the setup twice leaves one entry per language, whose
fallback is eglot's original entry, not our own previous one."
  (require 'eglot)
  (let* ((eglot-server-programs (copy-sequence eglot-server-programs))
         (scrutiny-agent-eglot--entries nil)
         (before (length eglot-server-programs))
         (original (cdr (cl-find-if
                         (lambda (e)
                           (memq 'python-mode (flatten-tree (list (car e)))))
                         eglot-server-programs))))
    (should original)
    (scrutiny-agent-eglot-setup)
    (scrutiny-agent-eglot-setup)
    (should (= (length eglot-server-programs)
               (+ before (length scrutiny-agent-eglot-languages))))
    ;; In a non-remote buffer the contact hands back eglot's own entry.
    (let ((contact (cdr (assoc '(python-mode python-ts-mode)
                               eglot-server-programs)))
          (default-directory temporary-file-directory))
      (should (eq original
                  (with-temp-buffer
                    (setq major-mode 'python-mode)
                    (funcall contact)))))))

(provide 'scrutiny-agent-remote-tests)
;;; scrutiny-agent-remote-tests.el ends here
