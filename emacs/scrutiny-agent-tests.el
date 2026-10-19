;;; scrutiny-agent-tests.el --- ERT tests for scrutiny-agent.el  -*- lexical-binding: t; -*-

;; This file is part of scrutiny-agent (GPLv3).

;;; Commentary:

;; Pure-function unit tests for the wire client, plus one end-to-end
;; integration test (tagged, gated on SCRUTINY_AGENT_BIN) that runs
;; the REAL bootstrap over a local `sh' transport against a built
;; agent binary: base64 heredoc streaming, sha256 hash gate, exec,
;; meta.hello, chunked-response reassembly, and a raw-LSP tunnel
;; round trip.  CI runs it against the freshly built agent.
;;
;; Run:  emacs -Q --batch -L emacs -l scrutiny-agent-tests.el \
;;         -f ert-run-tests-batch-and-exit

;;; Code:

(require 'ert)
(require 'scrutiny-agent)
(require 'scrutiny-agent-eglot)

(defun scrutiny-agent-tests--image (os arch)
  "A fake OS / ARCH executable header, padded past 64 bytes.
Enough for `scrutiny-agent--binary-problem' to accept it as an agent
for that platform; it does not run."
  (let ((pad (make-list 100 0)))
    (pcase os
      ('linux (apply #'unibyte-string
                     #x7f ?E ?L ?F 2 1 1 0 0 0 0 0 0 0 0 0 2 0
                     (if (equal arch "aarch64") #xb7 #x3e) 0 pad))
      ('darwin (apply #'unibyte-string
                      #xcf #xfa #xed #xfe
                      (if (equal arch "aarch64") #x0c 7) 0 0 1 pad)))))

(defun scrutiny-agent-tests--write-image (path os arch)
  "Write a fake OS / ARCH executable to PATH and return PATH."
  (let ((coding-system-for-write 'binary))
    (with-temp-file path
      (set-buffer-multibyte nil)
      (insert (scrutiny-agent-tests--image os arch))))
  (set-file-modes path #o755)
  path)

(defun scrutiny-agent-tests--host-image ()
  "The fake image that passes the local check for a `sh' transport here."
  (scrutiny-agent-tests--image
   (if (eq system-type 'darwin) 'darwin 'linux)
   (if (string-match-p "aarch64\\|arm64" system-configuration)
       "aarch64" "x86_64")))

;; ---------------------------------------------------------------------
;; Framing
;; ---------------------------------------------------------------------

(ert-deftest scrutiny-agent-frame-roundtrip ()
  (let* ((payload '(:jsonrpc "2.0" :id 7 :method "meta.debug"
                    :params (:padBytes 3)))
         (parsed (scrutiny-agent--parse-frames
                  (scrutiny-agent--frame payload)))
         (msg (car (car parsed))))
    (should (equal (cdr parsed) ""))
    (should (equal (plist-get msg :id) 7))
    (should (equal (plist-get msg :method) "meta.debug"))
    (should (equal (plist-get (plist-get msg :params) :padBytes) 3))))

(ert-deftest scrutiny-agent-frame-partial-then-complete ()
  ;; A frame arriving split anywhere (mid-header, mid-body) parses only
  ;; once complete, and the remainder carries over byte-exactly.
  (let* ((frame (scrutiny-agent--frame '(:jsonrpc "2.0" :id 1 :result t)))
         (cut (- (length frame) 3))
         (first (scrutiny-agent--parse-frames (substring frame 0 cut))))
    (should (null (car first)))
    (should (equal (cdr first) (substring frame 0 cut)))
    (let ((second (scrutiny-agent--parse-frames
                   (concat (cdr first) (substring frame cut)))))
      (should (= 1 (length (car second))))
      (should (equal (cdr second) "")))))

(ert-deftest scrutiny-agent-frame-multiple-and-noise ()
  ;; Two frames in one buffer, preceded by a stray newline (the
  ;; bootstrap handoff race the parser explicitly tolerates).
  (let* ((f1 (scrutiny-agent--frame '(:jsonrpc "2.0" :id 1 :result 1)))
         (f2 (scrutiny-agent--frame '(:jsonrpc "2.0" :id 2 :result 2)))
         (parsed (scrutiny-agent--parse-frames (concat "\r\n\n" f1 f2))))
    (should (= 2 (length (car parsed))))
    (should (equal (mapcar (lambda (m) (plist-get m :id)) (car parsed))
                   '(1 2)))))

(ert-deftest scrutiny-agent-frame-utf8-body ()
  (let* ((payload `(:jsonrpc "2.0" :id 3 :result (:content "éñ😀")))
         (msg (car (car (scrutiny-agent--parse-frames
                         (scrutiny-agent--frame payload))))))
    (should (equal (plist-get (plist-get msg :result) :content) "éñ😀"))))

;; ---------------------------------------------------------------------
;; Chunk splitting and rpc.chunk reassembly
;; ---------------------------------------------------------------------

(ert-deftest scrutiny-agent-split-bytes ()
  (should (equal (scrutiny-agent--split-bytes "abcdef" 2) '("ab" "cd" "ef")))
  (should (equal (scrutiny-agent--split-bytes "abcde" 2) '("ab" "cd" "e")))
  (should (equal (scrutiny-agent--split-bytes "" 2) nil))
  (should (equal (scrutiny-agent--split-bytes "ab" 10) '("ab"))))

(ert-deftest scrutiny-agent-assemble-chunks ()
  ;; Out-of-order (SEQ . DATA) parts reassemble into the envelope, as
  ;; the agent's streamed-response path produces them.
  (let* ((envelope "{\"jsonrpc\":\"2.0\",\"id\":42,\"result\":{\"pad\":\"xyzzy\"}}")
         (b64 (base64-encode-string envelope t))
         (third (/ (length b64) 3))
         (parts (list (cons 1 (substring b64 third (* 2 third)))
                      (cons 0 (substring b64 0 third))
                      (cons 2 (substring b64 (* 2 third)))))
         (msg (scrutiny-agent--assemble-chunks parts)))
    (should (equal (plist-get msg :id) 42))
    (should (equal (plist-get (plist-get msg :result) :pad) "xyzzy"))))

;; ---------------------------------------------------------------------
;; Bootstrap building blocks
;; ---------------------------------------------------------------------

(ert-deftest scrutiny-agent-arch-asset ()
  (should (equal (scrutiny-agent--arch-asset "Linux" "x86_64") "x86_64"))
  (should (equal (scrutiny-agent--arch-asset "Linux" "aarch64") "aarch64"))
  (should (equal (scrutiny-agent--arch-asset "Linux" "arm64") "aarch64"))
  (should (null (scrutiny-agent--arch-asset "Darwin" "arm64")))
  (should (null (scrutiny-agent--arch-asset "Linux" "riscv64"))))

(ert-deftest scrutiny-agent-bootstrap-scripts ()
  (let ((st (scrutiny-agent--bootstrap-script "$HOME/.x" "agent-1-x86_64"
                                              "cafe")))
    (should (string-search "__SCRA_ST__" st))
    (should (string-search "agent-1-x86_64" st))
    (should (string-search "cafe" st))
    (should (string-search "shasum -a 256" st)))  ; sha256sum fallback
  (let ((inst (scrutiny-agent--install-script "$HOME/.x" "agent-1-x86_64")))
    (should (string-search "<<'__SCRB64__'" inst))
    (should (string-search "base64 -d" inst)))
  (let ((ep (scrutiny-agent--install-epilogue "$HOME/.x" "agent-1-x86_64"
                                              "cafe")))
    (should (string-search "__SCRA_INST__" ep))
    (should (string-search "chmod +x" ep))
    (should (string-search "mv" ep))))

(ert-deftest scrutiny-agent-file-sha256 ()
  (let ((f (make-temp-file "scra-hash")))
    (unwind-protect
        (progn
          (with-temp-file f (set-buffer-multibyte nil) (insert "abc"))
          (should (equal (scrutiny-agent--file-sha256 f)
                         "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")))
      (delete-file f))))

;; ---------------------------------------------------------------------
;; Eglot glue
;; ---------------------------------------------------------------------

(ert-deftest scrutiny-agent-eglot-language-lookup ()
  (should (equal (scrutiny-agent-eglot--language 'python-mode) 2))
  (should (equal (scrutiny-agent-eglot--language 'rust-ts-mode) 1))
  (should (null (scrutiny-agent-eglot--language 'fundamental-mode))))

(ert-deftest scrutiny-agent-eglot-host-lookup ()
  (let ((scrutiny-agent-hosts '(("devbox" :transport "ssh devbox")))
        (scrutiny-agent-eglot-host-alist '(("devbox.corp" . "devbox"))))
    (should (equal (scrutiny-agent-eglot--host "/ssh:devbox:/src/") "devbox"))
    (should (equal (scrutiny-agent-eglot--host "/ssh:devbox.corp:/src/")
                   "devbox"))
    (should (null (scrutiny-agent-eglot--host "/ssh:other:/src/")))
    (should (null (scrutiny-agent-eglot--host "/home/me/src/")))))

(ert-deftest scrutiny-agent-eglot-contact-fallback ()
  ;; In a non-remote directory the contact function must return the
  ;; fallback untouched, so local editing is byte-identical to stock
  ;; eglot behavior.
  (let* ((default-directory "/tmp/")
         (contact (scrutiny-agent-eglot-contact '("pylsp"))))
    (should (equal (funcall contact) '("pylsp")))))

;; ---------------------------------------------------------------------
;; End-to-end integration (gated; CI sets SCRUTINY_AGENT_BIN)
;; ---------------------------------------------------------------------

(defun scrutiny-agent-tests--wait (pred timeout)
  (let ((deadline (+ (float-time) timeout)))
    (while (and (not (funcall pred)) (< (float-time) deadline))
      (accept-process-output nil 0.05))
    (funcall pred)))

(ert-deftest scrutiny-agent-integration ()
  :tags '(integration)
  (skip-unless (getenv "SCRUTINY_AGENT_BIN"))
  (let* ((bin (getenv "SCRUTINY_AGENT_BIN"))
         (install (make-temp-file "scra-install" t))
         (tmproot (file-name-as-directory temporary-file-directory))
         (scrutiny-agent-hosts
          `(("itest" :transport "sh"
             :install-dir ,install
             :local-binary ,bin
             :agent-args ("--allow-root" ,tmproot))))
         (conn (scrutiny-agent-connect "itest")))
    (unwind-protect
        (progn
          ;; Bootstrap streamed + hash-gated + exec'd; handshake done.
          (should (member "lsp.tunnelOpen"
                          (scrutiny-agent--conn-capabilities conn)))
          ;; Plain request.
          (let ((r (scrutiny-agent-request conn "meta.debug"
                                           '(:padBytes 16))))
            (should (equal (plist-get r :pad) (make-string 16 ?x))))
          ;; Over-cap response: exercises rpc.chunk reassembly here.
          (let ((r (scrutiny-agent-request conn "meta.debug"
                                           '(:padBytes 300000)
                                           60)))
            (should (= (length (plist-get r :pad)) 300000)))
          ;; Raw-LSP tunnel round trip (python -> pylsp when present;
          ;; a clean LSP_FAILED is also conformant).
          (let* ((ws (make-temp-file "scra-ws" t))
                 (stream "")
                 (closed nil)
                 (tunnel
                  (condition-case err
                      (scrutiny-agent-tunnel-open
                       conn ws 2
                       (lambda (b)
                                   (setq stream (concat stream b)))
                       (lambda (r) (setq closed r)))
                    (scrutiny-agent-rpc-error
                     (should (= (nth 1 err) 1004))
                     nil))))
            (when tunnel
              (let* ((body (json-serialize
                            `(:jsonrpc "2.0" :id 1 :method "initialize"
                              :params (:processId :null
                                       :rootUri ,(concat "file://" ws)
                                       :capabilities ,(make-hash-table)))))
                     (frame (concat (format "Content-Length: %d\r\n\r\n"
                                            (length body))
                                    body))
                     (cut (/ (length frame) 2)))
                ;; Split mid-frame: chunk boundaries are not message
                ;; boundaries, order must hold.
                (scrutiny-agent-tunnel-send tunnel (substring frame 0 cut))
                (scrutiny-agent-tunnel-send tunnel (substring frame cut))
                (should (scrutiny-agent-tests--wait
                         (lambda ()
                           (let ((msgs (car (ignore-errors
                                              (scrutiny-agent--parse-frames
                                               stream)))))
                             (cl-find-if
                              (lambda (m) (and (equal (plist-get m :id) 1)
                                               (plist-get m :result)))
                              msgs)))
                         45))
                (scrutiny-agent-tunnel-close tunnel)
                (should (scrutiny-agent-tests--wait
                         (lambda () closed) 15))))))
      (scrutiny-agent-disconnect "itest")
      (delete-directory install t))))

(provide 'scrutiny-agent-tests)
;;; scrutiny-agent-tests.el ends here

;; ---------------------------------------------------------------------
;; Multi-architecture binary selection
;; ---------------------------------------------------------------------

(ert-deftest scrutiny-agent-local-binary-string-form ()
  ;; A plain string means "this binary, this host" -- unchanged behavior.
  (let ((f (make-temp-file "scra-bin")))
    (scrutiny-agent-tests--write-image f 'linux "x86_64")
    (unwind-protect
        (should (equal (scrutiny-agent--local-binary (list :local-binary f)
                                                     "x86_64")
                       (expand-file-name f)))
      (delete-file f))))

(ert-deftest scrutiny-agent-local-binary-selects-by-arch ()
  ;; One Emacs driving both an x86 server and an ARM one.
  (let ((amd (make-temp-file "scra-amd"))
        (arm (make-temp-file "scra-arm")))
    (scrutiny-agent-tests--write-image amd 'linux "x86_64")
    (scrutiny-agent-tests--write-image arm 'linux "aarch64")
    (unwind-protect
        (let ((plist (list :local-binary (list (cons "x86_64" amd)
                                               (cons "aarch64" arm)))))
          (should (equal (scrutiny-agent--local-binary plist "x86_64")
                         (expand-file-name amd)))
          (should (equal (scrutiny-agent--local-binary plist "aarch64")
                         (expand-file-name arm))))
      (delete-file amd)
      (delete-file arm))))

(ert-deftest scrutiny-agent-local-binary-prefers-the-cache ()
  ;; scripts/build-agents.sh installs both arches here; a local hit must
  ;; win over the network so the usual connect is offline.
  (let* ((dir (make-temp-file "scra-cache" t))
         (scrutiny-agent-cache-directory dir)
         (scrutiny-agent-binary-version "9.9.9")
         (name "scrutiny-agent-9.9.9-aarch64")
         (path (expand-file-name name dir)))
    (unwind-protect
        (progn
          (scrutiny-agent-tests--write-image path 'linux "aarch64")
          (should (equal (scrutiny-agent--local-binary nil "aarch64") path)))
      (delete-directory dir t))))

(ert-deftest scrutiny-agent-local-binary-reports-what-is-missing ()
  ;; The first thing that fails on a new machine; the message has to say
  ;; how to fix it rather than just failing.
  (let* ((dir (make-temp-file "scra-empty" t))
         (scrutiny-agent-cache-directory dir)
         (scrutiny-agent-binary-version "9.9.9")
         (scrutiny-agent-download-releases nil))
    (unwind-protect
        (let ((err (should-error (scrutiny-agent--local-binary nil "aarch64"))))
          (should (string-match-p "build-agents.sh"
                                  (error-message-string err)))
          (should (string-match-p "arm64" (error-message-string err))))
      (delete-directory dir t))))

(ert-deftest scrutiny-agent-installed-binaries-listing ()
  (let* ((dir (make-temp-file "scra-cache" t))
         (scrutiny-agent-cache-directory dir)
         (scrutiny-agent-binary-version "1.2.3"))
    (unwind-protect
        (progn
          (dolist (name '("scrutiny-agent-1.2.3-x86_64"
                          "scrutiny-agent-1.2.3-aarch64"
                          "scrutiny-agent-1.2.3-x86_64.sha256"
                          "scrutiny-agent-0.0.1-x86_64"))
            (scrutiny-agent-tests--write-image
             (expand-file-name name dir) 'linux
             (if (string-suffix-p "aarch64" name) "aarch64" "x86_64")))
          (let ((found (scrutiny-agent-installed-binaries)))
            (should (equal (sort (mapcar #'car found) #'string<)
                           '("aarch64" "x86_64")))))
      (delete-directory dir t))))

(ert-deftest scrutiny-agent-explicit-binary-must-exist ()
  ;; Both misses say where the file was expected: a path that is not
  ;; on this machine (the natural mistake is naming a binary built on
  ;; the host), and an alist with no entry for the host's arch.
  (let ((err (should-error (scrutiny-agent--local-binary
                            (list :local-binary "/no/such/agent") "x86_64"))))
    (should (string-search "/no/such/agent" (error-message-string err)))
    (should (string-search "on this machine" (error-message-string err))))
  (let ((err (should-error (scrutiny-agent--local-binary
                            (list :local-binary '(("aarch64" . "/x")))
                            "x86_64"))))
    (should (string-search "no entry for x86_64" (error-message-string err)))
    (should (string-search "aarch64" (error-message-string err)))))

;; ---------------------------------------------------------------------
;; What may be streamed: the local check on the binary
;; ---------------------------------------------------------------------

(ert-deftest scrutiny-agent-binary-problem-reads-the-image-header ()
  (let ((file (make-temp-file "scra-img")))
    (unwind-protect
        (progn
          (scrutiny-agent-tests--write-image file 'linux "x86_64")
          (should-not (scrutiny-agent--binary-problem file))
          (should-not (scrutiny-agent--binary-problem file "Linux" "x86_64"))
          (should-not (scrutiny-agent--binary-problem file "Linux" "amd64"))
          (should (string-match-p "x86_64 binary, not aarch64"
                                  (scrutiny-agent--binary-problem
                                   file "Linux" "aarch64")))
          (should (string-match-p "Linux (ELF) binary; the host is Darwin"
                                  (scrutiny-agent--binary-problem
                                   file "Darwin" "x86_64")))
          (scrutiny-agent-tests--write-image file 'linux "aarch64")
          (should-not (scrutiny-agent--binary-problem file "Linux" "arm64"))
          (scrutiny-agent-tests--write-image file 'darwin "aarch64")
          (should-not (scrutiny-agent--binary-problem file "Darwin" "arm64"))
          (should (string-match-p "aarch64 binary, not x86_64"
                                  (scrutiny-agent--binary-problem
                                   file "Darwin" "x86_64")))
          (should (string-match-p "Mach-O.*host is Linux"
                                  (scrutiny-agent--binary-problem
                                   file "Linux" "aarch64"))))
      (delete-file file))))

(ert-deftest scrutiny-agent-binary-problem-rejects-what-is-not-an-image ()
  ;; The case that was seen in the field: GitHub's 404 page, saved
  ;; under the binary's name by `url-copy-file', streamed to the host
  ;; and installed over a working agent.  It is named for what it is.
  (let ((file (make-temp-file "scra-404")))
    (unwind-protect
        (progn
          (with-temp-file file (insert "Not Found"))
          (let ((problem (scrutiny-agent--binary-problem file "Linux" "x86_64")))
            (should problem)
            (should (string-search file problem))
            (should (string-search "9 bytes" problem))
            (should (string-search "Not Found" problem))
            (should (string-search "release asset that does not exist" problem)))
          (with-temp-file file (insert ""))
          (should (string-search "is empty"
                                 (scrutiny-agent--binary-problem file)))
          (with-temp-file file
            (insert "#!/bin/sh\necho 'some other tool 1.0'\n")
            (insert (make-string 100 ?#)))
          (should (string-search "not an ELF or Mach-O"
                                 (scrutiny-agent--binary-problem file))))
      (delete-file file))))

(ert-deftest scrutiny-agent-explicit-binary-must-be-an-image ()
  (let ((file (make-temp-file "scra-explicit-text")))
    (unwind-protect
        (progn
          (with-temp-file file (insert "Not Found"))
          (let ((err (should-error (scrutiny-agent--local-binary
                                    (list :local-binary file) "x86_64"))))
            (should (string-search file (error-message-string err)))
            (should (string-search "Not Found" (error-message-string err))))
          ;; The right image for the wrong host is refused before any
          ;; transfer, naming both sides.
          (scrutiny-agent-tests--write-image file 'linux "aarch64")
          (let ((err (should-error (scrutiny-agent--local-binary
                                    (list :local-binary file) "x86_64" "Linux"))))
            (should (string-search "aarch64 binary, not x86_64"
                                   (error-message-string err))))
          (should (equal (scrutiny-agent--local-binary
                          (list :local-binary file) "aarch64" "Linux")
                         (expand-file-name file))))
      (delete-file file))))

(ert-deftest scrutiny-agent-cached-404-page-is-discarded ()
  ;; An older client cached the 404 body.  It is deleted rather than
  ;; served, and with downloads off the error says what was thrown away.
  (let* ((dir (make-temp-file "scra-cache" t))
         (scrutiny-agent-bundled-binary-directory nil)
         (scrutiny-agent-cache-directory dir)
         (scrutiny-agent-binary-version "9.9.9")
         (scrutiny-agent-download-releases nil)
         (cached (expand-file-name "scrutiny-agent-9.9.9-x86_64" dir)))
    (unwind-protect
        (progn
          (with-temp-file cached (insert "Not Found"))
          (with-temp-file (concat cached ".sha256") (insert "junk\n"))
          (let ((err (should-error (scrutiny-agent--local-binary nil "x86_64"))))
            (should (string-search "Not Found" (error-message-string err)))
            (should (string-search "build-agents.sh" (error-message-string err))))
          (should-not (file-exists-p cached))
          (should-not (file-exists-p (concat cached ".sha256")))
          (should-not (scrutiny-agent-installed-binaries)))
      (delete-directory dir t))))

(defun scrutiny-agent-tests--with-fake-http (responses body)
  "Run BODY with `url-retrieve-synchronously' answering from RESPONSES.
RESPONSES is an alist of URL to (STATUS . BODY-STRING); an unlisted
URL is a 404 with GitHub's body, which is what the real thing does."
  (cl-letf (((symbol-function 'url-retrieve-synchronously)
             (lambda (url &rest _)
               (let* ((r (or (cdr (assoc url responses)) '(404 . "Not Found")))
                      (buf (generate-new-buffer " *fake-http*")))
                 (with-current-buffer buf
                   (set-buffer-multibyte nil)
                   (setq-local url-http-response-status (car r))
                   (insert (format "HTTP/1.1 %d X\r\nContent-Type: x\r\n\r\n"
                                   (car r)))
                   (insert (cdr r)))
                 buf))))
    (funcall body)))

(ert-deftest scrutiny-agent-download-refuses-a-404 ()
  ;; The release does not exist.  Nothing is written, and the error
  ;; carries the status and the URL, not a nine-byte "binary".
  (let* ((dir (make-temp-file "scra-cache" t))
         (scrutiny-agent-bundled-binary-directory nil)
         (scrutiny-agent-cache-directory dir)
         (scrutiny-agent-binary-version "9.9.9")
         (scrutiny-agent-download-releases t))
    (unwind-protect
        (scrutiny-agent-tests--with-fake-http nil
          (lambda ()
            (let ((err (should-error (scrutiny-agent--local-binary nil "x86_64"))))
              (should (string-search "HTTP 404" (error-message-string err)))
              (should (string-search "v9.9.9/scrutiny-agent-9.9.9-x86_64"
                                     (error-message-string err))))
            (should-not (directory-files dir nil "scrutiny"))))
      (delete-directory dir t))))

(ert-deftest scrutiny-agent-download-is-checked-against-the-sidecar ()
  (let* ((dir (make-temp-file "scra-cache" t))
         (scrutiny-agent-bundled-binary-directory nil)
         (scrutiny-agent-cache-directory dir)
         (scrutiny-agent-binary-version "9.9.9")
         (scrutiny-agent-download-releases t)
         (url (format scrutiny-agent-release-url-format "9.9.9" "9.9.9" "aarch64"))
         (image (scrutiny-agent-tests--image 'linux "aarch64"))
         (sha (secure-hash 'sha256 image))
         (cached (expand-file-name "scrutiny-agent-9.9.9-aarch64" dir)))
    (unwind-protect
        (progn
          ;; A body that does not hash to the sidecar is not cached.
          (scrutiny-agent-tests--with-fake-http
           `((,(concat url ".sha256") . (200 . ,(concat sha "  x\n")))
             (,url . (200 . ,(concat image "tampered"))))
           (lambda ()
             (let ((err (should-error (scrutiny-agent--local-binary nil "aarch64"))))
               (should (string-search "does not match" (error-message-string err))))
             (should-not (file-exists-p cached))))
          ;; The genuine one is, executable, with its sidecar beside it.
          (scrutiny-agent-tests--with-fake-http
           `((,(concat url ".sha256") . (200 . ,(concat sha "\n")))
             (,url . (200 . ,image)))
           (lambda ()
             (should (equal (scrutiny-agent--local-binary nil "aarch64" "Linux")
                            cached))))
          (should (file-executable-p cached))
          (should (equal (scrutiny-agent--file-sha256 cached) sha))
          (should (equal (with-temp-buffer
                           (insert-file-contents (concat cached ".sha256"))
                           (string-trim (buffer-string)))
                         sha))
          ;; And the next lookup is served from the cache, no network.
          (cl-letf (((symbol-function 'url-retrieve-synchronously)
                     (lambda (&rest _) (error "network used"))))
            (should (equal (scrutiny-agent--local-binary nil "aarch64") cached))))
      (delete-directory dir t))))

;; ---------------------------------------------------------------------
;; Config shipped to the host
;; ---------------------------------------------------------------------

(ert-deftest scrutiny-agent-config-scripts ()
  (let ((check (scrutiny-agent--config-script "$HOME/.x" "a.conf" "cafe")))
    (should (string-search "__SCRA_CFG__" check))
    (should (string-search "a.conf" check))
    (should (string-search "cafe" check))
    (should (string-search "shasum -a 256" check)))
  (should (string-search "<<'__SCRCFG64__'"
                         (scrutiny-agent--config-install-script "$D" "a.conf")))
  (let ((epilogue (scrutiny-agent--config-epilogue "$D" "a.conf" "cafe")))
    ;; The epilogue is also the synchronization point: without it the
    ;; exec line races the shell still consuming the heredoc.
    (should (string-search "__SCRA_CFGDONE__" epilogue))
    (should (string-search "cafe" epilogue))))

(ert-deftest scrutiny-agent-config-hash-is-of-the-content ()
  (should (equal (scrutiny-agent--string-sha256 "abc")
                 "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")))

(defmacro scrutiny-agent-tests--with-config (config varlist &rest body)
  "Bootstrap a host with CONFIG and bind (CONN INSTALL ROOT) for BODY."
  (declare (indent 2) (debug t))
  (let ((conn (nth 0 varlist)) (install (nth 1 varlist)) (root (nth 2 varlist)))
    `(let* ((bin (getenv "SCRUTINY_AGENT_BIN"))
            (,install (make-temp-file "scra-cfg-install" t))
            (,root (file-truename (make-temp-file "scra-cfg-root" t)))
            (scrutiny-agent-default-config (funcall ,config ,root))
            (scrutiny-agent-hosts
             `(("cfgtest" :transport "sh"
                :install-dir ,,install
                :local-binary ,bin)))
            (,conn nil))
       (unwind-protect
           (progn (setq ,conn (scrutiny-agent-connect "cfgtest")) ,@body)
         (scrutiny-agent-disconnect "cfgtest")
         (delete-directory ,install t)
         (delete-directory ,root t)))))

(ert-deftest scrutiny-agent-config-is-installed-and-applied ()
  :tags '(integration)
  (skip-unless (getenv "SCRUTINY_AGENT_BIN"))
  (scrutiny-agent-tests--with-config
      (lambda (root)
        (format "allow-root = %s\nallow-write\ngit-exec-preset = magit\n" root))
      (conn install root)
    ;; The exec line carries no policy at all here: everything the agent
    ;; is running with came from the file streamed to the host.
    (let ((fsa (plist-get (scrutiny-agent-request conn "meta.capabilities" nil)
                          :fileSystemAccess)))
      (should (equal (append (plist-get fsa :allowedRoots) nil) (list root)))
      (should (eq (plist-get fsa :writable) t)))
    (should (member "git.exec" (scrutiny-agent--conn-capabilities conn)))
    (should (file-exists-p (expand-file-name "scrutiny-agent.conf" install)))))

;; The regression this guards: every other config test names an absolute
;; temp directory as the install dir, so none of them noticed that the
;; DEFAULT one -- a shell expression -- reached the agent unexpanded.
(ert-deftest scrutiny-agent-config-is-applied-from-the-default-install-dir ()
  :tags '(integration)
  (skip-unless (getenv "SCRUTINY_AGENT_BIN"))
  (let* ((home (file-truename (make-temp-file "scra-home" t)))
         ;; An abbreviated default-directory ("~/...") would be
         ;; re-expanded against the temporary HOME below and vanish.
         (default-directory (file-truename default-directory))
         (process-environment (cons (concat "HOME=" home) process-environment))
         (scrutiny-agent-default-config
          "allow-root = src\nallow-write\ngit-exec-preset = magit\n")
         (scrutiny-agent-hosts
          `(("homecfg" :transport "sh"
             :local-binary ,(getenv "SCRUTINY_AGENT_BIN"))))
         (conn nil))
    (make-directory (expand-file-name "src" home))
    (unwind-protect
        (progn
          (setq conn (scrutiny-agent-connect "homecfg"))
          (let ((fsa (plist-get
                      (scrutiny-agent-request conn "meta.capabilities" nil)
                      :fileSystemAccess)))
            (should (equal (append (plist-get fsa :allowedRoots) nil)
                           (list (expand-file-name "src" home))))
            (should (eq (plist-get fsa :writable) t)))
          (should (member "git.exec" (scrutiny-agent--conn-capabilities conn)))
          (should (member "fs.writeFile"
                          (scrutiny-agent--conn-capabilities conn))))
      (scrutiny-agent-disconnect "homecfg")
      (delete-directory home t))))

(ert-deftest scrutiny-agent-config-is-not-resent-when-unchanged ()
  :tags '(integration)
  (skip-unless (getenv "SCRUTINY_AGENT_BIN"))
  ;; Hash-gated exactly like the binary: reconnecting must cost an echo,
  ;; not a transfer.
  (scrutiny-agent-tests--with-config
      (lambda (root) (format "allow-root = %s\n" root))
      (conn install root)
    (ignore conn install root)
    (scrutiny-agent-disconnect "cfgtest")
    (let ((sent nil))
      (cl-letf* ((original (symbol-function 'process-send-string))
                 ((symbol-function 'process-send-string)
                  (lambda (proc text)
                    (when (string-search "__SCRCFG64__" text) (setq sent t))
                    (funcall original proc text))))
        (scrutiny-agent-connect "cfgtest"))
      (should-not sent)
      (should (member "fs.stat" (scrutiny-agent--conn-capabilities
                                 (scrutiny-agent-connection "cfgtest")))))))

(ert-deftest scrutiny-agent-host-config-overrides-the-default ()
  :tags '(integration)
  (skip-unless (getenv "SCRUTINY_AGENT_BIN"))
  (let* ((bin (getenv "SCRUTINY_AGENT_BIN"))
         (install (make-temp-file "scra-ovr-install" t))
         (root (file-truename (make-temp-file "scra-ovr-root" t)))
         (scrutiny-agent-default-config "allow-root = /nowhere\n")
         (scrutiny-agent-hosts
          `(("ovr" :transport "sh" :install-dir ,install :local-binary ,bin
             :config ,(format "allow-root = %s\n" root)))))
    (unwind-protect
        (let* ((conn (scrutiny-agent-connect "ovr"))
               (fsa (plist-get (scrutiny-agent-request
                                conn "meta.capabilities" nil)
                               :fileSystemAccess)))
          (should (equal (append (plist-get fsa :allowedRoots) nil)
                         (list root))))
      (scrutiny-agent-disconnect "ovr")
      (delete-directory install t)
      (delete-directory root t))))

(ert-deftest scrutiny-agent-config-can-be-suppressed ()
  :tags '(integration)
  (skip-unless (getenv "SCRUTINY_AGENT_BIN"))
  ;; `:config nil' means "send none" -- the exec line is then the only
  ;; policy, which is how this worked before configs existed.
  (let* ((bin (getenv "SCRUTINY_AGENT_BIN"))
         (install (make-temp-file "scra-none-install" t))
         (root (file-truename (make-temp-file "scra-none-root" t)))
         (scrutiny-agent-default-config "allow-root = /nowhere\n")
         (scrutiny-agent-hosts
          `(("none" :transport "sh" :install-dir ,install :local-binary ,bin
             :config nil
             :agent-args ("--allow-root" ,root)))))
    (unwind-protect
        (let* ((conn (scrutiny-agent-connect "none"))
               (fsa (plist-get (scrutiny-agent-request
                                conn "meta.capabilities" nil)
                               :fileSystemAccess)))
          (should (equal (append (plist-get fsa :allowedRoots) nil)
                         (list root)))
          (should-not (file-exists-p
                       (expand-file-name "scrutiny-agent.conf" install))))
      (scrutiny-agent-disconnect "none")
      (delete-directory install t)
      (delete-directory root t))))

(ert-deftest scrutiny-agent-exec-args-add-to-the-config ()
  :tags '(integration)
  (skip-unless (getenv "SCRUTINY_AGENT_BIN"))
  (let* ((bin (getenv "SCRUTINY_AGENT_BIN"))
         (install (make-temp-file "scra-both-install" t))
         (root (file-truename (make-temp-file "scra-both-root" t)))
         (extra (file-truename (make-temp-file "scra-both-extra" t)))
         (scrutiny-agent-default-config (format "allow-root = %s\n" root))
         (scrutiny-agent-hosts
          `(("both" :transport "sh" :install-dir ,install :local-binary ,bin
             :agent-args ("--allow-root" ,extra)))))
    (unwind-protect
        (let* ((conn (scrutiny-agent-connect "both"))
               (fsa (plist-get (scrutiny-agent-request
                                conn "meta.capabilities" nil)
                               :fileSystemAccess)))
          (should (equal (sort (append (plist-get fsa :allowedRoots) nil)
                               #'string<)
                         (sort (list root extra) #'string<))))
      (scrutiny-agent-disconnect "both")
      (delete-directory install t)
      (delete-directory root t)
      (delete-directory extra t))))

(provide 'scrutiny-agent-tests)
;;; scrutiny-agent-tests.el ends here

;; ---------------------------------------------------------------------
;; Platform probe and binary verification
;; ---------------------------------------------------------------------

(ert-deftest scrutiny-agent-probe-uses-only-posix-uname ()
  ;; -s and -m are POSIX; -o, -i and -p are not, and are absent or
  ;; different on the systems most likely to be surprising.
  (let ((script (scrutiny-agent--probe-script)))
    (should (string-search "uname -s" script))
    (should (string-search "uname -m" script))
    (should-not (string-match-p "uname -[oip]" script))
    (should (string-search "__SCRA_PROBE__" script))))

(ert-deftest scrutiny-agent-machine-normalization ()
  ;; Kernels and userlands disagree about the same machine.
  (should (equal (scrutiny-agent--normalize-machine "x86_64") "x86_64"))
  (should (equal (scrutiny-agent--normalize-machine "amd64") "x86_64"))
  (should (equal (scrutiny-agent--normalize-machine "aarch64") "aarch64"))
  (should (equal (scrutiny-agent--normalize-machine "arm64") "aarch64"))
  (should (equal (scrutiny-agent--normalize-machine "ARM64") "aarch64"))
  (should-not (scrutiny-agent--normalize-machine "armv7l"))
  (should-not (scrutiny-agent--normalize-machine nil)))

(ert-deftest scrutiny-agent-arch-asset-selection ()
  (should (equal (scrutiny-agent--arch-asset "Linux" "x86_64") "x86_64"))
  (should (equal (scrutiny-agent--arch-asset "Linux" "amd64") "x86_64"))
  (should (equal (scrutiny-agent--arch-asset "Linux" "arm64") "aarch64"))
  ;; Nothing is published for these; the caller must say so rather than
  ;; send an x86 binary and let it fail confusingly on the far end.
  (should-not (scrutiny-agent--arch-asset "Linux" "armv7l"))
  (should-not (scrutiny-agent--arch-asset "Linux" "s390x"))
  (should-not (scrutiny-agent--arch-asset "Darwin" "arm64"))
  (should-not (scrutiny-agent--arch-asset "FreeBSD" "x86_64")))

(ert-deftest scrutiny-agent-verify-script-shape ()
  (let ((script (scrutiny-agent--verify-script "$HOME/.x/agent-1")))
    (should (string-search "\"$HOME/.x/agent-1\"" script))
    ;; --version is the probe: it execs, exits 0, and names itself.
    (should (string-search "--version" script))
    (should (string-search "__SCRA_VERIFY__" script))
    ;; The exit status must survive, and multi-line loader errors must
    ;; be flattened or they break the single-line marker protocol.
    (should (string-search "R=$?" script))
    (should (string-search "tr " script))))

(ert-deftest scrutiny-agent-verify-parsing ()
  ;; Good.
  (should-not (scrutiny-agent--parse-verify "0 1.2.3 proto 1 " "1.2.3"))
  ;; Wrong architecture / not executable: the shell says which.
  (let ((reason (scrutiny-agent--parse-verify
                 "126 sh: /x: Exec format error" "1.2.3")))
    (should (string-match-p "architecture" reason))
    (should (string-match-p "Exec format error" reason)))
  ;; Dynamic linking, or a missing file.
  (let ((reason (scrutiny-agent--parse-verify
                 "127 /x: error while loading shared libraries: libc.so.6"
                 "1.2.3")))
    (should (string-match-p "shared library" reason))
    (should (string-match-p "libc.so.6" reason)))
  ;; Ran, but is not our program.
  (let ((reason (scrutiny-agent--parse-verify "0 some other tool 1.0" "1.2.3")))
    (should (string-match-p "expected version 1.2.3" reason))
    (should (string-match-p "some other tool" reason)))
  ;; Ran, but is the wrong version of our program.
  (should (scrutiny-agent--parse-verify "0 9.9.9 proto 1" "1.2.3"))
  ;; Crashed.
  (should (string-match-p "exited 1"
                          (scrutiny-agent--parse-verify "1 " "1.2.3"))))

(ert-deftest scrutiny-agent-verify-parsing-for-a-remote-binary ()
  ;; A :remote-binary is whatever the user built on the host: its
  ;; version is not ours to check, its protocol is.
  (should-not (scrutiny-agent--parse-verify "0 9.9.9 proto 1" "1.2.3" 1))
  (should-not (scrutiny-agent--parse-verify "0 1.2.3 proto 1" "1.2.3" 1))
  (let ((reason (scrutiny-agent--parse-verify "0 1.2.3 proto 2" "1.2.3" 1)))
    (should (string-match-p "speaks protocol 2" reason))
    (should (string-match-p "client speaks protocol 1" reason)))
  ;; Not our program at all.
  (let ((reason (scrutiny-agent--parse-verify "0 some other tool 1.0"
                                              "1.2.3" 1)))
    (should (string-match-p "protocol 1" reason))
    (should (string-match-p "some other tool" reason)))
  ;; Exec failures read the same either way.
  (should (string-match-p "architecture"
                          (scrutiny-agent--parse-verify
                           "126 sh: /x: Exec format error" "1.2.3" 1)))
  (should (string-match-p "exited 1"
                          (scrutiny-agent--parse-verify "1 " "1.2.3" 1))))

(ert-deftest scrutiny-agent-remote-binary-is-a-shell-expression ()
  (should-not (scrutiny-agent--remote-binary '(:transport "sh")))
  (should (equal (scrutiny-agent--remote-binary
                  '(:remote-binary "$HOME/bin/scrutiny-agent"))
                 "$HOME/bin/scrutiny-agent"))
  ;; Inside the double quotes the remote shell uses, ~ is a literal.
  (should (equal (scrutiny-agent--remote-binary
                  '(:remote-binary "~/src/scrutiny-agent/build/agent/scrutiny-agent"))
                 "$HOME/src/scrutiny-agent/build/agent/scrutiny-agent"))
  (should-error (scrutiny-agent--remote-binary '(:remote-binary (a b)))))

(defun scrutiny-agent-tests--connect-remote-binary (remote)
  "Connect a host whose agent is REMOTE, a path on the (local) host.
Returns (REASON . SENT): REASON is nil on success or the error text,
SENT the list of strings written to the transport before the error
or the exec."
  (let* ((install (make-temp-file "scra-rb-install" t))
         (sent nil)
         (scrutiny-agent-default-config nil)
         (scrutiny-agent-hosts
          `(("rb" :transport "sh" :install-dir ,install
             :remote-binary ,remote))))
    (unwind-protect
        (cl-letf* ((original (symbol-function 'process-send-string))
                   ((symbol-function 'process-send-string)
                    (lambda (proc text)
                      (unless (scrutiny-agent-connection "rb")
                        (push text sent))
                      (funcall original proc text)))
                   ;; Nothing on this side may be consulted.
                   ((symbol-function 'scrutiny-agent--local-binary)
                    (lambda (&rest _)
                      (error "local binary lookup must not run"))))
          (cons (condition-case err
                    (progn (scrutiny-agent-connect "rb") nil)
                  (error (error-message-string err)))
                (progn
                  (should-not (directory-files install nil "scrutiny-agent-"))
                  (nreverse sent))))
      (ignore-errors (scrutiny-agent-disconnect "rb"))
      (delete-directory install t))))

(ert-deftest scrutiny-agent-remote-binary-runs-what-is-on-the-host ()
  :tags '(integration)
  (skip-unless (getenv "SCRUTINY_AGENT_BIN"))
  (let* ((result (scrutiny-agent-tests--connect-remote-binary
                  (expand-file-name (getenv "SCRUTINY_AGENT_BIN"))))
         (sent (string-join (cdr result) "")))
    ;; No error means the handshake completed against that binary.
    (should-not (car result))
    ;; Probe, verify, exec: no hash gate, no stream, no install.
    (should (string-search "__SCRA_PROBE__" sent))
    (should (string-search "__SCRA_VERIFY__" sent))
    (should-not (string-search "__SCRA_ST__" sent))
    (should-not (string-search "__SCRB64__" sent))
    (should-not (string-search "__SCRA_INST__" sent))
    (should (string-search (concat "exec \"" (expand-file-name
                                               (getenv "SCRUTINY_AGENT_BIN"))
                                   "\" --rpc-stdio")
                           sent))))

(ert-deftest scrutiny-agent-remote-binary-must-exist-on-the-host ()
  :tags '(integration)
  (skip-unless (getenv "SCRUTINY_AGENT_BIN"))
  (let ((reason (car (scrutiny-agent-tests--connect-remote-binary
                      "/nonexistent/scrutiny-agent"))))
    (should reason)
    (should (string-match-p "does not run on" reason))
    (should (string-search ":remote-binary" reason))
    (should (string-search "/nonexistent/scrutiny-agent" reason))))

(ert-deftest scrutiny-agent-remote-binary-must-speak-our-protocol ()
  :tags '(integration)
  (skip-unless (getenv "SCRUTINY_AGENT_BIN"))
  ;; The version is the user's business; the protocol is not.
  (let ((old (make-temp-file "scra-rb-proto"))
        (other (make-temp-file "scra-rb-ver")))
    (unwind-protect
        (progn
          (with-temp-file old
            (insert "#!/bin/sh\necho \"0.1.0 proto "
                    (number-to-string (1+ scrutiny-agent-protocol-version))
                    "\"\n"))
          (set-file-modes old #o755)
          (let ((reason (car (scrutiny-agent-tests--connect-remote-binary old))))
            (should reason)
            (should (string-match-p
                     (format "speaks protocol %d, but this client speaks \
protocol %d"
                             (1+ scrutiny-agent-protocol-version)
                             scrutiny-agent-protocol-version)
                     reason))
            (should (string-search old reason)))
          ;; Right protocol, some other version: accepted at verify.
          ;; (It is a shell script, so the handshake then fails; the
          ;; failure must be past the verify step.)
          (with-temp-file other
            (insert "#!/bin/sh\n[ \"$1\" = --version ] && echo \"9.9.9 proto "
                    (number-to-string scrutiny-agent-protocol-version)
                    "\"\n"))
          (set-file-modes other #o755)
          (let ((reason (car (scrutiny-agent-tests--connect-remote-binary
                              other))))
            (should reason)
            (should-not (string-match-p "does not run on" reason))))
      (delete-file old)
      (delete-file other))))

(defun scrutiny-agent-tests--connect-with-binary (binary &optional unchecked)
  "Connect a host using BINARY; return nil on success or the error text.
UNCHECKED skips the local image check: the verify tests below feed
the REMOTE step files the local one would refuse, and the remote
step must still catch them for a host whose libraries or kernel
differ from what the header promised."
  (let* ((install (make-temp-file "scra-vfy-install" t))
         (scrutiny-agent-default-config nil)
         (scrutiny-agent-hosts
          `(("vfy" :transport "sh" :install-dir ,install
             :local-binary ,binary))))
    (unwind-protect
        (cl-letf (((symbol-function 'scrutiny-agent--binary-problem)
                   (if unchecked
                       (lambda (&rest _) nil)
                     (symbol-function 'scrutiny-agent--binary-problem))))
          (condition-case err
              (progn (scrutiny-agent-connect "vfy") nil)
            (error (error-message-string err))))
      (ignore-errors (scrutiny-agent-disconnect "vfy"))
      (delete-directory install t))))

(ert-deftest scrutiny-agent-bootstrap-refuses-a-non-binary-before-streaming ()
  :tags '(integration)
  (skip-unless (getenv "SCRUTINY_AGENT_BIN"))
  ;; The field failure: nothing may be sent, nothing installed, and
  ;; the error names the local file so the user knows what to replace.
  (let ((file (make-temp-file "scra-vfy-404"))
        (install (make-temp-file "scra-vfy-install" t))
        (sent nil))
    (unwind-protect
        (let* ((scrutiny-agent-default-config nil)
               (scrutiny-agent-hosts
                `(("vfy404" :transport "sh" :install-dir ,install
                   :local-binary ,file)))
               (reason
                (cl-letf* ((original (symbol-function 'process-send-string))
                           ((symbol-function 'process-send-string)
                            (lambda (proc text)
                              (when (string-search "__SCRB64__" text)
                                (setq sent t))
                              (funcall original proc text))))
                  (with-temp-file file (insert "Not Found"))
                  (condition-case err
                      (progn (scrutiny-agent-connect "vfy404") nil)
                    (error (error-message-string err))))))
          (should reason)
          (should (string-search file reason))
          (should (string-search "Not Found" reason))
          (should-not sent)
          (should-not (directory-files install nil "scrutiny"))
          (should-not (scrutiny-agent-connection "vfy404")))
      (ignore-errors (scrutiny-agent-disconnect "vfy404"))
      (delete-file file)
      (delete-directory install t))))

(ert-deftest scrutiny-agent-verify-accepts-a-working-binary ()
  :tags '(integration)
  (skip-unless (getenv "SCRUTINY_AGENT_BIN"))
  (should-not (scrutiny-agent-tests--connect-with-binary
               (getenv "SCRUTINY_AGENT_BIN"))))

(ert-deftest scrutiny-agent-verify-rejects-an-unrunnable-binary ()
  :tags '(integration)
  (skip-unless (getenv "SCRUTINY_AGENT_BIN"))
  ;; Without the verification step this is a twenty-second timeout at
  ;; meta.hello with nothing to show for it.
  (let ((file (make-temp-file "scra-vfy-text")))
    (unwind-protect
        (progn
          (with-temp-file file (insert "#!/nonexistent/interpreter\n"))
          (set-file-modes file #o755)
          (let ((reason (scrutiny-agent-tests--connect-with-binary file t)))
            (should reason)
            (should (string-match-p "does not run on" reason))
            ;; It names the platform and the file, so the reader knows
            ;; which host and which binary to look at.
            (should (string-match-p (if (eq system-type 'darwin) "Darwin" "Linux")
                                    reason))
            (should (string-match-p (regexp-quote file) reason))))
      (delete-file file))))

(ert-deftest scrutiny-agent-transport-with-a-terminal-is-diagnosed ()
  :tags '(integration)
  ;; Teleport runs a plain `tsh ssh HOST' session in a PTY, whatever
  ;; the client asked for.  The PTY echoes the bootstrap back with a
  ;; prompt in front of every line, so no marker ever starts a line
  ;; and, before this, the connect sat out its first deadline and
  ;; reported a timeout.  The echo of the probe command is the
  ;; diagnosis; the error names the transport that works.
  (skip-unless (getenv "SCRUTINY_AGENT_BIN"))
  (skip-unless (executable-find "python3"))
  (let* ((transport "python3 -c 'import pty,sys; sys.exit(pty.spawn([\"sh\"]))'")
         (install (make-temp-file "scra-pty-install" t))
         (scrutiny-agent-default-config nil)
         (scrutiny-agent-hosts
          `(("pty" :transport ,transport :install-dir ,install
             :local-binary ,(getenv "SCRUTINY_AGENT_BIN"))))
         (t0 (float-time))
         (reason (unwind-protect
                     (condition-case err
                         (progn (scrutiny-agent-connect "pty") nil)
                       (error (error-message-string err)))
                   (ignore-errors (scrutiny-agent-disconnect "pty"))
                   (delete-directory install t))))
    (should reason)
    (should (string-match-p "terminal" reason))
    (should (string-search (concat transport " sh") reason))
    ;; Recognised from the echo, not from the deadline.
    (should (< (- (float-time) t0) 10))
    ;; The transport is gone with its connection.
    (should-not (scrutiny-agent-connection "pty"))))

(ert-deftest scrutiny-agent-transport-that-dies-reports-its-stderr ()
  ;; An ssh whose host is down, unresolvable, or refusing the key says
  ;; so on stderr and exits with nothing on stdout.  The connect used
  ;; to report `transport died; transcript:' and an empty transcript,
  ;; which told the user nothing; the stderr went to a buffer the
  ;; error never named.  The error now carries the transport command,
  ;; its exit status and its stderr.
  ;; tsh writes its errors in colour; the escapes are stripped.
  (let* ((transport "printf '\\033[31mERROR: \\033[0mno SSH auth methods loaded, are you logged in?\\n' >&2; exit 255")
         (scrutiny-agent-default-config nil)
         (scrutiny-agent-hosts `(("down" :transport ,transport)))
         (t0 (float-time))
         (reason (unwind-protect
                     (condition-case err
                         (progn (scrutiny-agent-connect "down") nil)
                       (error (error-message-string err)))
                   (ignore-errors (scrutiny-agent-disconnect "down")))))
    (should reason)
    (should (string-search "transport died" reason))
    (should (string-search "exit status 255" reason))
    (should (string-search "ERROR: no SSH auth methods loaded" reason))
    (should-not (string-search "\e[" reason))
    (should (string-search transport reason))
    (should (string-search "transcript: (nothing)" reason))
    ;; Only what the transport wrote: not Emacs's own note that the
    ;; stderr pipe closed.
    (should-not (string-search "Process scrutiny-agent" reason))
    ;; Reported from the exit, not from the deadline.
    (should (< (- (float-time) t0) 10))
    (should-not (scrutiny-agent-connection "down"))))

(ert-deftest scrutiny-agent-transport-that-hangs-reports-its-stderr ()
  ;; The other failure shape: the transport is alive but silent on
  ;; stdout -- ssh waiting at a host-key or password prompt, which it
  ;; writes to stderr.  The deadline fires; the prompt must be in the
  ;; error, or the user is left guessing why nothing happened.
  (let* ((transport "echo 'Are you sure you want to continue connecting (yes/no)?' >&2; sleep 30")
         (scrutiny-agent-default-config nil)
         (scrutiny-agent-hosts `(("prompt" :transport ,transport)))
         (reason (cl-letf (((symbol-function 'scrutiny-agent--wait-line)
                            (let ((orig (symbol-function 'scrutiny-agent--wait-line)))
                              (lambda (proc state marker _timeout &optional echo-of)
                                (funcall orig proc state marker 1 echo-of)))))
                   (unwind-protect
                       (condition-case err
                           (progn (scrutiny-agent-connect "prompt") nil)
                         (error (error-message-string err)))
                     (ignore-errors (scrutiny-agent-disconnect "prompt"))))))
    (should reason)
    (should (string-search "timed out waiting for __SCRA_PROBE__" reason))
    (should (string-search "continue connecting" reason))
    (should-not (string-search "exit status" reason))
    (should-not (scrutiny-agent-connection "prompt"))))

(ert-deftest scrutiny-agent-verify-rejects-a-wrong-architecture-binary ()
  :tags '(integration)
  (skip-unless (getenv "SCRUTINY_AGENT_BIN"))
  (let ((file (make-temp-file "scra-vfy-elf")))
    (unwind-protect
        (progn
          (let ((coding-system-for-write 'binary))
            (with-temp-file file
              (set-buffer-multibyte nil)
              ;; ELF64 little-endian for e_machine 0xf7, which this host
              ;; cannot execute whatever it happens to be.
              (insert (unibyte-string #x7f ?E ?L ?F 2 1 1 0 0 0 0 0 0 0 0 0
                                      2 0 #xf7 0 1 0 0 0))))
          (set-file-modes file #o755)
          (let ((reason (scrutiny-agent-tests--connect-with-binary file t)))
            (should reason)
            (should (string-match-p "architecture\\|Exec format" reason))))
      (delete-file file))))

(ert-deftest scrutiny-agent-verify-rejects-a-different-program ()
  :tags '(integration)
  (skip-unless (getenv "SCRUTINY_AGENT_BIN"))
  ;; Runs fine, exits 0, is not us. Only checking the exit status would
  ;; wave this through and fail at the handshake instead.
  (let ((file (make-temp-file "scra-vfy-other")))
    (unwind-protect
        (progn
          (with-temp-file file (insert "#!/bin/sh\necho 'some other tool 1.0'\n"))
          (set-file-modes file #o755)
          (let ((reason (scrutiny-agent-tests--connect-with-binary file t)))
            (should reason)
            (should (string-match-p "expected version" reason))))
      (delete-file file))))

(ert-deftest scrutiny-agent-eglot-setup-defers-until-eglot-loads ()
  ;; Calling the setup from init must not load eglot (and with it xref,
  ;; project, flymake...); the contacts go on once eglot arrives, and
  ;; the hook that waited for it is gone afterwards.  Written without
  ;; `with-eval-after-load', which package-lint refuses in a package.
  (skip-unless (not (featurep 'eglot)))
  (scrutiny-agent-eglot-setup)
  (should-not (featurep 'eglot))
  (should (memq #'scrutiny-agent-eglot--register-when-loaded
                after-load-functions))
  (require 'eglot)
  (should scrutiny-agent-eglot--entries)
  (should-not (memq #'scrutiny-agent-eglot--register-when-loaded
                    after-load-functions))
  (should (cl-every (lambda (e) (memq e eglot-server-programs))
                    scrutiny-agent-eglot--entries)))

(ert-deftest scrutiny-agent-unsupported-platform-is-named ()
  ;; "we publish nothing for this" and "the binary is broken" are
  ;; different problems and need different messages.
  (should-not (scrutiny-agent--arch-asset "Linux" "riscv64"))
  (should-not (scrutiny-agent--arch-asset "SunOS" "sparc")))

(ert-deftest scrutiny-agent-bootstrap-is-a-defined-sequence ()
  ;; The bootstrap is a fixed dialogue of marker-terminated steps, each
  ;; one bounded. This pins the markers so a step cannot be reordered
  ;; or dropped without the test noticing.
  (let ((source (with-temp-buffer
                  (insert-file-contents
                   (expand-file-name "scrutiny-agent.el"
                                     (file-name-directory
                                      (locate-library "scrutiny-agent"))))
                  (buffer-string))))
    (dolist (marker '("__SCRA_PROBE__"      ; 1. uname -s / uname -m
                      "__SCRA_ST__"         ; 2. is the right binary there?
                      "__SCRA_INST__"       ; 3. streamed install, hash-gated
                      "__SCRA_VERIFY__"     ; 4. does the binary actually run?
                      "__SCRA_CFG__"        ; 5. is the right config there?
                      "__SCRA_CFGDONE__"    ;    streamed config, hash-gated
                      "__SCRA_EXEC__"))     ; 6. handover
      (should (string-search marker source)))))

(ert-deftest scrutiny-agent-exec-waits-for-the-handover-marker ()
  ;; Without this the handshake is written while the shell may still be
  ;; reading ahead past the exec line, and is lost: the agent starts,
  ;; prints its startup lines, and waits on a stdin that never carries
  ;; meta.hello. Intermittent, and worse on a slow link.
  (let ((source (with-temp-buffer
                  (insert-file-contents
                   (expand-file-name "scrutiny-agent.el"
                                     (file-name-directory
                                      (locate-library "scrutiny-agent"))))
                  (buffer-string))))
    ;; The echo must be on the same line as the exec, so the marker
    ;; proves the shell consumed that line and nothing beyond it.
    (should (string-match-p "echo __SCRA_EXEC__; exec " source))
    (should (string-match-p
             "wait-line proc state \"__SCRA_EXEC__\"" source))))

;; ---------------------------------------------------------------------
;; Packaging
;; ---------------------------------------------------------------------

(defun scrutiny-agent-tests--package-files ()
  "The .el files that ship in the package (tests excluded)."
  (let ((dir (file-name-directory (locate-library "scrutiny-agent"))))
    (seq-remove (lambda (f) (string-match-p "-tests\\.el\\'" f))
                (directory-files dir t "\\.el\\'"))))

(ert-deftest scrutiny-agent-no-duplicate-definitions ()
  "No two shipped files may define the same function.

Loading one file after another silently replaces the earlier
definition, so a collision is invisible until both are loaded --
which is exactly what installing the package does, and what caught
`scrutiny-agent-status' being two unrelated commands."
  (let ((seen (make-hash-table :test #'equal))
        (collisions nil))
    (dolist (file (scrutiny-agent-tests--package-files))
      (with-temp-buffer
        (insert-file-contents file)
        (goto-char (point-min))
        (while (re-search-forward
                "^(\\(?:cl-\\)?\\(?:defun\\|defmacro\\|defsubst\\|\
define-minor-mode\\) \\([^ ()\n]+\\)" nil t)
          (let* ((name (match-string 1))
                 (previous (gethash name seen))
                 (this (file-name-nondirectory file)))
            (if (and previous (not (equal previous this)))
                (push (format "%s: %s and %s" name previous this) collisions)
              (puthash name this seen))))))
    (should (equal collisions nil))))

(ert-deftest scrutiny-agent-package-files-declare-a-provide ()
  ;; package.el requires each file to provide its own feature, or
  ;; `require' from a sibling silently loads nothing.
  (dolist (file (scrutiny-agent-tests--package-files))
    (let ((feature (file-name-base file)))
      (with-temp-buffer
        (insert-file-contents file)
        (should (string-search (format "(provide '%s)" feature)
                               (buffer-string)))))))

(ert-deftest scrutiny-agent-bundled-binaries-are-preferred ()
  ;; A package ships binaries in bin/ beside the Lisp; that has to win
  ;; over the download path, or an installed package hits the network
  ;; on its first connect.
  (let* ((bundle (make-temp-file "scra-bundle" t))
         (cache (make-temp-file "scra-cache" t))
         (scrutiny-agent-bundled-binary-directory bundle)
         (scrutiny-agent-cache-directory cache)
         (scrutiny-agent-binary-version "9.9.9")
         (scrutiny-agent-download-releases nil)
         (name "scrutiny-agent-9.9.9-x86_64"))
    (unwind-protect
        (progn
          (scrutiny-agent-tests--write-image
           (expand-file-name name cache) 'linux "x86_64")
          (should (equal (scrutiny-agent--local-binary nil "x86_64")
                         (expand-file-name name cache)))
          (scrutiny-agent-tests--write-image
           (expand-file-name name bundle) 'linux "x86_64")
          (should (equal (scrutiny-agent--local-binary nil "x86_64")
                         (expand-file-name name bundle)))
          ;; ...and an explicit :local-binary still beats both.
          (let ((explicit (make-temp-file "scra-explicit")))
            (scrutiny-agent-tests--write-image explicit 'linux "x86_64")
            (unwind-protect
                (should (equal (scrutiny-agent--local-binary
                                (list :local-binary explicit) "x86_64")
                               (expand-file-name explicit)))
              (delete-file explicit))))
      (delete-directory bundle t)
      (delete-directory cache t))))

(ert-deftest scrutiny-agent-installed-binaries-spans-both-directories ()
  (let* ((bundle (make-temp-file "scra-bundle" t))
         (cache (make-temp-file "scra-cache" t))
         (scrutiny-agent-bundled-binary-directory bundle)
         (scrutiny-agent-cache-directory cache)
         (scrutiny-agent-binary-version "9.9.9"))
    (unwind-protect
        (progn
          (scrutiny-agent-tests--write-image
           (expand-file-name "scrutiny-agent-9.9.9-x86_64" bundle)
           'linux "x86_64")
          (scrutiny-agent-tests--write-image
           (expand-file-name "scrutiny-agent-9.9.9-aarch64" cache)
           'linux "aarch64")
          (should (equal (sort (mapcar #'car (scrutiny-agent-installed-binaries))
                               #'string<)
                         '("aarch64" "x86_64"))))
      (delete-directory bundle t)
      (delete-directory cache t))))
