(ns puumerkki.crypt
  (:require
     [puumerkki.codec :as codec]
     [clojure.java.io :as io]
     [clojure.string :as str])

  (:import
     (java.security MessageDigest)
     (java.security Signature)
     (java.security.spec X509EncodedKeySpec)
     (java.security.spec PKCS8EncodedKeySpec)
     (java.security KeyFactory)
     (java.security.cert CertificateFactory)
     (sun.security.x509 CRLDistributionPointsExtension)
     ))

(def a-signature-trust-roots (atom nil))

(def b64->bytes
   (comp byte-array
         codec/base64-decode-octets))

(defn bytes->cert [bytes]
   (try
      (let [cf (CertificateFactory/getInstance "X.509")]
          (.generateCertificate cf (io/input-stream bytes)))
      (catch Exception e
         ; (println "ERROR: chain->cert: " e)
         nil)))


(defn read-cert [cf instr]
   (if (.available instr)
      (try
         (.generateCertificate cf instr)
         (catch Exception e
            ; (println "ERROR reading certificates: " e)
            nil))
      nil))

(defn pem-file->certs [path]
   (try
      (let [stream (io/input-stream path)
            cf (CertificateFactory/getInstance "X.509")]
            (loop [certs nil]
               (let [cert (read-cert cf stream)]
                  (if cert
                     (recur (cons cert certs))
                     certs))))
      (catch Exception e
         nil)))


(defn cert-name [cert]
   (try
      (.getName (.getSubjectDN cert))
      (catch Exception e
         (println "EXCEPTION " e)
         "(bad cert)")))

(defn trusted-root-cert? [cert]
   (reduce
      (fn [is ca]
         (or is (.equals ca cert)))
      false @a-signature-trust-roots))

;; -> added-something?
(defn add-trust-roots! [pem-path]
   (println "Loading signature trust roots from " pem-path)
   (let [certs (pem-file->certs pem-path)]
      (if (empty? certs)
         (do
            (println "ERROR: Failed to load certs from " pem-path)
            false)
         (reduce
            (fn [added? cert]
               (if (trusted-root-cert? cert)
                  (do
                     (println "NOTE: skipping already trusted cert " (cert-name cert))
                     added?)
                  (do
                     (println "NOTE: Adding trusted cert " (cert-name cert))
                     (reset! a-signature-trust-roots
                        (cons cert @a-signature-trust-roots))
                     true)))
               false certs))))

(defn string->bytes [s]
   (.getBytes s))

(def b64->cert
   (comp bytes->cert
         b64->bytes))

(def chain->signing-cert
   (comp b64->cert first))

(defn cert->pubkey [cert]
   (if cert (.getPublicKey cert)))

(defn signature-validity [errs pub signature type data]
   (let [verifier (Signature/getInstance type)]   ; <- type requested by us
      (.initVerify verifier pub)
      (.update verifier data)
      (if (.verify verifier signature)
         errs
         (cons :signature-not-valid errs))))

(defn b64-cert->pem [b]
   (str "-----BEGIN CERTIFICATE-----\n"
      (clojure.string/replace b #"([^\n]{80})" "$1\n") ;; for readability
      "\n-----END CERTIFICATE-----\n"))

(defn anchor-cert-validity [errs b64cert]
   (let [cert (b64->cert b64cert)]
      (if (trusted-root-cert? cert)
         errs
         (cons :untrusted-root-cert errs))))

(defn chain-validity [errs certs]
   (cond
      (nil? certs)
         (cons :invalid-certificate-chain errs)
      (empty? (rest certs))
         errs ;; root cert is checked elsewhere
      :else
         (let [sub (first certs)       ;; the chain is complete and in order
               issuer (second certs)]
            (try
               (do
                  ; (println "debug: validating cert chain at " (.getIssuerDN sub) " <- " (.getSubjectDN issuer))
                  (.verify sub (cert->pubkey issuer))
                  (chain-validity errs (rest certs)))
               (catch Exception e
                  ;; could accidentally leak sensitive data to log if this is e.g. the signing
                  ;; certificate and error results from card reader application failure or
                  ;; unexpected change in its operation.
                  ; (println "ERROR: certificate chain validation failed for certificate: " sub)
                  (cons :invalid-certificate-chain errs))))))

;; exception -> boolean
(defn cert-validity [errs cert]
   (try
      (.checkValidity cert)
      errs
      (catch Exception e
         ; (cons :cert-not-valid errs)
         ;; need to order new test cards
         (println "WARNING: certificate not valid, but allowing it")
         errs)))

(defn cert-revocation-status [errs cert]
   (println "NOTE: No CRL/OCSP handling yet. Allowing cert.")
   errs)

;; -> nil = ok, list of error symbols otherwise
(defn validation-errors [sig-b64s msg-bytes chain]
   (try
      (let [cert (chain->signing-cert chain)
            pub  (cert->pubkey cert)]

         (cond
            (not cert)
               (list :cannot-read-certificate)
            (not pub)
               (list :cannot-read-public-key)
            :else
               (-> nil
                  (cert-validity cert)          ;; validity time, relies on computer clock
                  (cert-revocation-status cert) ;; CRL distribution point known, no loading and check yet
                  (signature-validity pub (b64->bytes sig-b64s) "SHA256withRSA" msg-bytes)
                  (chain-validity (map b64->cert chain))
                  (anchor-cert-validity (last chain))
                  )))
      (catch Exception e
         (list :validation:error))))

;; You probably want to call validation-errors instead to be able to log/report the reasons
(defn valid? [sig-b64s msg-string chain]
   (let [errs (validation-errors sig-b64s (string->bytes msg-string) chain)]
      (println "DEBUG: validation errors " errs)
      (empty? errs)))

(defn n-bits [num]
   (loop [n 0 h 1]
      (if (> h num)
         n
         (recur (+ n 1) (*' 2 h)))))

;; get bit count if applicable
(defn rsa-key-size [pub]
   (try
      (n-bits (.getModulus pub))
      (catch Exception e
         nil)))

(defn cert-crl-bytes [cert]
   (try
      (nth
         (codec/asn1-decode
            (map
               (fn [x] (bit-and 255 x))
               (seq (.getExtensionValue cert "2.5.29.31"))))
         1)
      (catch Exception e
         (println "ERROR: failed to find CRL source from cert " (cert-name cert))
         nil)))

(defn crl-distribution-points [cert]
   (map
      (fn [crl]
         (let [s (.toString (.names (.getFullName crl)))]
            (str/replace s #"^\[URIName: (.*)\]$" "$1")))
      (.get (.getCRLDistributionPointsExtension cert)
         CRLDistributionPointsExtension/POINTS)))

(defn cert->signer-info [cert]
   {:serial (.getSerialNumber cert)
    :issuer (.getName (.getIssuerDN cert))
    :not-after (.getTime (.getNotAfter cert))
    :not-before (.getTime (.getNotBefore cert))
    :givenname (.getGivenName (.getSubjectDN cert))
    :surname (.getGivenName (.getSubjectDN cert))
    :commonname (.getCommonName (.getSubjectDN cert))
    :algorithm (.getAlgorithm (.getPublicKey cert))
    :key-size (rsa-key-size (.getPublicKey cert))     ; nil for non-rsa
    :crl-points (crl-distribution-points cert)
    })

;; -> nil if signature is invalid | map of signing certificate information
(defn signer-info [sig-b64s msg-string chain]
   (let [errs (validation-errors sig-b64s (string->bytes msg-string) chain)]
      (if (empty? errs)
         (cert->signer-info
            (chain->signing-cert chain))
         (do
            (println "ERRORS: " errs)
            nil))))
