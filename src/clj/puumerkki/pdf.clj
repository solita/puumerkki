(ns puumerkki.pdf
  (:require
     [pandect.algo.sha256 :refer :all]
     [puumerkki.codec :as codec]
     [clojure.java.io :as io])

  (:import [org.apache.pdfbox.pdmodel.interactive.digitalsignature PDSignature SignatureInterface SignatureOptions]
           [org.apache.pdfbox.pdmodel.interactive.digitalsignature.visible PDVisibleSignDesigner PDVisibleSigProperties]
           [org.apache.pdfbox.pdmodel PDDocument]
           [org.apache.pdfbox.io RandomAccessFile]
           [org.apache.commons.io IOUtils]
           (org.apache.pdfbox.cos COSName)
           (java.security MessageDigest)
           [java.security.cert Certificate X509Certificate]
           [java.util Calendar]
           [java.io File FileInputStream FileOutputStream ByteArrayOutputStream ByteArrayInputStream]
           (java.security.cert CertificateFactory)
           (java.security Signature)
           (org.apache.commons.codec.digest DigestUtils)
           [org.apache.pdfbox.pdmodel.font PDFont PDType1Font PDTrueTypeFont]
           [org.apache.pdfbox.pdmodel PDPageContentStream]
           [org.bouncycastle.cms.jcajce JcaSimpleSignerInfoVerifierBuilder]
           [org.bouncycastle.cms CMSProcessableByteArray CMSSignedData]
         ))

;; Steps
;;  1. (add-signature-space "your.pdf" "output.pdf" "Stephen Signer") -> create "output.pdf", has space for a signature
;;  2. (compute-base64-pkcs ) -> compute data required for signing the signable document
;;  3. obtain signature from external source
;;  4. construct a valid encoded pkcs7 signature to be added to pdf
;;  4. (write-signature! [pdf-data] pkcs7)

;; -----------------------------------------------------------------------------------


(def byterange-pattern-vector
  [47 66 121 116 101 82 97 110 103 101 32 91])

(defn space-char? [x]
  (or (= x 32) (= x 10) (= x 13)))


;; File I/O utils

(defn read-file [path]
   (with-open [out (java.io.ByteArrayOutputStream.)]
      (io/copy (io/input-stream path) out)
      (.toByteArray out)))

(defn read-pdf [path]
   (PDDocument/load (io/file path)))

(defn write-file! [path data]
   (with-open [w (clojure.java.io/output-stream path)]
      (.write w data)))


;; byte array helpers (based on old js versions)

(defn seq->byte-array [seq] ;; java convention, bytes [-128 - +127]
   (let [arr (byte-array (count seq))]
      (loop [pos 0 seq seq]
         (if (empty? seq)
            arr
            (do
               (aset-byte arr pos (first seq))
               (recur (+ pos 1) (rest seq)))))))

(def unsigned->signed-byte
  (let [mask (bit-shift-right (bit-and-not -1 255) 7)]
     (fn [x]
        (bit-or x (* mask (bit-and x 128))))))

(defn unsigned-seq->byte-array [seq] ;; bytes [0 - 255]
   (seq->byte-array
      (map unsigned->signed-byte seq)))

(defn subarray [arr start len]
   (if (or (< len 0) (< start 0) (> (+ start len) (count arr)))
      nil
      (let [target (byte-array len)]
         (loop [pos 0]
            (if (= pos len)
               target
               (do
                  (aset-byte target pos (aget arr (+ start pos)))
                  (recur (+ pos 1))))))))

(defn copy-bytes! [array content offset]
   (if (>= (count array) (+ offset (count content)))
      (loop [pos (- (count content) 1)]
         (if (> pos -1)
            (do
               (aset-byte array (+ offset pos) (aget content pos))
               (recur (- pos 1)))
            array))
      (do
         (println "ERROR: copy-bytes: byte array size " (count content) ", target data at " offset " of length " (count content) ". Unpossible.")
         nil)))

;; data-bvec offset pattern-vec → false | offset+length(pattern-vec)
(defn vector-match-at [data offset pattern]
   (loop [at 0]
      (let [want (get pattern at)]
         (if want
            (if (= want (aget data (+ offset at)))
               (recur (+ at 1))
               false)
            (+ offset at)))))


(defn skip-space [bs]
   (if (space-char? (first bs))
      (recur (rest bs))
      bs))

(defn finish-num [firstp n bs]
   (vector
      (if (and (= n 0) firstp) false n)
      bs))

(defn digit? [n]
   (<= 48 n 57))

(defn grab-num [bs]
   (loop [bs bs n 0 firstp true]
      (cond
         (empty? bs)
            (finish-num firstp n bs)
         (digit? (first bs))
            (recur (rest bs)
               (+ (* n 10) (- (first bs) 48))
               false)
         :else
            (finish-num firstp n bs))))

;; parse four space delimited decimal numbers
;; these are the before and after byte ranges of signature
(defn grab-byte-ranges [offset bs]
   (let
      [[sa bs] (grab-num (skip-space bs))
       [la bs] (grab-num (skip-space bs))
       [sb bs] (grab-num (skip-space bs))
       [lb bs] (grab-num (skip-space bs))]
    (if (and sa la sb lb)
       (vector offset sa la sb lb)
       (vector offset false false false false))))

 ;; iterate over a data at a specific position
 (defn walk-buffer [buff pos]
    (let [val (aget buff pos)]
       (if val
          (lazy-seq (cons val (walk-buffer buff (+ pos 1))))
          nil)))

;; Find position of signature byte ranges from pdf data and get the numbers.
;; Now that this is handled in backend, we could also get this while adding
;; the space or by parsing the whole pdf.
(defn find-byte-ranges [data]
   (loop [at (- (count data) 1)]
      (if (= at -1)
         (vector false false false false false)
         (let [posp (vector-match-at data at byterange-pattern-vector)]
            (if posp
               (grab-byte-ranges posp (walk-buffer data posp))
               (recur (- at 1)))))))

;; read the byte ranges (for hashing)
;; bvec pos1 len1 pos2 len2 → bvec' | nil, if positions or lengths are missing
(defn maybe-get-byte-ranges [data sa al sb bl]
   (if (and sa al sb bl)
      (let [temp (byte-array (+ al bl))] ;; room for data to be hashed
         (copy-bytes! temp (subarray data sa al) 0)   ;; copy before signature part
         (copy-bytes! temp (subarray data sb bl) al)  ;; copy after signature part
         temp)
     nil))

(defn make-pkcs [sha256sum]
  (into []
     (codec/asn1-encode ;; make the encryptedattributes part
       [:set
        [:sequence [:identifier 1 2 840 113583 1 1 8]
         [:set [:sequence]]]
        [:sequence [:identifier 1 2 840 113549 1 9 3]
         [:set [:identifier 1 2 840 113549 1 7 1]]]
        [:sequence [:identifier 1 2 840 113549 1 9 4]
         [:set [:octet-string (map (partial bit-and 255) sha256sum)]]]])))


;; This is the expression to be encoded and saved to PDF
(defn make-pkcs7-asn [chain certinfo-asn sha256sum sha256withrsa]
  [:sequence
   [:identifier 1 2 840 113549 1 7 2] ;; signedData
   [:explicit 0
    [:sequence
     1 ;; version
     [:set-of [:sequence [:identifier 2 16 840 1 101 3 4 2 1] :null]] ;; sha-256
     [:sequence [:identifier 1 2 840 113549 1 7 1]] ;; data
     [:explicit 0
      [:quote (nth chain 2)]
      [:quote (nth chain 1)]
      [:quote (nth chain 0)]]
     [:set-of
      [:sequence
       1
       certinfo-asn
       [:sequence [:identifier 2 16 840 1 101 3 4 2 1] :null] ;; SHA256

       ;; pkcs, voisi käyttää samaa
       [:explicit 0 ;; encryptedAttributes
        [:sequence [:identifier 1 2 840 113583 1 1 8] [:set-of [:sequence]]]  ;; pdfRevocationInfoArchival
        [:sequence [:identifier 1 2 840 113549 1 9 3] [:set-of [:identifier 1 2 840 113549 1 7 1]]] ;; Contentype, data
        [:sequence
         [:identifier 1 2 840 113549 1 9 4] ;; messageDigest
         [:set-of
          [:octet-string sha256sum]]]] ;; message digest payload

       [:sequence [:identifier 1 2 840 113549 1 1 11] :null] ; sha256w/rsa
       [:octet-string sha256withrsa]]]]]])

;; get certificate info for pkcs7
(defn maybe-get-certificate-info [cert]
  (let [issuerinfo (-> cert (nth 1) (nth 4)) ;; could now use codec -> asn selectors
        keyid (nth (nth cert 1) 2)]
    (if (and keyid issuerinfo)
      [:sequence issuerinfo keyid]
      nil)))

;; count number of ascii zeroes at position (which are used for signature area filling)
(defn zeroes-at [data pos]
   (loop [pos pos n 0]
      (let [val (aget data pos)]
         (if (= val 48)
            (recur (+ pos 1) (+ n 1))
            n))))

(defn find-signature-space [data]
   (loop [pos 0]
      (cond
         (not (aget data pos))
            false ;; out of data
         (and (= (aget data pos) 60) (> (zeroes-at data (+ pos 1)) 512))
            (+ pos 1)
         :else
            (recur (+ pos 1)))))

;; see https://www.adobe.com/devnet-docs/acrobatetk/tools/DigSigDC/Acrobat_DigitalSignatures_in_PDF.pdf

(defn signable-data [pdf-data]
   (let [[at sa la sb lb] (find-byte-ranges pdf-data)
         hashdata (maybe-get-byte-ranges pdf-data sa la sb lb)]
     hashdata))

(defn signable-data-hash [pdf-data]
   (if-let [hashdata (signable-data pdf-data)]
      (map (partial bit-and 255) (sha256-bytes hashdata))))

(defn compute-base64-pkcs [pdf-data]
   (if-let [sha256sum (signable-data-hash pdf-data)]
      (let [pkcs (make-pkcs sha256sum)
            payload (codec/base64-encode (map (partial bit-and 255) pkcs))]
        payload)))

(defn blank-signer []
  (proxy [SignatureInterface] []
    (sign [content]
       (byte-array (byte-array 100)))))

;; "Signer Name", (nil | image) -> PDSignature

(defn signature [name]
  (doto (PDSignature.)
    (.setFilter PDSignature/FILTER_ADOBE_PPKLITE)
    (.setSubFilter PDSignature/SUBFILTER_ADBE_PKCS7_DETACHED)
    (.setName name)
    ;(.setLocation "")
    ;(.setReason "")
    (.setSignDate (Calendar/getInstance)))) ;; not a secure time source, but best we can do here


;;; pdfbox notes
; - in 1.8 it was possible to add signature and use saveincremental
; - in 2.0 it seems to be necessary to saveIncrementalForExternalSigning, even though we aren't really using it
; - not adding a signature (which we don't use) seems to result in broken byte ranges in output
; - using saveincremental would appear to require marking altered objects
; - it may be possible to use saveincremental again in 2.1=

;; Warning! Do not parse user supplied PDF:s without proper safety equipment.

;; "foo.pdf" "foo-signed.pdf" "Signer Name" -> "foo-signed.pdf" | nil on error
(defn add-signature-space [pdf-path output-pdf-path signer-name]
   (try
      (let [input-document (io/file pdf-path)
            doc (PDDocument/load input-document)
            sig (signature signer-name)
            dummy (blank-signer)]
         (with-open [out (io/output-stream output-pdf-path)]
            (.addSignature doc sig dummy)
            (let [ext (.saveIncrementalForExternalSigning doc out)]
               (let [data (.getContent ext)] ;; data to be signed
                  (.setSignature ext (byte-array 32))
                  (.close doc))))
      output-pdf-path)
      (catch Exception e
         ;; log reason
         ;; todo: since there are various logging systems in use, pass handlers optionally here?
         (println "ERROR: " e)
         nil)))

(defn add-watermarked-signature-space [pdf-path output-pdf-path signer-name image-path x y]
   (let [pdf (read-pdf pdf-path)
         sig-designer
            (PDVisibleSignDesigner.
               pdf
               (io/input-stream image-path)
               1)
         sig-props (PDVisibleSigProperties.)
         sig-opts  (SignatureOptions.)
        ]
       ;(.signerName sig-props "")
       (.xAxis sig-designer x)    ;; 0 left
       (.yAxis sig-designer y)    ;; 0 top
       ;(.zoom sig-designer 100)
       (.visualSignEnabled sig-props true)
       (.setPdVisibleSignature sig-props sig-designer)
       (.buildSignature sig-props)
       (.setVisualSignature sig-opts sig-props)
       (with-open [out (io/output-stream output-pdf-path)]
            (.addSignature
               pdf                     ;; PDDocument
               (signature signer-name) ;; PDSignature
               (blank-signer)          ;; SignatureInterface (dummy)
               sig-opts                ;; SignatureOptions
               )
            (let [ext (.saveIncrementalForExternalSigning pdf out)]
               (let [data (.getContent ext)] ;; data to be signed
                  (.setSignature ext (byte-array 32))
                  (.close pdf))))
      (.close sig-opts)
      output-pdf-path
      ))


;; write-signature pdf-data-byte-array pkcs7-asn1-der-byte-sequence → pdf-data-byte-array (modified) | nil
(defn write-signature! [data pkcs7]
   (let [signature (seq->byte-array (codec/hex-encode pkcs7))
         pos (find-signature-space data)]
      (if pos
         (do
            (copy-bytes! data signature pos)
            data)
         nil)))

(defn make-pkcs7 [data pdf-data]
   (let [signature (codec/base64-decode-octets (:signature data))
         chain (map codec/base64-decode-octets (:chain data))
         chain-asn (map codec/asn1-decode chain)
         card-asn (first chain-asn)
         pcertinfo (maybe-get-certificate-info card-asn)
         sha256sum (signable-data-hash pdf-data)
         pkcs7-asn (make-pkcs7-asn chain pcertinfo sha256sum signature)]
      (codec/asn1-encode pkcs7-asn)))

(defn message-digest [asn]
   (if-let [node (codec/asn1-find asn [:sequence [:identifier 1 2 840 113549 1 9 4] [:set :octet-string]])]
      (-> node (nth 2) (nth 1) (nth 1))))

;; pdf-data -> nil | validish-signature-ast (only structure and digest is verified, not the actual signature)
(defn cursory-verify-signature [data]
   (let [[at sa la sb lb] (find-byte-ranges data)]
      (if (and
            at sa sb lb                  ;; byte ranges there
            (= sa 0)                     ;; signed data starts from beginning
            (= (+ sb lb) (count data))   ;; signed data ends at end of file
            (< (+ sa la) sb)             ;; first range is below the second one
            (= 60 (aget data la)))       ;; first range is followed by < (though this is odd)
         (if-let [sigspace
               (subarray data
                  (+ la 1)               ;; skip the leading <
                  (- sb la 2))]          ;; up to start of data to be hashed
            (if-let [sigdata (codec/hex-decode sigspace)]
               (if-let [asn-ast (codec/asn1-decode sigdata)]
                  (if-let [digest (message-digest asn-ast)]
                     (if-let [correct-digest (signable-data-hash data)]
                        (if (= digest correct-digest)
                           ;; all good so far
                           asn-ast
                           nil)))))))))

;; first part of verification
(defn partial-verify-signatures [pdf-path]
   (try
      (let [pdf (read-pdf pdf-path)]
         (reduce
            (fn [st sig]
               (and st
                  (let [signature-content (.getContents sig (io/input-stream pdf-path))
                        signed-content    (.getSignedContent sig (io/input-stream pdf-path))
                        cmsProcessableInputStream (CMSProcessableByteArray. signed-content)
                        cmsSignedData (CMSSignedData. cmsProcessableInputStream signature-content)
                        signerInformationStore (.getSignerInfos cmsSignedData)
                        signers (.getSigners signerInformationStore)
                        certs (.getCertificates cmsSignedData)]
                     (reduce
                        (fn [st signer]
                           (and st
                              (let [signer-id (.getSID signer)
                                    certificates (.getMatches certs signer-id)]
                                 (reduce
                                    (fn [st signerCertificate]
                                       (and st
                                          (let [verifier (.build (JcaSimpleSignerInfoVerifierBuilder.) signerCertificate)]
                                             (.verify signer verifier))))
                                    st
                                    certificates))))
                       st
                       signers))))
            true
            (.getSignatureDictionaries pdf)))
      (catch Exception e
         (println "exception: " e)
         nil)))

(defn verify-signatures [path]
   (and
      (partial-verify-signatures path)
      ; check revocation lists
      ; check signing time, or rely on verifier
      ; fixed optional trust root?
      ))


; (defn inc-update [path out-path]
;    (let [pdf (read-pdf path)
;          page (.getPage pdf 0)
;          font
;             org.apache.pdfbox.pdmodel.font.PDType1Font/HELVETICA
;             ; org.apache.pdfbox.pdmodel.font.PDType1Font/TIMES_ROMAN
;          font-size 14
;          catalog (.getDocumentCatalog pdf)
;          pages (.getPages catalog) ;; no longer getAllPages
;          first (.get pages 0)
;          content-stream
;             (PDPageContentStream. pdf first
;                true  ;; append
;                false ;; compress
;                )]
;       (.beginText content-stream)
;       (.newLineAtOffset content-stream 50 50)
;       (.setFont content-stream font font-size)
;       (.showText content-stream "Overlay")
;       (.endText content-stream)
;       (.close content-stream)
;
;       (-> pdf (.getPages) (.getCOSObject) (.setNeedToBeUpdated true))
;       (-> pdf (.getDocumentCatalog) (.getCOSObject) (.setNeedToBeUpdated true))
;       (-> first (.getCOSObject) (.setNeedToBeUpdated true))
;
;       (let [out (clojure.java.io/output-stream out-path)]
;          (.saveIncremental pdf out)
;          (.close out))
;
;       (.close pdf)
;       out-path))

