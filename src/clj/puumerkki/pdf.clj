(ns puumerkki.pdf
  (:require
     [pandect.algo.sha256 :refer :all]
     [puumerkki.codec :as codec]
     [clojure.java.io :as io])

  (:import [org.apache.pdfbox.pdmodel.interactive.digitalsignature PDSignature SignatureInterface]
           [org.apache.pdfbox.pdmodel PDDocument]
           ;[org.apache.pdfbox.pdmodel.graphics.xobject PDPixelMap PDXObject PDJpeg]
           [org.apache.pdfbox.io RandomAccessFile]
           [org.apache.commons.io IOUtils]
           (org.apache.pdfbox.cos COSName)
           (java.security MessageDigest)
           [java.util Calendar]
           [java.io File FileInputStream FileOutputStream ByteArrayOutputStream]
           (org.apache.commons.codec.digest DigestUtils)))

;; Steps
;;  1. (add-signature-space "your.pdf" "Stephen Signer") -> create "your.pdf-signable"
;;  2. (compute-base64-pkcs [pdf-data]) -> compute data required for signing the signable document
;;  3. obtain signature from external source
;;  4. construct a valid encoded pkcs7 signature to be added to pdf
;;  4. (write-signature! [pdf-data] pkcs7)

;; -----------------------------------------------------------------------------------

(def test-shasum (atom nil)) ;; <- temporary


(def byterange-pattern-vector
  [47 66 121 116 101 82 97 110 103 101 32 91])

(defn space-char? [x]
  (or (= x 32) (= x 10) (= x 13)))


;; File I/O utils

(defn read-file [path]
   (with-open [out (java.io.ByteArrayOutputStream.)]
      (io/copy (io/input-stream path) out)
      (.toByteArray out)))

(defn write-file! [path data]
   (with-open [w (clojure.java.io/output-stream path)]
      (.write w data)))


;; byte array helpers (based on old js versions)

(defn seq->byte-array [seq] ;; bytes -128 -- 127
   (let [arr (byte-array (count seq))]
      (loop [pos 0 seq seq]
         (if (empty? seq)
            arr
            (do
               (aset-byte arr pos (first seq))
               (recur (+ pos 1) (rest seq)))))))

(defn unsigned-seq->byte-array [seq] ;; bytes -128 -- 127
   (let [arr (byte-array (count seq))]
      (loop [pos 0 seq seq]
         (if (empty? seq)
            arr
            (do
               (aset-byte arr pos (first seq))
               (recur (+ pos 1) (rest seq)))))))

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
   (let [end (or (count data) 0)]
      (loop [at 0]
         (if (= at end)
            (vector false false false false false)
            (let [posp (vector-match-at data at byterange-pattern-vector)]
               (if posp
                  (grab-byte-ranges posp (walk-buffer data posp))
                  (recur (+ at 1))))))))

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

;; byte ranges known to be at pos, so signature space is within a few bytes forward
(defn find-signature-space [data pos]
   (loop [pos pos distance 0]
      (cond
         (not (aget data pos))
            false ;; out of data
         (< (zeroes-at data pos) 512)
            (recur (+ pos 1) (+ distance 1))
         :else
            pos)))

;; see https://www.adobe.com/devnet-docs/acrobatetk/tools/DigSigDC/Acrobat_DigitalSignatures_in_PDF.pdf
(defn compute-base64-pkcs [pdf-data]
   (let [[at sa la sb lb] (find-byte-ranges pdf-data)
         signature-space-start (find-signature-space pdf-data 0)
         hashdata (maybe-get-byte-ranges pdf-data sa la sb lb)]
     (if (and hashdata signature-space-start)
       (let
         [sha256sum (map (partial bit-and 255) (sha256-bytes hashdata))
          pkcs (make-pkcs sha256sum)
          payload (codec/base64-encode (map (partial bit-and 255) pkcs))]
        (reset! test-shasum sha256sum) ;; <- temporary
        payload) ;; to be sent to digisign in the data parameter
       nil)))

(defn blank-signer []
  (proxy [SignatureInterface] []
    (sign [content]
       (byte-array (byte-array 100)))))

(defn signature [name]
  (doto (PDSignature.)
    (.setFilter PDSignature/FILTER_ADOBE_PPKLITE)
    (.setSubFilter PDSignature/SUBFILTER_ADBE_PKCS7_DETACHED)
    (.setName name)
    ;(.setLocation "")
    ;(.setReason "")
    (.setSignDate (Calendar/getInstance)))) ;; not a secure time source, but best we can do here


(defn add-signature-space [pdf-path signer-name]
  (let [output-path (str pdf-path "-signable")
        input-document (io/file pdf-path)
        doc (PDDocument/load input-document)
        sig (signature signer-name)
        dummy (blank-signer)
        ]
      (with-open [out (io/output-stream output-path)]
         (.addSignature doc sig dummy)
         (let [ext (.saveIncrementalForExternalSigning doc out)]
            (let [data (.getContent ext)] ;; data to be signed
               (.setSignature ext (byte-array 32))
               (.close doc))))
      output-path))

;; write-signature pdf-data-byte-array pkcs7-asn1-der-byte-sequence → pdf-data-byte-array (modified)
(defn write-signature! [data pkcs7]
   (let [signature (seq->byte-array (codec/hexencode pkcs7))
         pos (find-signature-space data 0)]
      ; (println "Copying signature to pos " pos " -> " (copy-bytes! data signature pos))
      data))



(defn make-pkcs7 [data]
   (let [signature (codec/base64-decode-octets (:signature data))
         chain (map codec/base64-decode-octets (:chain data))
         chain-asn (map codec/asn1-decode chain)
         card-asn (first chain-asn)
         pcertinfo (maybe-get-certificate-info card-asn)
         sha256sum @test-shasum
         pkcs7-asn (make-pkcs7-asn chain pcertinfo sha256sum signature)]
      (codec/asn1-encode pkcs7-asn)))
