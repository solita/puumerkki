(ns puumerkki.codec
  (:refer-clojure :exclude [abs bigint])
  (:require [puumerkki.bigint :as bigint :refer [bigint bigint?]]
            #?(:cljs [goog.crypt :as crypt])))

;;; misc utils

(def max-safe-integer-bytes
  #?(:cljs 4
     :clj 7))

(defn abs [n]
  (if (< n 0) (* n -1) n))

(defn lex< [a b]
  (cond
    (empty? a) (not (empty? b))
    (empty? b) false
    (< (first a) (first b)) true
    (= (first a) (first b)) (recur (rest a) (rest b))
    :else false))

(defn fail [& whys]
  #?(:clj (throw (Exception. (apply str whys))), :cljs (throw (js/Error. whys))))

(defn char2ascii [x]
  #?(:clj (int x), :cljs (.charCodeAt (str x) 0)))

(defn string2bytes [s]
  #?(:clj (.getBytes s), :cljs (map char2ascii s)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;,
;;;
;;; ASN.1 (DER) encoding
;;;

(defn to-7bit-digits [n]
  (if (< n 128)
    (list n)
    (cons (bit-and n 127)
          (to-7bit-digits
            (bit-shift-right n 7)))))

(defn to-8bit-digits [x]
  (loop [x* x out (list)]
    (let [res (cons (bit-and x* 255) out)
          x* (bit-shift-right x* 8)]
      (if (<= x* 0)
        res
        (recur x* res)))))

(defn bigint->8bit-digits [x]
  (loop [x* (bigint x) out (list)]
    (let [res (cons (bigint/bit-and x* (bigint 255)) out)
          x* (bigint/bit-shift-right x* 8)]
      (if (= x* (bigint 0))
        (map bigint/->int res)
        (recur x* res)))))

(defn bignum [in]
  (loop
    [left (bit-shift-right in 7)
     out (list (bit-and in 127))]
    (if (= left 0)
      out
      (recur (bit-shift-right left 7)
             (cons (bit-or (bit-and left 127) 128) out)))))

(defn length-bs [len]
  (if (< len 128)
    (list len)
    (let
      [ds (to-8bit-digits len)
       nd (count ds)]
      (if (< nd 128)
        (cons (bit-or 128 nd) ds)
        (fail "too many length bytes")))))

(defn byte2bits [tl b]
  (loop [bit 128 out tl]
    (if (= bit 0)
      out
      (recur (bit-shift-right bit 1)
             (cons
               (if (= (bit-and b bit) 0) \0 \1)
               out)))))

(defn bytes2bitstring [bs]
  (reverse
    (reduce byte2bits () bs)))

(defn identifier [class consp tagnum]
  (if (> tagnum 30)
    (cons
      (bit-or (bit-shift-left class 6) (bit-or (bit-shift-left consp 5) 31))
      (bignum tagnum))
    (list
      (bit-or (bit-shift-left class 6) (bit-or (bit-shift-left consp 5) tagnum)))))

;;; todo: preshift


(def class-universal 0)
(def class-application 1)
(def class-context-specific 2)
(def class-private 3)

(def is-primitive 0)
(def is-constructed 1)

(def tag-boolean 1)
(def tag-integer 2)
(def tag-bit-string 3)
(def tag-octet-string 4)
(def tag-null 5)
(def tag-object-identifier 6)
(def tag-sequence 16)                                       ;; also sequence-of
(def tag-set 17)                                            ;; also set-of
(def tag-printable-string 19)
(def tag-t61string 20)
(def tag-ia5string 22)
(def tag-utfstring 12)
(def tag-utc-time 23)

(def integer-identifier
  (identifier class-universal is-primitive tag-integer))

(defn- encode-integer-from-bytes [bytes]
  (let [bytes (if (= 0x80 (bit-and (first bytes) 0x80))
                (cons 0 bytes)
                bytes)]
    (concat
     integer-identifier
     (length-bs (count bytes))
     bytes)))

(defn encode-integer [int]
  (if (neg? int)
    (fail "Negative integer: " int)
    (encode-integer-from-bytes (to-8bit-digits int))))

(defn encode-bigint [int]
  (if (neg? int)
    (fail "Negative integer: " int)
    (encode-integer-from-bytes (bigint->8bit-digits int))))

(defn bitstring2bytes [str]
  (loop
    [bs (seq str)
     bit 128
     this 0
     out (list)]
    (if (empty? bs)
      (reverse
        (if (= bit 128) out (cons this out)))
      (let [this (if (= (first bs) \1) (bit-or bit this) this)]
        (if (= bit 1)
          (recur (rest bs) 128 0 (cons this out))
          (recur (rest bs) (bit-shift-right bit 1) this out))))))

(def encode-null
  (list 5 0))

(defn encode-object-identifier [ids]
  ;; first two ids are merged and there are always at least two of them
  (let
    [ids (cons (+ (* 40 (first ids)) (nth ids 1)) (rest (rest ids)))
     contents
     (apply concat
            (map bignum ids))]
    (concat
      (identifier class-universal is-primitive tag-object-identifier)
      (concat
        (length-bs (count contents))
        contents))))

;; (ceil (/ x 8)), but avoid clojure/java math weirdness here
(defn needed-bytes [bits]
  (+ (bit-shift-right bits 3)
     (if (= 0 (bit-and bits 3)) 0 1)))

(defn encode-bitstring [bs]
  (let
    [l (count bs)
     nb (needed-bytes l)
     pad-bits (abs (- l (* nb 8)))
     bytes (bitstring2bytes bs)
     content (cons pad-bits bytes)
     len-bytes (length-bs (count content))]
    (concat (identifier class-universal is-primitive tag-bit-string)
            len-bytes content)))

(defn encode-ia5string [str]
  (let [l (count str)]
    (concat
      (identifier class-universal is-primitive tag-ia5string)
      (length-bs l)
      (string2bytes str))))

(defn encode-printable-string [str]
  (let [l (count str)]
    (concat
      (identifier class-universal is-primitive tag-printable-string)
      (length-bs l)
      (string2bytes str))))

(defn encode-utfstring [s]
   (let [bs #?(:clj (map (partial bit-and 255) (.getBytes s "UTF-8")) ;; &255, because java bytes are signed
               :cljs (crypt/stringToUtf8ByteArray s))]
      (concat
         (identifier class-universal is-primitive tag-utfstring)
         (length-bs (count bs))
         bs)))

(defn encode-octet-string [bs]
  (concat
    (identifier class-universal is-primitive tag-octet-string)
    (length-bs (count bs))
    (seq bs)))

(defn encode-sequence [& es]
  (concat
    (identifier class-universal is-constructed tag-sequence)
    (let [bs (apply concat es)]
      (concat
        (length-bs (count bs))
        bs))))

(defn encode-set [& encoded]
  (let [bs (apply concat encoded)]
    (concat
      (identifier class-universal is-constructed tag-set)
      (length-bs (count bs))
      bs)))

;; as encode-set, but order is lexicographic
(defn encode-set-of [& encoded]
  (let [bs (apply concat (sort lex< encoded))]
    (concat
      (identifier class-universal is-constructed tag-set)
      (length-bs (count bs))
      bs)))

(defn encode-explicit [n & es]
  (let [bs (apply concat es)]
    (concat
      (identifier class-context-specific is-constructed n)
      (length-bs (count bs))
      bs)))

(defn encode-utc-time [timestr]
  (concat
    (identifier class-universal is-primitive tag-utc-time)
    (length-bs (count timestr))
    (string2bytes timestr)))

(defn asn1-encode [node]
   (cond
      (vector? node)
         (let [op (first node)]
            (cond
               (= op :sequence)
                  (apply encode-sequence
                     (map asn1-encode (rest node)))
               (= op :set)
                  (apply encode-set (map asn1-encode (rest node)))
               (= op :set-of)
                  (apply encode-set-of (map asn1-encode (rest node)))
               (= op :explicit)
                  (apply encode-explicit (cons (nth node 1) (map asn1-encode (rest (rest node)))))
               (= op :quote)
                  (if (= (count node) 2)
                     (nth node 1)
                     (fail ":quote requires one pre-encoded argument"))
               (= op :ia5string)
                  (if (= (count node) 2)
                    (encode-ia5string (nth node 1))
                    (fail ":ia5string wants one string element"))
               (= op :octet-string)
                  (if (= (count node) 2)
                    (encode-octet-string (nth node 1))
                    (fail ":octet-string wants one list element"))
               (= op :bit-string)
                  (if (= (count node) 2)
                    (encode-bitstring (nth node 1))
                    (fail ":bit-string wants one string element"))
               (= op :printable-string)
                  (if (= (count node) 2)
                    (encode-printable-string (nth node 1))
                    (fail ":printable-string wants one string element"))
               (= op :utfstring)
                  (if (= (count node) 2)
                    (encode-utfstring (nth node 1))
                    (fail ":utfstring wants one string element"))
               (= op :identifier)
                  (encode-object-identifier (rest node))
               (= op :encapsulated-octet-string)
                  ;; these are just octet strings which happen to have valid content
                  (if (= (count node) 2)
                    (encode-octet-string
                      (asn1-encode (nth node 1)))
                    (fail ":encapsulated-octet-string requires one argument (did you want a sequence?)"))
               (= op :encapsulated-bitstring)
               ;; these are just bitstrings which happen to have valid content
                  (if (= (count node) 2)
                    (encode-bitstring
                      (bytes2bitstring
                        (asn1-encode (nth node 1))))
                    (fail ":encapsulated-bitstring requires one argument (did you want a sequence?)"))
               (= op :utctime)
                  (if (= (count node) 2)
                    (encode-utc-time (nth node 1))
                    (fail ":utctime wants one string element"))
               :else
                  (fail "Unknown ASN.1 operator")))
      (bigint? node)
         (encode-bigint node)
      (integer? node)
         (encode-integer node)
      (string? node)
         (encode-printable-string node)
      (= node false)
         (list 1 1 0)
      (= node true)
         (list 1 1 255) ;; true is very true in ASN.1
      (= node :null)
         encode-null
      (= node ())
         encode-null
      :else
         (fail "Unknown ASN.1 encoder node type: " node)))



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;,
;;;
;;; ASN.1 (DER) decoding
;;;

(defn parse-bignum [lst]
  (loop [out 0 this (first lst) lst (rest lst)]
    (cond
      (nil? this)
      (vector false "end of input" lst)
      (= 128 (bit-and this 128))
      ;; 7 more bits in this byte
      (recur
        (bit-or (bit-shift-left out 7) (bit-and this 127))
        (first lst) (rest lst))
      :else
      (vector true (bit-or (bit-shift-left out 7) this) lst))))

;; parsers are lst → ok/bool value/reason rest-of-input
(defn parse-identifier [tag tail]
  (let
    [class (bit-shift-right tag 6)
     consp (bit-and (bit-shift-right tag 5) 1)
     tagnum (bit-and tag 31)]
    (if (= tagnum 31)
      (let [[ok tagnum tailp] (parse-bignum tail)]
        (if ok
          (vector true class consp tagnum tailp)
          (vector false (list "bad bignum: " tagnum) tail)))
      (vector true class consp tagnum tail))))

(defn read-bytes [bs count]
  (loop [bs bs count count out 0]
    (if (= count 0)
      (vector true out bs)
      (let [hd (first bs)]
        (if hd
          (recur (rest bs) (- count 1) (bit-or (bit-shift-left out 8) hd))
          (vector false "out of data" bs))))))

(defn read-bytes-other-endian [bs count]
  (loop [bs bs count count out 0 shift 0]
    (if (= count 0)
      (vector true out bs)
      (let [hd (first bs)]
        (if hd
          (recur (rest bs) (- count 1) (bit-or out (bit-shift-left hd shift)) (+ shift 8))
          (vector false "out of data" bs))))))

(defn read-bytes->bigint [bs count]
  (loop [[hd & bs-rest :as bs] bs count count out (bigint 0)]
    (if (= count 0)
      (vector true out bs)
      (if hd
        (recur bs-rest (dec count) (bigint/bit-or (bigint/bit-shift-left out 8) (bigint hd)))
        (vector false "out of data" bs)))))

(defn parse-length [bs]
  (let [n (first bs)]
    (cond
      (not n)
      (vector false "out of data" bs)
      (< n 128)
      (vector true n (rest bs))
      :else
      (let [count (- n 128)]
        (read-bytes (rest bs) count)))))

(defn parse-integer [bs]
  (let
    [[ok nb bs] (parse-length bs)]
    (if ok
      (if (> nb max-safe-integer-bytes)
        (read-bytes->bigint bs nb)
        (read-bytes bs nb))
      (vector false (str "failed to get integer size: " nb) bs))))

(defn grab [lst n]
  (loop [lst lst n n out ()]
    (cond
      (= n 0)
      (vector (reverse out) lst)
      (empty? lst)
      (vector false lst)
      :else
      (recur (rest lst) (- n 1) (cons (first lst) out)))))

(defn parse-printable-string [bs]
  (let [[ok nb bs] (parse-length bs)]
    (if ok
      (let [[bytes bs] (grab bs nb)]
        (if bytes
          (vector true (vector :printable-string (apply str (map char bytes))) bs)
          (vector false bytes bs)))
      (vector false nb bs))))

(defn parse-object-identifier [bs]
  (let [[ok nb bs] (parse-length bs)]
    (if ok
      (let [[idbs bs] (grab bs nb)]
        (loop [idbs idbs ids ()]
          (if (empty? idbs)
            (let [ids (reverse ids)
                  a (quot (first ids) 40)
                  b (rem (first ids) 40)
                  ids (cons a (cons b (rest ids)))]
              (vector true (into [] (cons :identifier ids)) bs))
            (let [[ok num idbs] (parse-bignum idbs)]
              (if ok
                (recur idbs (cons num ids))
                (vector false (str "bad bignum within object identifier: " num) bs))))))
      (vector false "out of data reading object identifier" bs))))

(defn parse-ia5string [bs]
  (let [[ok nb bs] (parse-length bs)]
    (if ok
      (let [[bytes bs] (grab bs nb)]
        (if bytes
          (vector true (vector :ia5string (apply str (map char bytes))) bs)
          (vector false bytes bs)))
      (vector false nb bs))))

(defn parse-utfstring [bs]
  (let [[ok nb bs] (parse-length bs)]
    (if ok
      (let [[bytes bs] (grab bs nb)]
        (if bytes
          (vector true (vector :utfstring #?(:clj  (String. (byte-array bytes)),
                                             :cljs (crypt/utf8ByteArrayToString (clj->js bytes)))) bs)
          (vector false bytes bs)))
      (vector false nb bs))))

(defn parse-utctime [bs]
  (let [[ok nb bs] (parse-length bs)]
    (if ok
      (let [[bytes bs] (grab bs nb)]
        (if bytes
          (vector true (vector :utctime (apply str (map char bytes))) bs)
          (vector false bytes bs)))
      (vector false nb bs))))

(defn parse-t61string [bs]
  (let [[ok nb bs] (parse-length bs)]
    (if ok
      (let [[bytes bs] (grab bs nb)]
        (if bytes
          (vector true (vector :t61string (apply str (map char bytes))) bs)
          (vector false bytes bs)))
      (vector false nb bs))))

(defn octets2bitstring [octets pads]
  (let [len (* 8 (count octets))
        bits (bytes2bitstring octets)
        [bits pads] (grab bits (- len pads))]
    (vector :bit-string (apply str bits))))

(defn parse-bit-string [bs]
  (let [[ok nb bs] (parse-length bs)]
    (if ok
      (let [pads (first bs)
            [octets bs] (if pads (grab (rest bs) (- nb 1)) (vector false bs))]
        (cond
          (not octets)
          (vector false "failed to read bitstring bytes" bs)
          (> pads 7)
          (vector false (str "invalid number of pad bits in bit string: " pads) bs)
          :else
          (vector ok (octets2bitstring octets pads) bs)))
      (vector false "invalid bitstring length" bs))))

(defn decode [bs]
  (let [tag (first bs)]
    (if tag
      (let [[ok class consp tagnum bs] (parse-identifier tag (rest bs))]
        (if ok
          (cond
            (and (= consp 0) (= tagnum tag-integer))
            ;; permissive: assumed universal
            (parse-integer bs)
            (and (= consp 0) (= tagnum tag-octet-string))
            (let [[ok len bs] (parse-length bs)]
              (if ok
                (let [[elems bs] (grab bs len)]
                  (if elems
                    (vector true (vector :octet-string (into [] elems)) bs)
                    (vector false "out of data reading octet string" bs)))
                (vector false len bs)))
            (and (= consp 0) (= tagnum tag-printable-string))
            (parse-printable-string bs)
            (and (= consp 0) (= tagnum tag-ia5string))
            (parse-ia5string bs)
            (and (= consp 0) (= tagnum tag-utfstring))
            (parse-utfstring bs)
            (and (= consp 0) (= tagnum tag-t61string))
            (parse-t61string bs)
            (and (= consp 0) (= tagnum tag-utc-time))
            (parse-utctime bs)
            ;; NOTE: no way to differentiate set and set-of (latter is sorted but sorted need not be set-of)
            (= tagnum tag-set)
            (let [[ok len bs] (parse-length bs)]
              (let [[seqbs bs] (grab bs len)]
                (if seqbs
                  (loop [seqbs seqbs out ()]
                    (let [[ok val seqbsp] (decode seqbs)]
                      (cond
                        ok (recur seqbsp (cons val out))
                        (empty? seqbs)
                        (vector true (into [] (cons :set (reverse out))) bs)
                        :else
                        (vector false
                                (str "error reading a set at position " (count out)
                                     (if (empty? out) "" (str " after " (first out)))
                                     ": " val)
                                seqbs))))
                  (vector false "out of data reading set length" bs))))
            (= tagnum tag-sequence)
            (let [[ok len bs] (parse-length bs)]
              (if ok
                (let [[seqbs bs] (grab bs len)]
                  (if seqbs
                    (loop [seqbs seqbs out ()]
                      (let [[ok val seqbsp] (decode seqbs)]
                        (cond
                          ok (recur seqbsp (cons val out))
                          (empty? seqbs)
                          (vector true (into [] (cons :sequence (reverse out))) bs)
                          :else
                          (vector false
                                  (str "error reading a sequence at position " (count out)
                                       (if (empty? out) "" (str " after " (first out)))
                                       ": " val)
                                  seqbs))))
                    (vector false "out of data reading sequence length" bs)))
                (vector false "could not read sequence length" bs)))
            (and (= consp 0) (= tagnum tag-bit-string))
            (parse-bit-string bs)
            (= tagnum tag-null)
            (let [len (first bs)]
              (if (= len 0)
                (vector true () (rest bs))
                (vector false "invalid byte after null tag" bs)))
            (= tagnum tag-boolean)
            (let [[len val & bs] bs]
              (cond
                (not (= len 1))
                (vector false (str "invalid boolan length: " len) bs)
                (= val 0)
                (vector true false bs)
                (= val 255)
                (vector true true bs)
                :else
                (vector false (str "wrong shade of gray for boolean truth: " val) bs)))
            (and (= class class-universal) (= tag tag-object-identifier))
            (parse-object-identifier bs)
            (= class class-context-specific)
            (let [[ok len bs] (parse-length bs)]
              (if ok
                (let [[ok val bs] (decode bs)]
                  (if ok
                    (vector true (vector :explicit tagnum val) bs)
                    (vector false (str "failed to read explicit content: " val) bs)))
                (vector false (str "failed to read explicit: " len) bs)))
            :else
            (vector false (str "Unknown identifier tag: " tagnum ", constructed " consp ", class " class) bs))
          (vector false (str "Failed to read identifier: " class) bs)))
      (vector false "no input" bs))))

(defn asn1-decode [bs]
  (let [[ok value bs] (decode bs)]
    (if ok
      (do
        (if (not (empty? bs))
          (println "Warning: " (count bs) " bytes of trailing garbage ignored after ASN.1 decoding"))
        value)
      (do
        (println "ERROR: ASN.1 decoding failed: " value)
        nil))))

;; a function for ast → binary → back to ast conversion, to check for differences introduced by encoding or decoding
(defn asn1-rencode [ast]
  (let
    [bs (asn1-encode ast)
     astp (asn1-decode bs)]
    (if (= ast astp)
      true
      (do
        (println "IN:  " ast)
        (println "OUT: " astp)
        (println "ENCODED: " bs)
        false))))

;(defn binary-slurp [x]
;  (with-open [out (java.io.ByteArrayOutputStream.)]
;    (clojure.java.io/copy (clojure.java.io/input-stream x) out)
;    (map (partial bit-and 255) (seq (.toByteArray out)))))

;(defn asn1-decode-file [path]
;  (println "reading " path)
;  (let [data (binary-slurp path)]
;    (println "read " (count data) " bytes")
;    (println path " -> " (asn1-decode data))))

; (asn1-decode-file "/home/aki/src/asn/asn.raw")




;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; ASN.1 AST utils
;;;

(defn tagged-as? [asn k]
  (and (vector? asn) (= (first asn) k)))

;; ASN.1 pattern matching
; :?         → match anything
; :keyword   → match [:keyword ...]
; 42         → match 42 (being [:integer 42])
; true/false → match corresponding boolean
; ()         → match null

(defn each-first [lst]
  (loop [left () lst lst opts ()]
    (if (empty? lst)
      opts
      (recur (cons (first lst) left)
             (rest lst)
             (cons (concat lst left) opts)))))

;; fuzzing note: degenerate inputs make this go exponential
(defn match-set [asts pats rec]
  (or (empty? pats)
      (some
        (fn [order] (match-set (rest order) (rest pats) rec))
        (filter
          (fn [x] (rec (first x) (first pats)))
          (each-first asts)))))

;; AST pattern → bool
(defn asn1-match? [asn pat]
   (cond
      (= pat :?)
         true
      (keyword? pat)
         (tagged-as? asn pat)
      (vector? pat)
         ;; todo: set order may vary
         (and
            (tagged-as? asn (first pat))
            (= (count asn) (count pat))
            (if (= (first pat) :set)
              (match-set (rest asn) (rest pat) asn1-match?)
              (every? (partial apply asn1-match?)
                      (rest (map vector asn pat)))))
    (number? pat)
       (= pat asn)
    (or (= pat true) (= pat false))
       (= pat asn)
    (= pat ())
       (= pat asn)
    (string? pat)
       (= pat asn)
    :else
      (fail (str "known asn1-match pattern node: " pat))))

(defn first-match [pred lst]
   (if (empty? lst)
      false
      (let [val (pred (first lst))]
         (if val val
            (recur pred (rest lst))))))

(defn asn1-find-matches [asn pat rout]
   (if (vector? asn)
      (let [rout (reduce (fn [rout asn] (asn1-find-matches asn pat rout)) rout asn)]
         (if (asn1-match? asn pat)
            (cons asn rout)
            rout))
      rout))

;; AST pattern → AST' ∊ AST ∨ nil
(defn asn1-find-left-dfs [asn pat]
   (cond
      (asn1-match? asn pat)
         asn
      (vector? asn)
         (or (first-match (fn [x] (asn1-find-left-dfs x pat)) (rest asn)) nil)
      :else
         nil))

;; AST pattern → [matching-subast ...], depth first, left to right
(defn asn1-matches [asn pat]
   (reverse (asn1-find-matches asn pat ())))

(def asn1-find
  asn1-find-left-dfs)


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;,
;;;
;;; Quoted-printable
;;;

(defn hexval [a]
  "ascii value -> integer (denoting 4 bits) | nil"
  (cond
    (< 47 a 58) (- a 48)                                    ;; 0-9
    (< 96 a 103) (- a 87)                                   ;; a-z
    (< 64 a 71) (- a 55)                                    ;; A-Z
    :else nil))

(defn quoted-printable-decode
  "decode quoted printable encoding in character sequence, nil if invalid data"
  [data]
  (loop [data data out ()]
    (let [[c & data] data]
      (cond
        (= c \=)
        (let [[a b & data] data]
          (cond
            (nil? b)
            nil
            (and (= a \return) (= b \newline))
            (recur data out)
            :else
            (let [na (hexval (int a)) nb (hexval (int b))]
              (if (and na nb)
                (recur data
                       (cons (char (bit-or (bit-shift-left na 4) nb)) out))
                (do
                  ;(println "Invalid quoted printable: '=" a " " b "' = " (int a) ", " (int b) " -> " (list na nb))
                  ;(println (take 100 data))
                  nil)))))
        (nil? c)
        (reverse out)
        :else
        (recur data (cons c out))))))



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;,
;;;
;;; Base64 decoder
;;;

;; (int \A) = 65, (char 65) = \A

;; 0-25 = A-Z
;; 26-51 = a-z
;; 52-61 = 0-9
;; 62 = +
;; 63 = /
;; __ = =

(defn base64-value [c]
  (cond
    (and (<= 48 c) (< c 58))
    (+ c 4)                                                 ;; 0-9, 52 + (c - 48) = c + 4
    (and (<= 65 c) (< c 91))
    (- c 65)                                                ;; A-Z
    (and (<= 97 c) (< c 123))
    (- c 71)                                                ;; a-z, 26 + (c - 97) = c - 71
    (= c 43)
    62                                                      ; +
    (= c 47)
    63                                                      ; /
    (= c 61)
    :end
    (or (= c 10) (= c 13))
    :skip                                                   ;; = \r \n
    :else
    (do
      (println "Invalid byte in base64 decoding: " c)
      :bad)))

(defn base64-finish [val state out]
  (if (= val 0)
    (reverse out)
    nil))

;            0     1    2     3    decoder states
; bits    |----||----||----||----| from base64 values
;         |      ||      ||      |
; output  '------''------''------' to output
;            0        1      2     encoder states

(defn base64-decode-raw [data]
  (loop [data data state 0 val 0 out ()]
    (let [[v & data] data]
      (cond
        (= v :skip)
        (recur data state val out)
        (= v :bad)
        nil
        (= v :end)
        (base64-finish val state out)
        (nil? v)
        (base64-finish val state out)
        (= state 0)
        (recur data 1 (bit-shift-left v 2) out)
        (= state 1)
        (let [lo2 (bit-shift-right v 4)
              hi4 (bit-and v 15)]
          (recur data 2
                 (bit-shift-left hi4 4)
                 (cons (bit-or val lo2) out)))
        (= state 2)
        (let [lo4 (bit-shift-right v 2)
              hi2 (bit-and v 3)]
          (recur data 3
                 (bit-shift-left hi2 6)
                 (cons (bit-or val lo4) out)))
        :else
        (recur data 0 0
               (cons (bit-or val v) out))))))

(defn base64-decode-octets [instr]
  (base64-decode-raw (map base64-value (map char2ascii instr))))

(defn base64-decode [instr]
  (let [res (base64-decode-octets instr)]
    (if res (apply str (map char res)) nil)))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;,
;;;
;;; Base64 encoder
;;;

;; digit in range → char in encoding
(defn base64-digit [b]
  (cond
    (= b \=) b
    (== b (bit-and b 63))
    (char
      (cond
        (< b 26) (+ b 65)
        (< b 52) (+ b 71)
        (< b 62) (- b 4)
        (= b 62) 43
        :else 47))
    :else
    (do
      (println "Bad base64 digit: " b)
      false)))

(defn base64-encode-bytes [l]
  (loop [l l out (list)]
    (let [[a b c & l] l]
      (cond
        (nil? a)
        (reverse out)
        (nil? b)
        (reverse (concat (list \= \=
                               (bit-and 63 (bit-shift-left (bit-and a 3) 4)) ;; low 2 bits
                               (bit-shift-right a 2))       ;; top 6 bits
                         out))
        (nil? c)
        (reverse
          (concat (list \=
                        (bit-and 63 (bit-shift-left b 2))   ;; low 2
                        (bit-and 63 (bit-or (bit-shift-left a 4) (bit-shift-right b 4))) ;; low 2 + top 4
                        (bit-shift-right a 2))              ;; top 6 bits
                  out))
        :else
        (recur l
               (cons (bit-and c 63)
                     (cons (bit-and 63 (bit-or (bit-shift-left b 2) (bit-shift-right c 6)))
                           (cons (bit-and 63 (bit-or (bit-shift-left a 4) (bit-shift-right b 4))) ;; low 2 + top 4
                                 (cons (bit-shift-right a 2) ;; top 6 bits
                                       out)))))))))

(defn base64-encode [input]
  (cond
    (string? input)
    (apply str (map base64-digit (base64-encode-bytes (string2bytes input))))
    (seq? input)
    (apply str (map base64-digit (base64-encode-bytes input)))
    (vector? input)
    (apply str (base64-encode-bytes input))
    :else
    (fail "How should I base64-encode " input " of type " (type input) "?")))

(defn base64-rencode [in]
  (let
    [encd (base64-encode in)
     out (base64-decode-octets encd)]
    (if (= in out)
      true
      (do
        (println "Base64 error: input " in)
        (println "             output " out)
        (println "            encoded " encd)
        false))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;,
;;
;; Hex encoding
;;

(defn hex-char [n]
  (nth [48 49 50 51 52 53 54 55 56 57 97 98 99 100 101 102] n))

(def hex-bits
   (let [bits (reduce (fn [out x] (assoc out x (- x 48))) {} (range 48 58))
         bits (reduce (fn [out x] (assoc out x (- (+ x 10) 97))) bits (range 97 103))
         bits (reduce (fn [out x] (assoc out x (- (+ x 10) 65))) bits (range 65 71))]
      bits))

(defn hex-encode [bs]
   (loop [bs bs out ()]
      (if (empty? bs)
         (reverse out)
         (let [x (first bs)]
            (recur (rest bs)
               (cons (hex-char (bit-and x 15))
                  (cons (hex-char (bit-and (bit-shift-right x 4) 15)) out)))))))

(defn hex-decode [chars]
   (if (even? (count chars))
      (let [bits (map (comp hex-bits char2ascii) chars)]
         (if (every? (fn [x] x) bits)
            (map (fn [[a b]] (+ (* a 16) b)) (partition 2 bits))
            nil))
      nil))



;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;,
