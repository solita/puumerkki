(ns puumerkki.bigint
  (:refer-clojure :exclude [bigint bit-shift-left bit-shift-right bit-and bit-or])
  #?(:cljs (:require-macros [puumerkki.bigint :refer [-bit-shift-left
                                                      -bit-shift-right
                                                      -bit-and
                                                      -bit-or]])))

(defmacro -bit-shift-left [x n]
  (list 'js* "~{} << ~{}" x n))

(defmacro -bit-shift-right [x n]
  (list 'js* "~{} >> ~{}" x n))

(defmacro -bit-and [x y]
  (list 'js* "~{} & ~{}" x y))

(defmacro -bit-or [x y]
  (list 'js* "~{} | ~{}" x y))

(defn bigint [x]
  #?(:cljs (js/BigInt x)
     :clj (biginteger x)))

(defn bigint? [x]
  #?(:cljs (= (type x) js/BigInt)
     :clj (instance? BigInteger x)))

(defn ->int [x]
  #?(:cljs (js/parseInt x)
     :clj (int x)))

(defn bit-shift-left [x n]
  #?(:cljs (-bit-shift-left x (bigint n))
     :clj (.shiftLeft x n)))

(defn bit-shift-right [x n]
  #?(:cljs (-bit-shift-right x (bigint n))
     :clj (.shiftRight x n)))

(defn bit-and [x y]
  #?(:cljs (-bit-and x y)
     :clj (.and x y)))

(defn bit-or [x y]
  #?(:cljs (-bit-or x y)
     :clj (.or x y)))
