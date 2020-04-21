
;;; ASN.1 encoding / known values

(ns puumerkki.codec-test
  (:require [clojure.test :refer :all]
            [codec.core :refer :all]))

(deftest asn1-known
  (testing "Known ASN.1 encodings"
    (is (= (to-8bit-digits 111111111111111) 
              [101 14 18 78 241 199]))
    (is (= (bignum 127) 
              [127]))
    (is (= (bignum 1111111111111111111) 
              [143 181 221 181 178 222 145 227 71]))
    (is (= (encode-object-identifier (list 1 2 3 4)) 
              [6 3 42 3 4]))
    (is (= (encode-object-identifier (list 1 2 840 113549 1 1 1)) 
              [6 9 42 134 72 134 247 13 1 1 1]))
    (is (= (bitstring2bytes "1111111100000000111100000000111100000001") 
              [255 0 240 15 1]))
    (is (= (encode-bitstring "1010111111111000000001111000010101") 
              [3 6 6 175 248 7 133 64]))
    (is (= (encode-ia5string "Hello, world!") 
              [22 13 72 101 108 108 111 44 32 119 111 114 108 100 33]))
    (is (= (encode-octet-string (list 0 1 2 127 128 255))
              [4 6 0 1 2 127 128 255]))
    (is (= (encode-sequence encode-null encode-null encode-null)
              [48 6 5 0 5 0 5 0]))
    (is (= (encode-set (encode-integer 3) (encode-integer 1) (encode-integer 2))
              [49 9 2 1 3 2 1 1 2 1 2]))
    (is (= (encode-set-of (encode-integer 3) (encode-integer 1) (encode-integer 2))
              [49 9 2 1 1 2 1 2 2 1 3]))
    (is (= (encode-explicit 1 (encode-sequence (encode-object-identifier (list 1 2 3)) (encode-integer 42) encode-null))
              [161 11 48 9 6 2 42 3 2 1 42 5 0]))
    (is (= (encode-utc-time "200630093839Z")
              [23 13 50 48 48 54 51 48 48 57 51 56 51 57 90]))
    (is (= (encode-printable-string "Clojutre")
              [19 8 67 108 111 106 117 116 114 101]))))

(deftest asn1-dsl
  (testing "AST -> known ASN.1 (DER)"
    (is (= [48 45 6 3 42 3 4 160 16 49 6 2 1 2 2 1 1 49 6 2 1 1 2 1 2 19 3 102 111 111 23 13 50 48 48 54 51 48 48 57 51 56 51 57 90 5 0]
           (asn1-encode
            [:sequence
              [:identifier 1 2 3 4]
              [:explicit 0
                [:set 2 1]
                [:set-of 2 1]]
              "foo"
              [:utctime "200630093839Z"]
              ()])))
    (is (= [4 10 4 8 2 6 10 27 1 212 177 199]
          (asn1-encode
            [:encapsulated-octet-string
              [:encapsulated-octet-string 11111111111111]])))
    (is (= [3 7 0 2 4 66 58 53 199]
          (asn1-encode
              [:encapsulated-bitstring 1111111111])))))


;;; ASN.1 AST -> bytes -> AST' equality comparisons

(deftest asn-rencode
  (testing "AST -> ASN.1 (DER) -> AST"
    (is (asn1-rencode 0))
    (is (asn1-rencode 127))
    (is (asn1-rencode 128))
    (is (asn1-rencode 255))
    (is (asn1-rencode 256))
    (is (asn1-rencode 65535))
    (is (asn1-rencode 65536))
    (is (asn1-rencode 11111111111111))

    (is (asn1-rencode [:octet-string (list)]))
    (is (asn1-rencode [:octet-string (list 1)]))
    (is (asn1-rencode [:octet-string (list 0 1 1 0 1 1 1 0 0 1 0 1 1 1 0 1 1 1 1 0 0 0)]))

    (is (asn1-rencode [:sequence]))
    (is (asn1-rencode [:sequence 1]))
    (is (asn1-rencode [:sequence 1 2]))
    (is (asn1-rencode [:sequence 1 2 3 4 5 6]))
    (is (asn1-rencode [:sequence [:sequence 1 2] [:sequence 3 4 5] 6]))

    (is (asn1-rencode [:printable-string "Hello, world!"]))
    (is (asn1-rencode [:printable-string "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]))
    (is (asn1-rencode [:ia5string "foo@bar.com"]))

    (is (asn1-rencode [:set 1 2 3 4]))
    (is (asn1-rencode [:set [:set [:set 1 [:sequence 2 [:set 3 4]]]]]))

    (is (asn1-rencode [:explicit 0 42]))
    (is (asn1-rencode [:explicit 30 [:explicit 31 [:explicit 31337 1111111111111]]]))

    (is (asn1-rencode ()))

    (is (asn1-rencode [:identifier 1 2 3]))
    (is (asn1-rencode [:identifier 1 2 31337]))
    (is (asn1-rencode [:identifier 1 2 840 113549 1 1 1]))
    (is (asn1-rencode [:sequence [:identifier 1 2 840 113549 1 1 1] ()]))

    (is (asn1-rencode [:utctime "200630093839Z"]))

    (is (asn1-rencode [:bit-string ""]))
    (is (asn1-rencode [:bit-string "0"]))
    (is (asn1-rencode [:bit-string "1"]))
    (is (asn1-rencode [:bit-string "10000000"]))
    (is (asn1-rencode [:bit-string "0000000010000000"]))
    (is (asn1-rencode [:bit-string "0000000100000000"]))
    (is (asn1-rencode [:bit-string "110100100010000100000100000010000000110100100010000100000100000010000000"]))

    (is (asn1-rencode [:sequence [:bit-string ""] [:bit-string "0"] [:bit-string "1"] [:bit-string "00"] [:bit-string "01"] [:bit-string "10"] [:bit-string "11"] [:bit-string "000"] [:bit-string "001"] [:bit-string "010"] [:bit-string "011"] [:bit-string "100"] [:bit-string "101"] [:bit-string "110"] [:bit-string "111"]]))

    (is (asn1-rencode [:sequence true false]))

    (is (asn1-rencode [:explicit 0 [:sequence [:set [:explicit 0 [:explicit 0 [:sequence [:explicit 0 [:sequence [:explicit 0 [:sequence [:explicit 0 [:sequence [:explicit 0 [:sequence [:set [:set [:set [:set [:set [:sequence [:set 1 2 3 4 1 3 4]]]]]]]]]]] [:explicit 0 [:explicit 0 [:sequence [:explicit 0 [:sequence [:explicit 0 [:sequence [:explicit 0 [:sequence [:explicit 0 [:sequence [:set [:set [:set 1 4 4 1111111111111111111 1 1 1 11 11111111111111 [:printable-string "fooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo"]]]]]]]]]]]]]]]]]]]]]]]]]))))


;;; ASN.1 pattern matching

(deftest asn-pat 
  (testing "ASN.1 AST node pattern matching and utilities"
    (is (= true  (asn1-match? [:foo "foo"] :foo)))
    (is (= false (asn1-match? [:foo "foo"] :bar)))
    (is (= nil (asn1-find [:foo [:foo "foo"]] :bar)))
    (is (= [:bar "foo"] (asn1-find [:foo [:bar "foo"]] :bar)))
    (is (= [:bar [:baz "here"]] (asn1-find [:not [:here] [:bar "almost"] [:bar [:baz "here"]]] [:bar :baz])))
    (is (= true (asn1-match? [:foo 31337 () 42 [:bar] true false] [:foo :? () 42 :bar true false])))

    (is (= true (asn1-match? [:set 1 2 3] [:set 3 1 2])))
    
    (is (= true (asn1-match? [:set 1 1] [:set 1 1])))

    (is (= true (asn1-match? [:set [:set 1 2] [:set 1 2 3] [:set 1 2 4]] 
                             [:set [:set :? 1 2] :? [:set 3 2 1]]))) ;; first has 2 options, middle 3, last one
))


;;; Base64

(deftest b64
  (testing "Base64 known decoding"
    (is (= (base64-decode "") 
      ""))
    (is (= (base64-decode "YQ==") 
      "a"))
    (is (= (base64-decode "YWI=")
           "ab"))
    (is (= (base64-decode "YWJj")
           "abc"))
    (is (= (base64-decode "YWJjZA==")
           "abcd"))
    (is (= (base64-decode "T3BlbiB0aGUgcG9kIGJheSBkb29ycyBwbGVhc2UgSEFMIQo=")
           "Open the pod bay doors please HAL!\n"))))

(deftest b64-dencode
   (testing "Base64 binary encode + decode"
      (is (base64-rencode (list)))
      (is (base64-rencode (list 1)))
      (is (base64-rencode (list 2)))
      (is (base64-rencode (list 4)))
      (is (base64-rencode (list 8)))
      (is (base64-rencode (list 16)))
      (is (base64-rencode (list 32)))
      (is (base64-rencode (list 64)))
      (is (base64-rencode (list 128)))
      (is (base64-rencode (list 0 1)))
      (is (base64-rencode (list 0 2)))
      (is (base64-rencode (list 0 4 )))
      (is (base64-rencode (list 0 8)))
      (is (base64-rencode (list 0 16)))
      (is (base64-rencode (list 0 32)))
      (is (base64-rencode (list 0 64)))
      (is (base64-rencode (list 0 128)))
      (is (base64-rencode (list 0 0 1)))
      (is (base64-rencode (list 0 0 2)))
      (is (base64-rencode (list 0 0 4 )))
      (is (base64-rencode (list 0 0 8)))
      (is (base64-rencode (list 0 0 16)))
      (is (base64-rencode (list 0 0 32)))
      (is (base64-rencode (list 0 0 64)))
      (is (base64-rencode (list 0 0 128)))
      (is (base64-rencode (apply list (range 0 256))))
      (is (base64-rencode (apply list (concat (range 0 256) (range 0 256) (remove even? (range 0 200)) (remove odd? (range 1 150)) (range 255 0)))))
))

