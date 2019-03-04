# Fuzz testing
Simple fuzz testing of the function *cn_cbor_decode* and *cn_cbor_decode*. Based on the code in **cbor_test.c**.

## libFuzzer
There are four configurations:
* libfuzzer_asan: With adress sanitizer
* libfuzzer_msam: With memory sanitizer
* libfuzzer_ubsan: With undefined behaviour sanitizer
* libfuzzer: No sanitizer
```sh
$ make libfuzzer_asan
$ ./libfuzzer_asan.out seed
```

## American Fuzzy Lop (AFL)
```sh
# Chose afl-gcc or afl-clang
$ CC=afl-gcc make afl
$ afl-fuzz -i seed -o output ./afl.out
```
