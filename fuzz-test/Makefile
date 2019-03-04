

CFLAGS = -Wall -Wextra -Werror
INCLUDES = -I../include
SRCS = cbor_libfuzzer.c ../src/cn-cbor.c ../src/cn-encoder.c
DEPS = ../include/cn-cbor/cn-cbor.h ../src/cbor.h Makefile

libfuzzer: CFLAGS += -fsanitize=fuzzer -g -O1
libfuzzer: $(DEPS) $(SRCS)
	clang $(CFLAGS) $(INCLUDES) $(SRCS) -o $@.out

libfuzzer_asan: CFLAGS += -fsanitize=fuzzer,address -g -O1
libfuzzer_asan: $(DEPS) $(SRCS)
	clang $(CFLAGS) $(INCLUDES) $(SRCS) -o $@.out

libfuzzer_msan: CFLAGS += -fsanitize=fuzzer,memory -g -O1
libfuzzer_msan: $(DEPS) $(SRCS)
	clang $(CFLAGS) $(INCLUDES) $(SRCS) -o $@.out

libfuzzer_ubsan: CFLAGS += -fsanitize=fuzzer,signed-integer-overflow -g -O1
libfuzzer_ubsan: $(DEPS) $(SRCS)
	clang $(CFLAGS) $(INCLUDES) $(SRCS) -o $@.out

debug: CFLAGS += -g -ggdb -O0 -DDEBUG -fsanitize=address -fno-omit-frame-pointer
debug:
	$(CC) $(CFLAGS) $(INCLUDES) $(SRCS) -o $@.out

afl: CFLAGS += -DDEBUG
afl:
	$(CC) $(CFLAGS) $(INCLUDES) $(SRCS) -o $@.out

clean:
	rm *.out
all: libfuzzer libfuzzer_asan libfuzzer_msan libfuzzer_ubsan debug
