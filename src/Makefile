HOME = ..
INCLUDE = $(HOME)/include
LIB_PATH = $(HOME)/lib
LIB = $(LIB_PATH)/libchkc.so
MAIN = $(HOME)/checkc
LIB_FLAGS = -fsanitize=address -g -I$(INCLUDE) -lssl
MAIN_FLAGS = -fsanitize=address -g -I$(INCLUDE) -lchkc -lcapstone
CC := gcc

all: $(LIB) $(MAIN)

$(LIB):
	$(CC) $(LIB_FLAGS) chk_file.c chk_kernel.c chk_proc.c format.c loader.c structs.c -shared -fPIC -o $(LIB)

$(MAIN):
	$(CC) $(MAIN_FLAGS) main.c -o $(MAIN) -L$(LIB_PATH)

install:
	install $(LIB) /usr/lib
	install $(MAIN) /usr/local/bin

clean:
	rm -f $(LIB) $(MAIN)
	rm -f /usr/lib/libchkc.so /usr/local/bin/checkc

