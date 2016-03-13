CFLAGS := -ansi -pedantic -Wall -Wextra -Werror

TEST_DEVLOG := test_devlog
TEST_PROC := test_proc

all:			\
	$(TEST_DEVLOG)	\
	$(TEST_PROC)

$(TEST_DEVLOG):
		@echo ""
		$(CC) $(CFLAGS) -o $@ ./tests/devlog.c ./eslib_log.c ./eslib_proc.c

$(TEST_PROC):
		@echo ""
		$(CC) $(CFLAGS) -o $@ ./tests/proc.c ./eslib_file.c ./eslib_proc.c
clean:
	rm -fv $(TEST_DEVLOG)
	rm -fv $(TEST_PROC)
	@echo cleaned.
