CFLAGS := -ansi -pedantic -Wall -Wextra -Werror

TEST_DEVLOG := test_devlog

all:			\
	$(TEST_DEVLOG)

$(TEST_DEVLOG):
		@echo ""
		$(CC) $(CFLAGS) -o $@ ./tests/devlog.c ./eslib_log.c ./eslib_proc.c

clean:
	rm -fv $(TEST_DEVLOG)
	@echo cleaned.
