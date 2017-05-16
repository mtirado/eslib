CFLAGS := -ansi -pedantic -Wall -Wextra -Werror -DNEWNET_IPVLAN -DNEWNET_MACVLAN

TEST_NETLINK := test_netlink
TEST_DEVLOG := test_devlog
TEST_PROC := test_proc
TEST_FILE := test_file
TEST_FORTIFY_INHERITABLE := test_fortify_inheritable

all:					\
	$(TEST_NETLINK) 		\
	$(TEST_DEVLOG)			\
	$(TEST_PROC)			\
	$(TEST_FILE)			\
	$(TEST_FORTIFY_INHERITABLE)
# TODO .o targets? meh
$(TEST_NETLINK):
		@echo ""
		$(CC) $(CFLAGS) -o $@ ./tests/netlink.c ./eslib_rtnetlink.c
$(TEST_DEVLOG):
		@echo ""
		$(CC) $(CFLAGS) -o $@ ./tests/devlog.c ./eslib_log.c ./eslib_proc.c
$(TEST_PROC):
		@echo ""
		$(CC) $(CFLAGS) -o $@ ./tests/proc.c ./eslib_file.c ./eslib_proc.c
$(TEST_FORTIFY_INHERITABLE):
		@echo ""
		$(CC) $(CFLAGS) -o $@ ./tests/fortify_inheritable.c ./eslib_fortify.c ./eslib_file.c ./eslib_proc.c
$(TEST_FILE):
		@echo ""
		$(CC) $(CFLAGS) -o $@ ./tests/file.c ./eslib_file.c
#TODO more foritfy tests
clean:
	rm -fv $(TEST_NETLINK)
	rm -fv $(TEST_DEVLOG)
	rm -fv $(TEST_PROC)
	rm -fv $(TEST_FILE)
	rm -fv $(TEST_FORTIFY_INHERITABLE)
	@echo cleaned.
