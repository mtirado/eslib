CFLAGS := -ansi -pedantic -Wall -Wextra -Werror -DNEWNET_IPVLAN -DNEWNET_MACVLAN

TEST_NETLINK := test_netlink
TEST_DEVLOG := test_devlog
TEST_PROC := test_proc

all:			\
	$(TEST_NETLINK) \
	$(TEST_DEVLOG)	\
	$(TEST_PROC)

$(TEST_NETLINK):
		@echo ""
		$(CC) $(CFLAGS) -o $@ ./tests/netlink.c ./eslib_rtnetlink.c
$(TEST_DEVLOG):
		@echo ""
		$(CC) $(CFLAGS) -o $@ ./tests/devlog.c ./eslib_log.c ./eslib_proc.c
$(TEST_PROC):
		@echo ""
		$(CC) $(CFLAGS) -o $@ ./tests/proc.c ./eslib_file.c ./eslib_proc.c

clean:
	rm -fv $(TEST_NETLINK)
	rm -fv $(TEST_DEVLOG)
	rm -fv $(TEST_PROC)
	@echo cleaned.
