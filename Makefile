CC = $(CROSS)$(TARGET)gcc
STRIP = $(CROSS)$(TARGET)strip
CFLAGS = -ggdb -Wall -Wextra -Wshadow -Wformat-security -Wno-strict-aliasing -O2
RM = /bin/rm -f
Q = @

LIBS = -lpthread
FUNCS_DIR = libfuncs
FUNCS_LIB = $(FUNCS_DIR)/libfuncs.a

tomcast_OBJS =  tomcast.o $(FUNCS_LIB)

all: tomcast

$(FUNCS_LIB):
	$(Q)echo "  MAKE	$(FUNCS_LIB)"
	$(Q)$(MAKE) -s -C $(FUNCS_DIR)

tomcast: $(tomcast_OBJS)
	$(Q)echo "  LINK	tomcast"
	$(Q)$(CC) $(CFLAGS) $(tomcast_OBJS) $(LIBS) -o tomcast

%.o: %.c
	$(Q)echo "  CC	tomcast		$<"
	$(Q)$(CC) $(CFLAGS)  -c $<

strip:
	$(Q)echo "  STRIP	tomcast"
	$(Q)$(STRIP) tomcast

clean:
	$(Q)echo "  RM	$(tomcast_OBJS)"
	$(Q)$(RM) $(tomcast_OBJS) tomcast *~

distclean: clean
	$(Q)$(MAKE) -s -C $(FUNCS_DIR) clean
