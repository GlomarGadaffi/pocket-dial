# Builds pjsip_check against a built pjproject tree, the way pjproject's own
# docs say an external app should: include its build.mak and use APP_*.
#   make -C tests/conformance PJDIR=$HOME/pjproject OUT=<dir>/pjsip_check
PJDIR ?= $(HOME)/pjproject
OUT   ?= pjsip_check
include $(PJDIR)/build.mak

$(OUT): pjsip_check.c $(PJDIR)/build.mak
	$(CC) -o $@ $< $(APP_CFLAGS) $(APP_LDFLAGS) $(APP_LDLIBS)

