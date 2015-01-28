#
#   Author Markus Gothe <nietzsche@lysator.liu.se>
#

## Process this file with automake to produce Makefile.in

AUTOMAKE_OPTIONS = gnu std-options
ACLOCAL_AMFLAGS = -I m4
AM_CFLAGS = $(INCLS) $(CFLAGS) $(V_CCOPT) $(V_INCLS) $(NETINC)
AM_LDFLAGS = $(LDFLAGS) 

##Linking
#noinst_LIBRARIES = liblltd.a
#liblltd_a_SOURCES = lltd.c

## What programs do we want to build?

bin_PROGRAMS = lltdscan$(EXEEXT)
lltdscan_SOURCES = lltdscan.c
lltdscan_DEPENDENCIES = $(V_PCAPDEP)
#lltdscan_LDFLAGS = -all-static
EXTRA_PROGRAMS = 


man_MANS = lltdscan.8

#libtool 2.x
LIBTOOL_DEPS = @LIBTOOL_DEPS@
libtool: $(LIBTOOL_DEPS)
		$(SHELL) ./config.status libtool
