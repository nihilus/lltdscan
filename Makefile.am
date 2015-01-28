#
#   Author Markus Gothe <nietzsche@lysator.liu.se>
#

## Process this file with automake to produce Makefile.in

AUTOMAKE_OPTIONS = foreign std-options
ACLOCAL_AMFLAGS = -I m4

##Linking
#noinst_LIBRARIES = liblltd.a
#libsunrise_a_SOURCES = lltd.c

## What programs do we want to build?

bin_PROGRAMS = sunrise$(EXEEXT)
sunrise_SOURCES = lltdscanner.c
#sunrise_LDFLAGS = -all-static
#sunrise_LDADD = liblltd.a
EXTRA_PROGRAMS = 


#libtool 2.x
LIBTOOL_DEPS = @LIBTOOL_DEPS@
libtool: $(LIBTOOL_DEPS)
		$(SHELL) ./config.status libtool
