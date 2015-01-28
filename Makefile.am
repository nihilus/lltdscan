#
#   Copyright (C) 2013, Dovado Europe AB
#
#   Author Markus Gothe <markus@dovado.com
#

## Process this file with automake to produce Makefile.in

AUTOMAKE_OPTIONS = foreign std-options
ACLOCAL_AMFLAGS = -I m4

##Linking
#noinst_LIBRARIES = libsunrise.a
#libsunrise_a_SOURCES = sunrise.c

## What programs do we want to build?

bin_PROGRAMS = sunrise$(EXEEXT)
sunrise_SOURCES = sunrise.c
sunrise_LDFLAGS = -all-static
#sunrise_LDADD = libsunrise.a
EXTRA_PROGRAMS = 


#libtool 2.x
LIBTOOL_DEPS = @LIBTOOL_DEPS@
libtool: $(LIBTOOL_DEPS)
		$(SHELL) ./config.status libtool
