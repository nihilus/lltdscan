#
#   Author Markus Gothe <nietzsche@lysator.liu.se>
#

## Process this file with automake to produce Makefile.in

AUTOMAKE_OPTIONS = gnu 1.11 check-news dist-bzip2 std-options subdir-objects
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

#libtool 2.x
LIBTOOL_DEPS = @LIBTOOL_DEPS@
libtool: $(LIBTOOL_DEPS)
		$(SHELL) ./config.status libtool

LIBLTDLDIR = $(LTDLOPEN)
SUBDIRS = ${LIBLTDLDIR} lib

man_MANS = lltdscan.8
EXTRA_DIST = autogen.sh m4/gnulib-cache.m4

#don't install headers  
noinst_HEADERS =
#don't install autogen.sh
noinst_SCRIPT = autogen.sh
#don't install unnecessary libs.
noinst_LTLIBRARIES =

MAINTAINERCLEANFILES = Makefile.in lib/Makefile.in

