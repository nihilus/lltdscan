#/*
#    Copyright (C) 2015, Markus Gothe <nietzsche@lysator.liu.se>
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as
#    published by the Free Software Foundation, either version 3 of the
#    License, or (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>. 
#*/

## Process this file with automake to produce Makefile.in

AUTOMAKE_OPTIONS = gnu 1.15 check-news dist-bzip2 std-options subdir-objects

ACLOCAL_AMFLAGS = -I m4
AM_CFLAGS = -I lib $(INCLS) $(CFLAGS) $(V_CCOPT) $(V_INCLS) $(NETINC) $(LTDLINCL)
AM_CPPFLAGS = -I lib $(INCLS) $(CFLAGS) $(V_CCOPT) $(V_INCLS) $(NETINC) $(LTDLINCL)
AM_LDFLAGS = $(LIBLTDL) $(top_srcdir)/lib/libgnu.la -export-dynamic

# Yacc / Flexx
#AM_YFLAGS =
#AM_LFLAGS =

## What programs do we want to build?

bin_PROGRAMS = lltdscan$(EXEEXT)
sbin_PROGRAMS =
EXTRA_PROGRAMS = 

# Sources
lltdscan_SOURCES = lltdscan.c

# Dependencies
lltdscan_DEPENDENCIES = $(V_PCAPDEP)
lltdscan_LDFLAGS = $(AM_LDFLAGS) -L./lib -no-undefined

#libtool 2.x
LIBTOOL_DEPS = @LIBTOOL_DEPS@
libtool: $(LIBTOOL_DEPS)
		$(SHELL) ./config.status libtool

LIBLTDLDIR = $(LTDLOPEN)
SUBDIRS = ${LIBLTDLDIR} lib

# What libararies do we want to build?

EXTRA_LTLIBRARIES =
lib_LTLIBRARIES =

# What libs do we want to link against?
LDADD =
lltdscan_LDADD = $(LIBLTDL) $(top_srcdir)/lib/libgnu.la 

#don't install headers  
noinst_HEADERS =
#don't install autogen.sh
noinst_SCRIPT = autogen.sh
#don't install unnecessary libs.
noinst_LTLIBRARIES =

# Autogenerated files.
BUILT_SOURCES =

# What documentation should we include?
man_MANS = lltdscan.8
EXTRA_DIST = autogen.sh m4/gnulib-cache.m4

## Extra stuff to remove when cleaning
MAINTAINERCLEANFILES = Makefile.in lib/Makefile.in
DISTCLEANFILES = 
