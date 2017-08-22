dnl/*
dnl    Copyright (C) 2015 Markus Gothe <nietzsche@lysator.liu.se>
dnl
dnl    This program is free software: you can redistribute it and/or modify
dnl    it under the terms of the GNU General Public License as
dnl    published by the Free Software Foundation, either version 3 of the
dnl    License, or (at your option) any later version.
dnl
dnl    This program is distributed in the hope that it will be useful,
dnl    but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl    GNU General Public License for more details.
dnl
dnl    You should have received a copy of the GNU General Public License
dnl    along with this program.  If not, see <http://www.gnu.org/licenses/>.
dnl */

dnl Process this file with autoconf to produce a configure script.

dnl init autoconf
AC_REQ(2.69)
AC_INIT([lltdscanner],[0.1.1],[Markus Gothe nietzsche@lysator.liu.se])
AC_CONFIG_HEADERS([config.h:config.h.in])
AC_CONFIG_SRCDIR([lltdscan.c])
AC_CONFIG_AUX_DIR([.]) 
AC_REQUIRE_AUX_FILE([install-sh])
AC_CANONICAL_BUILD
AC_CANONICAL_HOST
AC_CANONICAL_TARGET

dnl macros for automake
AM_INIT_AUTOMAKE([gnu 1.15 check-news dist-bzip2 std-options subdir-objects])
AM_MAINTAINER_MODE
AC_PROG_MAKE_SET
AC_CONFIG_MACRO_DIR([m4])

dnl PCAP-setup
AC_LBL_C_INIT_BEFORE_CC(V_INCLS)

dnl Checks for programs.
AC_PROG_CC
AC_LBL_C_INIT(V_CCOPT, V_INCLS)
AC_LBL_C_INLINE
dnl /bin/ln -s
AC_PROG_LN_S
dnl /usr/bin/make
AC_PROG_MAKE_SET
dnl /usr/bin/install
AC_PROG_INSTALL
dnl /bin/mkdir -p
AC_PROG_MKDIR_P
dnl /usr/bin/yacc
AC_PROG_YACC
dnl /usr/bin/lex
AC_PROG_LEX
dnl /usr/bin/sed
AC_PROG_SED
dnl /usr/bin/grep
AC_PROG_GREP
dnl /usr/bin/awk
AC_PROG_AWK
dnl /usr/bin/doxygen
AC_PATH_PROG(DOXYGEN, doxygen, "")
AM_CONDITIONAL(CONFIG_DOXYGEN, [test ! -z "$DOXYGEN"])

dnl /usr/bin/rm
dnl AC_PROG_RM

dnl shared/static
dnl linking & ltdl
LT_PREREQ([2.4])
LT_CONFIG_LTDL_DIR([libltdl])
LT_INIT([dlopen win32-dll shared pic-only])
AC_SUBST(LIBTOOL_DEPS)
LTDL_INIT([convenience recursive])

DLOPEN="-dlopen"
DLPREOPEN="-dlpreopen"
AC_SUBST(DLOPEN)
AC_SUBST(DLPREOPEN)

dnl Substitute INCLTDL and LIBLTDL in the Makefiles
AC_SUBST(INCLTDL)
AC_SUBST(LIBLTDL)

AM_CONDITIONAL(CONVENIENCE_LTDL, test x"${enable_ltdl_convenience-no}" != xno)
AM_CONDITIONAL(INSTALL_LTDL, test x"${enable_ltdl_install-no}" != xno)

dnl Set it in C99-mode
AC_SYS_INTERPRETER
AC_USE_SYSTEM_EXTENSIONS

dnl gnulib
gl_EARLY
gl_INIT

AC_PROG_CC_C99
AC_PROG_CPP
AC_REQUIRE_CPP
AC_PROG_CC_C_O
AC_PROG_CXX
AC_C_FLEXIBLE_ARRAY_MEMBER
AC_C_VARARRAYS
AC_EXEEXT

dnl check for OpenMP
dnl AC_OPENMP


dnl Check for libpcap
AC_LBL_LIBPCAP(V_PCAPDEP, V_INCLS)

dnl Checks for (installed) libdnet
AC_MSG_CHECKING(for libdnet)
AC_ARG_WITH(libdnet,
[  --with-libnet=DIR      use libnet in DIR],
[ case "$withval" in
  yes|no)
     AC_MSG_RESULT(no)
     ;;
  *)
     AC_MSG_RESULT($withval)
     if test -f $withval/lib/libnet.a; then
        NETINC="-I$withval/include"
        NETLIB="-L$withval/lib -lnet `$withval/net-config --libs`"
     elif test -x $withval/bin/libnet-config; then
        NETINC="`$withval/bin/libnet-config --cflags`"
        NETLIB="`$withval/bin/libnet-config --libs`"
     else
        AC_ERROR(libnet-config not found in $withval/bin)
     fi
     ;;
  esac ],
[ 
  AC_PATH_TOOL(LIBNET_CONFIG, libnet-config)
  if test -n "$LIBNET_CONFIG" ; then
     NETINC="`"$LIBNET_CONFIG" --cflags`"
     NETLIB="`"$LIBNET_CONFIG" --libs`"
  else
     AC_MSG_RESULT(no)
     AC_ERROR(libnet not found)
  fi
  AC_MSG_RESULT(yes) ]
)
AC_SUBST(NETINC)
AC_SUBST(NETLIB)
LIBS="$LIBS $NETLIB"

AC_SEARCH_LIBS([strerror], [cposix])
AC_CHECK_LIB([socket], [socket])
AC_CHECK_LIB([rt], [aio_read])
AC_CHECK_LIB([rt], [signal])
AC_CHECK_LIB([nsl], [gethostbyname])
AC_CHECK_LIB([m], [pow])

dnl Standard socklen_t test
AC_MSG_CHECKING([for socklen_t])
AC_CACHE_VAL(ac_cv_type_socklen_t,
	[AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
		#include <sys/types.h>
		#include <sys/socket.h>]], [[socklen_t t;]])],[ac_cv_type_socklen_t=yes],[ac_cv_type_socklen_t=no])])
if test $ac_cv_type_socklen_t = no; then
	AC_DEFINE(socklen_t, int, Define to 'int' if <sys/socket.h> doesn't define.) dnl BSD-style
fi
AC_MSG_RESULT($ac_cv_type_socklen_t)

AC_CHECK_DECLS([sys_siglist],[],[],[#include <signal.h>
/* NetBSD declares sys_siglist in unistd.h.  */
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
])

dnl Define macros for getting sa_len for struct sockaddr in a compatible way.
AC_CHECK_MEMBER(struct sockaddr.sa_len,
[AC_DEFINE([GET_SA_LEN(X)],[(((struct sockaddr*)&(X))->sa_len)],[Length of specified struct sockaddr.])],
[AC_DEFINE([GET_SA_LEN(X)],[(((struct sockaddr*)&(X))->sa_family == AF_INET  ? sizeof(struct sockaddr_in) : ((struct sockaddr*)&(X))->sa_family == AF_INET6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr))],[Length of specified struct sockaddr.])],
[#include <sys/socket.h>])

dnl Check it is safe to include both <sys/time.h> and <time.h>.
AC_HEADER_TIME

AC_CHECK_HEADERS([sys/types.h sys/stat.h sys/socket.h netinet/in.h unistd.h signal.h stddef.h pthread.h netdb.h arpa/inet.h libintl.h malloc.h \
				OS.h fcntl.h float.h langinfo.h limits.h locale.h net/ethernet.h sys/file.h sys/ioctl.h sys/param.h sys/time.h wchar.h])
AC_HEADER_SYS_WAIT
AC_HEADER_STDBOOL
AC_HEADER_ASSERT

dnl For BSD and Solaris
AC_CHECK_HEADERS([net/if_dl.h net/dlil.h])

dnl Check for netinet/if_ether, courtsey of GNU Autoconf.
AC_CHECK_HEADERS([sys/socket.h])
AC_CHECK_HEADERS([netinet/if_ether.h], [], [],
	[#include <stdio.h>
   	 #ifdef STDC_HEADERS
     # include <stdlib.h>
     # include <stddef.h>
     #else
     # ifdef HAVE_STDLIB_H
     #  include <stdlib.h>
     # endif
     #endif
     #ifdef HAVE_SYS_SOCKET_H
     # include <sys/socket.h>
     #endif
])

dnl Check for LLADDR
AC_CHECK_TYPES([struct sockaddr_dl], [], [], [[#include <net/if_dl.h>]])
AC_CHECK_TYPES([struct sockaddr_dl], [], [], [[#include <net/dlil.h>]])

dnl Check for functions.
AC_CHECK_FUNCS([setlocale]) 
AC_CHECK_FUNCS([gettimeofday])
AC_CHECK_FUNCS([memset])
AC_CHECK_FUNCS([memmove])
AC_CHECK_FUNCS([strtoul])
AC_CHECK_FUNCS([strchr])
AC_CHECK_FUNCS([strrchr])
AC_CHECK_FUNCS([strstr])
AC_CHECK_FUNCS([socket])
AC_CHECK_FUNCS([signal])
AC_CHECK_FUNCS([daemon])
AC_CHECK_FUNCS([getifaddrs freeifaddrs])
AC_CHECK_FUNCS([strcasecmp])
AC_CHECK_FUNCS([getopt getopt_long])
AC_CHECK_FUNC([_Exit], [], AC_DEFINE(_Exit, _exit, Define _Exit as _exit IFF not found.))
AC_CHECK_FUNCS([strdup strndup memchr strnlen localeconv inet_addr inet_ntoa dup2 atexit mblen mbrlen memchr strerror])

AC_FUNC_MMAP
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_STRTOD
AC_FUNC_STRTOLD
AC_FUNC_FORK

dnl check if types are defined.
AC_TYPE_SIZE_T
AC_TYPE_OFF_T
AC_TYPE_UID_T
AC_FUNC_FSEEKO

dnl C checks
AC_C_CONST
AC_C_RESTRICT
AC_C_VOLATILE
AC_C_INLINE
AC_C_TYPEOF
AC_C_CHAR_UNSIGNED
AC_C_STRINGIZE
AC_C_BIGENDIAN
AC_FUNC_SELECT_ARGTYPES

dnl Check for a C object stack.
AC_FUNC_OBSTACK

dnl GNU-charactaristics
AC_CHECK_FUNCS([__builtin_unreachable])
AC_SYS_POSIX_TERMIOS
AC_SYS_LARGEFILE
AC_SYS_LONG_FILE_NAMES
AC_FUNC_STRERROR_R
AC_TYPE_UINTPTR_T
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT8_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T


AC_FUNC_MBRTOWC
AC_CHECK_TYPES([ptrdiff_t])
AC_CHECK_MEMBERS([struct stat.st_rdev])

dnl AC_IRIX_SUN
AC_FUNC_GETMNTENT
AC_CHECK_LIB([sun], [getpwnam])
AC_CHECK_LIB([bsd], [getprogname])

dnl subst
AC_SUBST(V_CCOPT)
AC_SUBST(V_DEFS)
AC_SUBST(V_INCLS)
AC_SUBST(V_PCAPDEP)

AC_CONFIG_FILES([Makefile libltdl/Makefile lib/Makefile])
AC_OUTPUT
