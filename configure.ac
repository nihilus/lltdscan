dnl
dnl   Author Markus Gothe <nietzsche@lysator.liu.se>
dnl

dnl Process this file with autoconf to produce a configure script.

dnl init autoconf
AC_REQ(2.63)
AC_INIT([lltdscanner],[0.1.1],[Markus Gothe nietzsche@lysator.liu.se])
AC_CONFIG_HEADERS([config.h:config.h.in])
AC_CONFIG_SRCDIR([lltdscan.c])
AC_CONFIG_AUX_DIR([.]) 
AC_REQUIRE_AUX_FILE([install-sh])
AC_CANONICAL_BUILD
AC_CANONICAL_HOST
AC_CANONICAL_TARGET

dnl macros for automake
dnl AM_INIT_AUTOMAKE([gnu 1.11 check-news dist-bzip2 std-options subdir-objects])
AM_MAINTAINER_MODE
AC_PROG_MAKE_SET
AC_CONFIG_MACRO_DIR([m4])


dnl PCAP-setup
AC_LBL_C_INIT_BEFORE_CC(V_INCLS)

dnl Checks for programs.
AC_PROG_CC
AC_LBL_C_INIT(V_CCOPT, V_INCLS)
AC_LBL_C_INLINE
AC_PROG_CXX
AC_PROG_AWK
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET

dnl macros for automake
AM_INIT_AUTOMAKE([foreign std-options])
AC_CONFIG_MACRO_DIR([m4])

dnl shared/static
LT_PREREQ([2.2])
LT_INIT([disable-shared])
AC_SUBST(LIBTOOL_DEPS)

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
AC_EXEEXT

AC_HEADER_STDC
AC_HEADER_TIME
AC_CHECK_HEADERS([stdlib.h sys/time.h])
dnl Check for libmath
AC_CHECK_LIB([m],[cos])

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

dnl check if types are defined.
AC_TYPE_SIZE_T
AC_TYPE_OFF_T
AC_TYPE_UID_T
AC_FUNC_FSEEKO

AC_FUNC_STRTOD
AC_FUNC_STRTOLD
AC_STRUCT_TM 
AC_FUNC_MKTIME
AC_CHECK_FUNCS([floor])

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

dnl subst
AC_SUBST(V_CCOPT)
AC_SUBST(V_DEFS)
AC_SUBST(V_INCLS)
AC_SUBST(V_PCAPDEP)

AC_CONFIG_FILES([lib/Makefile Makefile])
AC_OUTPUT
