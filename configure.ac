dnl
dnl   Author Markus Gothe <nietzsche@lysator.liu.se>
dnl

dnl Process this file with autoconf to produce a configure script.

dnl init autoconf
AC_REQ(2.63)
AC_INIT([lltdscanner],[0.1.1],[Markus Gothe nietzsche@lysator.liu.se])
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADERS([config.h])
AC_CANONICAL_BUILD
AC_CANONICAL_HOST
AC_CANONICAL_TARGET

dnl Checks for programs.
AC_PROG_CXX
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_RANLIB

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

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
