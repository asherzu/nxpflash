
# -*- Autoconf -*-
# configure.ac -- Autoconf script for mediaserver
#
# Process this file with autoconf to produce a configure script

# Requires autoconf tool later than 2.61
AC_PREREQ(2.61)

# Initialize the oem-mediaserver package version 1.0.0
AC_INIT([oem-mediaserver],1.0.0)

# Does not strictly follow GNU Coding standards
AM_INIT_AUTOMAKE([-Wall gnu foreign])

# Disables auto rebuilding of configure, Makefile.ins
AM_MAINTAINER_MODE

# defines some macros variable to be included by source
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_CXX
AC_PROG_LIBTOOL
AC_PROG_AWK
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
PKG_PROG_PKG_CONFIG

AC_ARG_WITH(sanitized-headers,
        AS_HELP_STRING([--with-sanitized-headers=DIR],
                [Specify the location of the sanitized Linux headers]),
        [CPPFLAGS="$CPPFLAGS -isystem $withval"])


PKG_CHECK_MODULES(GTHREAD, gthread-2.0 >= 2.16, dummy=yes,
                                AC_MSG_ERROR(GThread >= 2.16 is required))
PKG_CHECK_MODULES(GLIB, glib-2.0 >= 2.16, dummy=yes,
                                AC_MSG_ERROR(GLib >= 2.16 is required))
GLIB_CFLAGS="$GLIB_CFLAGS $GTHREAD_CFLAGS"
GLIB_CPPFLAGS="$GLIB_CPPFLAGS $GTHREAD_CPPFLAGS"
GLIB_LIBS="$GLIB_LIBS $GTHREAD_LIBS"

AC_SUBST(GLIB_CFLAGS)
AC_SUBST(GLIB_LIBS)


AM_CONDITIONAL(USE_GLIB, test "x${with_glib}" = "xyes")


AC_SUBST([CFLAGS])
AC_SUBST([CC])
AC_CONFIG_FILES([ \
        Makefile \
        \
        ])
AC_OUTPUT
