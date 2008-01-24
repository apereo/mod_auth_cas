################################################################################
#MJS - Find APXS
# 	path search for APXS
AC_DEFUN([AZ_PROG_APXS],
[
	AC_PATH_PROGS([APXS],[apxs apxs2])
])

################################################################################
#MJS - Look for --with-apxs
AC_DEFUN([AZ_WITH_APXS],
[
	AC_MSG_CHECKING([for --with-apxs])
	AC_ARG_WITH(
		[apxs],
		[AS_HELP_STRING([--with-apxs],[/path/to/apxs])],
		[APXS=$with_apxs]
	)
	if test "$APXS"
	then
		AC_MSG_RESULT([$APXS])
	else
		AC_MSG_RESULT([no])
	fi
])

################################################################################
#MJS - require apxs
AC_DEFUN([AZ_USE_APXS],
[
	AC_REQUIRE([AZ_WITH_APXS])
	if test -z "$APXS" 
	then
		AZ_PROG_APXS
	fi
	
	if test -z "$APXS"
	then
		AC_MSG_FAILURE([apxs not found])
	fi
	AC_SUBST([APXS])
	AC_MSG_NOTICE([Using APXS=$APXS])
])
