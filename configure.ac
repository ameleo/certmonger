AC_INIT(certmonger,0.80)
AM_INIT_AUTOMAKE([foreign subdir-objects])
AC_CONFIG_MACRO_DIR(m4)
AM_MAINTAINER_MODE([disable])
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_RANLIB
AM_GNU_GETTEXT([external])
AM_GNU_GETTEXT_VERSION(0.19)
AM_ICONV
ALL_LINGUAS="bg ca cs_CZ da de es eu fr gu hu id it ja ka ko lo lt nb nl pl pt pt_BR ru si sv ta tr uk zh_CN zh_TW"
if test x$GCC = xyes ; then
	CFLAGS="$CFLAGS -Wall -Wextra"
fi
AC_CONFIG_HEADER(src/config.h)

mybindir="$bindir"
mybindir=`eval echo $mybindir | sed "s,NONE,$prefix,g"`
mybindir=`eval echo $mybindir | sed "s,NONE,$exec_prefix,g"`
mybindir=`eval echo $mybindir | sed "s,NONE,$ac_default_prefix,g"`
mybindir=`eval echo $mybindir | sed "s,NONE,,g"`
AC_SUBST(mybindir)
AC_DEFINE_UNQUOTED(CM_GETCERT_DIR,"${mybindir}",
		   [Define to the directory holding various getcert commands after installation.])
mysbindir="$sbindir"
mysbindir=`eval echo $mysbindir | sed "s,NONE,$prefix,g"`
mysbindir=`eval echo $mysbindir | sed "s,NONE,$exec_prefix,g"`
mysbindir=`eval echo $mysbindir | sed "s,NONE,$ac_default_prefix,g"`
mysbindir=`eval echo $mysbindir | sed "s,NONE,,g"`
AC_SUBST(mysbindir)
AC_DEFINE_UNQUOTED(CM_CERTMONGER_DAEMON_PATH,"${mysbindir}/certmonger",
		   [Define to the path of the certmonger daemon after installation.])

UPCASE_PACKAGE_NAME=`echo "${PACKAGE_NAME}" | tr '[a-z]' '[A-Z]'`
mysysconfdir="$sysconfdir"
mysysconfdir=`eval echo $mysysconfdir | sed "s,NONE,$prefix,g"`
mysysconfdir=`eval echo $mysysconfdir | sed "s,NONE,$ac_default_prefix,g"`
mysysconfdir=`eval echo $mysysconfdir | sed "s,NONE,,g"`
AC_DEFINE_UNQUOTED(CM_STORE_CONFIG_DIRECTORY,"$mysysconfdir/${PACKAGE_NAME}",
		   [Define to the directory which holds configuration files.])
AC_DEFINE_UNQUOTED(CM_STORE_SESSION_CONFIG_DIRECTORY,".config/" PACKAGE_NAME,
		   [Define to the directory which holds user configuration files.])
AC_DEFINE_UNQUOTED(CM_STORE_CONFIG_DIRECTORY_ENV,"${UPCASE_PACKAGE_NAME}_CONFIG_DIR",
		   [Define to the name of the environment variable which can specify the directory which holds configuration files.])
CM_STORE_CONFIG_DIRECTORY_ENV="${UPCASE_PACKAGE_NAME}_CONFIG_DIR"
AC_SUBST(CM_STORE_CONFIG_DIRECTORY_ENV)
mylibexecdir="$libexecdir/${PACKAGE_NAME}"
mylibexecdir=`eval echo $mylibexecdir | sed "s,NONE,$prefix,g"`
mylibexecdir=`eval echo $mylibexecdir | sed "s,NONE,$ac_default_prefix,g"`
mylibexecdir=`eval echo $mylibexecdir | sed "s,NONE,,g"`
AC_SUBST(mylibexecdir)
AC_ARG_WITH(file-store-dir,
AS_HELP_STRING([--with-file-store-dir=/var/lib/certmonger],[directory to use for storing data]),
mylocalstatedir=$withval,
mylocalstatedir="$localstatedir/lib/${PACKAGE_NAME}")
mylocalstatedir=`eval echo $mylocalstatedir | sed "s,NONE,$prefix,g"`
mylocalstatedir=`eval echo $mylocalstatedir | sed "s,NONE,$ac_default_prefix,g"`
mylocalstatedir=`eval echo $mylocalstatedir | sed "s,NONE,,g"`
CM_STORE_LOCAL_STATE_DIR="$mylocalstatedir"
AC_SUBST(CM_STORE_LOCAL_STATE_DIR)

CM_STORE_SYSTEM_LOCK_FILE="$mylocalstatedir/lock"
CM_STORE_SYSTEM_LOCK_FILE_ENV="${UPCASE_PACKAGE_NAME}_SYSTEM_LOCK_FILE"
AC_SUBST(CM_STORE_SYSTEM_LOCK_FILE)
AC_SUBST(CM_STORE_SYSTEM_LOCK_FILE_ENV)
AC_DEFINE_UNQUOTED(CM_STORE_SYSTEM_LOCK_FILE,"${CM_STORE_SYSTEM_LOCK_FILE}",
		   [Define to the default path for the system daemon lock file.])
AC_DEFINE_UNQUOTED(CM_STORE_SYSTEM_LOCK_FILE_ENV,"${CM_STORE_SYSTEM_LOCK_FILE_ENV}",
		   [Define to the name of the environment variable which can specify the location of the system daemon lock file.])

CM_STORE_REQUESTS_DIRECTORY="$mylocalstatedir/requests"
CM_STORE_REQUESTS_DIRECTORY_ENV="${UPCASE_PACKAGE_NAME}_REQUESTS_DIR"
AC_SUBST(CM_STORE_REQUESTS_DIRECTORY)
AC_SUBST(CM_STORE_REQUESTS_DIRECTORY_ENV)
AC_DEFINE_UNQUOTED(CM_STORE_REQUESTS_DIRECTORY,"${CM_STORE_REQUESTS_DIRECTORY}",
		   [Define to the default path for request tracking files.])
AC_DEFINE_UNQUOTED(CM_STORE_SESSION_REQUESTS_DIRECTORY,".config/" PACKAGE_NAME "/requests",
		   [Define to the default path for user request tracking files.])
AC_DEFINE_UNQUOTED(CM_STORE_REQUESTS_DIRECTORY_ENV,"${CM_STORE_REQUESTS_DIRECTORY_ENV}",
		   [Define to the name of the environment variable which can specify the directory for tracking requests.])

CM_STORE_CAS_DIRECTORY="$mylocalstatedir/cas"
CM_STORE_CAS_DIRECTORY_ENV="${UPCASE_PACKAGE_NAME}_CAS_DIR"
AC_SUBST(CM_STORE_CAS_DIRECTORY)
AC_SUBST(CM_STORE_CAS_DIRECTORY_ENV)
AC_DEFINE_UNQUOTED(CM_STORE_CAS_DIRECTORY,"${CM_STORE_CAS_DIRECTORY}",
		   [Define to the default path for CA tracking files.])
AC_DEFINE_UNQUOTED(CM_STORE_SESSION_CAS_DIRECTORY,".config/" PACKAGE_NAME "/cas",
		   [Define to the default path for user CA tracking files.])
AC_DEFINE_UNQUOTED(CM_STORE_CAS_DIRECTORY_ENV,"${CM_STORE_CAS_DIRECTORY_ENV}",
		   [Define to the name of the environment variable which can specify the directory for tracking CAs.])

CM_STORE_LOCAL_CA_DIRECTORY="$mylocalstatedir/local"
CM_STORE_SESSION_LOCAL_CA_DIRECTORY=".config/${PACKAGE_NAME}/local"
CM_STORE_LOCAL_CA_DIRECTORY_ENV="${UPCASE_PACKAGE_NAME}_LOCAL_CA_DIR"
AC_SUBST(CM_STORE_LOCAL_CA_DIRECTORY)
AC_SUBST(CM_STORE_LOCAL_CA_DIRECTORY_ENV)
AC_DEFINE_UNQUOTED(CM_STORE_LOCAL_CA_DIRECTORY,"${CM_STORE_LOCAL_CA_DIRECTORY}",
		   [Define to the default path for data belonging to the local CA.])
AC_DEFINE_UNQUOTED(CM_STORE_SESSION_LOCAL_CA_DIRECTORY,"${CM_STORE_SESSION_LOCAL_CA_DIRECTORY}",
		   [Define to the default path for data belonging to the user CA.])
AC_DEFINE_UNQUOTED(CM_STORE_LOCAL_CA_DIRECTORY_ENV,"${CM_STORE_LOCAL_CA_DIRECTORY_ENV}",
		   [Define to the name of the environment variable which can specify the directory for the local CA.])

AC_ARG_WITH(homedir,
AS_HELP_STRING([--with-homedir=/],[directory to set as $HOME when running subprocesses as root]),
myhomedir=$withval,
myhomedir=/)
myhomedir=`eval echo $myhomedir | sed "s,NONE,$prefix,g"`
myhomedir=`eval echo $myhomedir | sed "s,NONE,$ac_default_prefix,g"`
myhomedir=`eval echo $myhomedir | sed "s,NONE,,g"`
CM_HOMEDIR="$myhomedir"
AM_CONDITIONAL(HOMEDIR,test x$CM_HOMEDIR != x)
AC_DEFINE_UNQUOTED(CM_HOMEDIR,"$CM_HOMEDIR",[Define to the default location to be used for storing temporary files.])
AC_SUBST(CM_HOMEDIR)

AC_ARG_WITH(tmpdir,
AS_HELP_STRING([--with-tmpdir=NONE],[directory to use for temporary storage]),
mytmpdir=$withval,
mytmpdir=)
mytmpdir=`eval echo $mytmpdir | sed "s,NONE,$prefix,g"`
mytmpdir=`eval echo $mytmpdir | sed "s,NONE,$ac_default_prefix,g"`
mytmpdir=`eval echo $mytmpdir | sed "s,NONE,,g"`
CM_TMPDIR="$mytmpdir"
AM_CONDITIONAL(TMPDIR,test x$CM_TMPDIR != x)
AC_DEFINE_UNQUOTED(CM_TMPDIR,"$CM_TMPDIR",[Define to the default location to be used for storing temporary files.])
CM_TMPDIR_ENV="${UPCASE_PACKAGE_NAME}_TMPDIR"
AC_DEFINE_UNQUOTED(CM_TMPDIR_ENV,"${CM_TMPDIR_ENV}",[Define to the default location to be used for storing temporary files.])
AC_SUBST(CM_TMPDIR)
AC_SUBST(CM_TMPDIR_ENV)

CM_NOTIFICATION_ENV="${UPCASE_PACKAGE_NAME}_NOTIFICATION"
AC_DEFINE_UNQUOTED(CM_NOTIFICATION_ENV,"${CM_NOTIFICATION_ENV}",[Define to the variable name to be used to hold a notification message.])
AC_SUBST(CM_NOTIFICATION_ENV)

CM_NOTIFICATION_TYPE_ENV="${UPCASE_PACKAGE_NAME}_NOTIFICATION_TYPE"
AC_DEFINE_UNQUOTED(CM_NOTIFICATION_TYPE_ENV,"${CM_NOTIFICATION_TYPE_ENV}",[Define to the variable name to be used to hold the notification type.])
AC_SUBST(CM_NOTIFICATION_TYPE_ENV)

CM_NOTIFICATION_CERT_NICKNAME_ENV="${UPCASE_PACKAGE_NAME}_NOTIFICATION_CERT_NICKNAME"
AC_DEFINE_UNQUOTED(CM_NOTIFICATION_CERT_NICKNAME_ENV,"${CM_NOTIFICATION_CERT_NICKNAME_ENV}",[Define to the variable name to be used to hold the certificate nickname regarding the notification.])
AC_SUBST(CM_NOTIFICATION_CERT_NICKNAME_ENV)

CERTMONGER_PVT_ADDRESS_ENV=CERTMONGER_PVT_ADDRESS
AC_DEFINE_UNQUOTED(CERTMONGER_PVT_ADDRESS_ENV,"${CERTMONGER_PVT_ADDRESS_ENV}",[Define to the variable name used to pass the location of the private D-Bus connection to subprocesses.])
AC_SUBST(CERTMONGER_PVT_ADDRESS_ENV)

mylocaledir="$localedir"
mylocaledir=`eval echo $mylocaledir | sed "s,NONE,$prefix,g"`
mylocaledir=`eval echo $mylocaledir | sed "s,NONE,$ac_default_prefix,g"`
mylocaledir=`eval echo $mylocaledir | sed "s,NONE,,g"`
AC_DEFINE_UNQUOTED(MYLOCALEDIR,"$mylocaledir",
		   [Define to the name of the directory under which locale data will be installed.])

CM_DBUS_NAME=org.fedorahosted.certmonger
AC_DEFINE_UNQUOTED(CM_DBUS_NAME,"$CM_DBUS_NAME",
		   [Define to the name of the certmonger service.])
AC_SUBST(CM_DBUS_NAME)
CM_DBUS_BASE_PATH=/org/fedorahosted/certmonger
AC_DEFINE_UNQUOTED(CM_DBUS_BASE_PATH,"$CM_DBUS_BASE_PATH",
		   [Define to the path of the certmonger main node.])
AC_DEFINE_UNQUOTED(CM_DBUS_RECONNECT_TIMEOUT,30,
		   [Define to the amount of time to wait between attempts to reconnect to the message bus if we get disconnected.])

if ! ${configure_dist_target_only:-false} ; then
	AC_CHECK_HEADERS(sys/types.h sys/socket.h linux/types.h linux/netlink.h linux/rtnetlink.h,,,[
		#ifdef HAVE_SYS_TYPES_H
		#include <sys/types.h>
		#endif
		#ifdef HAVE_SYS_SOCKET_H
		#include <sys/socket.h>
		#endif
		#ifdef HAVE_LINUX_TYPES_H
		#include <linux/types.h>
		#endif
		#ifdef HAVE_LINUX_NETLINK_H
		#include <linux/netlink.h>
		#endif
	])
	AC_CHECK_HEADERS(systemd/sd-login.h)

	PKG_CHECK_MODULES(TALLOC,talloc)
	PKG_CHECK_MODULES(TEVENT,tevent)
	PKG_CHECK_MODULES(DBUS,dbus-1 >= 1.0)
	AC_ARG_WITH(session-bus-services-dir,
	AS_HELP_STRING([--with-session-bus-services-dir=],[directory to install session bus configuration]),
	SESSIONBUSSERVICESDIR=$withval,
	SESSIONBUSSERVICESDIR=`pkg-config --variable=session_bus_services_dir dbus-1 2> /dev/null | sed -e "s|^${datadir}|\${datadir}|g" -e "s|^${datarootdir}|\${datarootdir}|g" -e "s|^${prefix}/share|\${datadir}|g"`)
	AC_SUBST(SESSIONBUSSERVICESDIR)
	AM_CONDITIONAL(SESSIONBUS,test x$SESSIONBUSSERVICESDIR != xno)
	AC_ARG_WITH(system-bus-services-dir,
	AS_HELP_STRING([--with-system-bus-services-dir=],[directory to install system bus configuration]),
	SESSIONBUSSERVICESDIR=$withval,
	SYSTEMBUSSERVICESDIR=`pkg-config --variable=system_bus_services_dir dbus-1 2> /dev/null | sed -e "s|^${datadir}|\${datadir}|g" -e "s|^${datarootdir}|\${datarootdir}|g" -e "s|^${prefix}/share|\${datadir}|g"`)
	AC_SUBST(SYSTEMBUSSERVICESDIR)
	AM_CONDITIONAL(SYSTEMBUS,test x$SYSTEMBUSSERVICESDIR != xno)

	AC_CHECK_FUNCS(clearenv)
	AC_CHECK_DECLS(strtold,,,[
		#include <stdlib.h>
	])

	savedLIBS="$LIBS"
	LIBS="$DBUS_LIBS $LIBS"
	AC_CHECK_FUNCS(dbus_watch_get_unix_fd dbus_watch_get_fd)
	LIBS="$savedLIBS"

	savedLIBS="$LIBS"
	RESOLV_LIBS=
	AC_CHECK_LIB(resolv,main,RESOLV_LIBS=-lresolv)
	LIBS="$RESOLV_LIBS"
	AC_CHECK_HEADERS(resolv.h arpa/nameser.h)
	have_ns_initparse=false
	AC_LINK_IFELSE([AC_LANG_PROGRAM([
		#ifdef HAVE_RESOLV_H
		#include <resolv.h>
		#endif
		#ifdef HAVE_ARPA_NAMESER_H
		#include <arpa/nameser.h>
		#endif
		],[
		ns_msg msg;
		ns_initparse(NULL, 0, &msg);
		])],
		have_ns_initparse=true,
		[LIBS="-lbind $LIBS"
		AC_LINK_IFELSE([AC_LANG_PROGRAM([
			#ifdef HAVE_RESOLV_H
			#include <resolv.h>
			#endif
			#ifdef HAVE_ARPA_NAMESER_H
			#include <arpa/nameser.h>
			#endif
			],[
			ns_msg msg;
			ns_initparse(NULL, 0, &msg);
			])],
			RESOLV_LIBS="-lbind $RESOLV_LIBS"
			have_ns_initparse=true,
			AC_MSG_WARN([cannot find ns_initparse() in libresolv or libbind])
			have_ns_initparse=false
		)]
	)
	AC_ARG_ENABLE(srv-location,
		      AS_HELP_STRING([--disable-srv-location],[disable SRV location for servers]),
		      SRV=$enableval,
		      SRV=auto)
	case "x$SRV" in
	xyes)
		if ! $have_ns_initparse ; then
			AC_MSG_ERROR([cannot build with SRV location])
		fi
		;;
	xno)
		have_ns_initparse=false
		;;
	xauto)
		;;
	esac
	AC_MSG_CHECKING(for SRV location)
	if $have_ns_initparse ; then
		AC_DEFINE(HAVE_NS_INITPARSE,1,[Define if you have ns_initparse() and want to use SRV location])
		AC_MSG_RESULT([yes, using $RESOLV_LIBS])
	else
		AC_MSG_RESULT(no)
		RESOLV_LIBS=
	fi
	AC_SUBST(RESOLV_LIBS)
	LIBS="$savedLIBS"

	PKG_CHECK_MODULES(CERTMONGER,dbus-1 talloc tevent nss)
	PKG_CHECK_MODULES(GETCERT,dbus-1 talloc)

	PKG_CHECK_MODULES(XML,libxml-2.0)
	have_libxml=true

	PKG_CHECK_MODULES(CURL,libcurl)
	have_libcurl=true

	savedCFLAGS="$CFLAGS"
	savedCPPFLAGS="$CPPFLAGS"
	savedLDFLAGS="$LDFLAGS"
	CFLAGS="$CFLAGS $CURL_CFLAGS"
	CPPFLAGS="$CPPFLAGS $CURL_CFLAGS"
	LDFLAGS="$LDFLAGS $CURL_LIBS"
	AC_CHECK_DECLS([CURLOPT_KEYPASSWD,CURLOPT_SSLKEYPASSWD,CURLOPT_SSLCERTPASSWD,CURLOPT_SSLCERT_BLOB],,,[#include <curl/curl.h>])
	CFLAGS="$savedCFLAGS"
	CPPFLAGS="$savedCPPFLAGS"
	LDFLAGS="$savedLDFLAGS"

	PKG_CHECK_MODULES(JANSSON,jansson)
	have_jansson=true

	AC_ARG_WITH([xmlrpc],
		[AC_HELP_STRING([--with-xmlrpc], [Enable XML-RPC support])],
		[with_xmlrpc=${with_xmlrpc}],
		[with_xmlrpc=no])
	AS_IF([test x"$with_xmlrpc" = xyes], [AC_DEFINE([WITH_XMLRPC], [1],
		[include XMLRPC support])])
	AM_CONDITIONAL(WITH_XMLRPC,test x"$with_xmlrpc" = xyes)

	AS_IF([test x"$with_xmlrpc" = xyes], [
		dnl PKG_CHECK_MODULES(XMLRPC,xmlrpc_client) # Not provided in upstream versions.
		savedCFLAGS="$CFLAGS"
		CFLAGS=
		AC_ARG_VAR(XMLRPC_C_CONFIG,[the full path of the xmlrpc-c-config command])
		AC_PATH_PROG(XMLRPC_C_CONFIG,[xmlrpc-c-config],,[$PATH$PATH_SEPARATOR/usr/xmlrpc/bin$PATH_SEPARATOR/usr/xmlrpc-c/bin])
		if test -z "$XMLRPC_C_CONFIG" ; then
			AC_MSG_ERROR(xmlrpc-c-config not found)
		fi
		AC_MSG_CHECKING(for XMLRPC CFLAGS)
		XMLRPC_CFLAGS="`${XMLRPC_C_CONFIG} client --cflags` `${XMLRPC_C_CONFIG} --cflags`"
		AC_MSG_RESULT([$XMLRPC_CFLAGS])
		AC_SUBST(XMLRPC_CFLAGS)
		AC_MSG_CHECKING(for XMLRPC LIBS)
		XMLRPC_LIBS="`${XMLRPC_C_CONFIG} client --libs` `${XMLRPC_C_CONFIG} --libs`"
		AC_MSG_RESULT([$XMLRPC_LIBS])
		AC_SUBST(XMLRPC_LIBS)
		CFLAGS="$CFLAGS $XMLRPC_CFLAGS"
		AC_CHECK_MEMBERS(struct xmlrpc_curl_xportparms.gssapi_delegation,,,
				 [
				 #include <xmlrpc-c/client.h>
				 #include <xmlrpc-c/transport.h>
				 ])
		CFLAGS="$savedCFLAGS"
	])

	savedCFLAGS="$CFLAGS"
	savedCPPFLAGS="$CPPFLAGS"
	savedLDFLAGS="$LDFLAGS"
	CFLAGS=
	AC_ARG_VAR(KRB5_CONFIG,[the full path of the krb5-config command])
	AC_PATH_PROG(KRB5_CONFIG,[krb5-config],,[$PATH$PATH_SEPARATOR/usr/kerberos/bin$PATH_SEPARATOR/usr/krb5/bin])
	if test -z "$KRB5_CONFIG" ; then
		AC_MSG_ERROR(krb5-config not found)
	fi
	AC_MSG_CHECKING(for krb5 CFLAGS)
	KRB5_CFLAGS=`${KRB5_CONFIG} --cflags`
	AC_MSG_RESULT([$KRB5_CFLAGS])
	AC_SUBST(KRB5_CFLAGS)
	AC_MSG_CHECKING(for krb5 LIBS)
	KRB5_LIBS=`${KRB5_CONFIG} --libs`
	AC_MSG_RESULT([$KRB5_LIBS])
	AC_SUBST(KRB5_LIBS)
	CFLAGS="$CFLAGS $KRB5_CFLAGS"
	CPPFLAGS="$CPPFLAGS $KRB5_CFLAGS"
	LDFLAGS="$LDFLAGS $KRB5_LIBS"
	AC_CHECK_DECLS([krb5_princ_component,krb5_princ_name,krb5_princ_set_realm_length,krb5_princ_size,krb5_princ_type],,,[#include <krb5.h>])
	AC_CHECK_FUNCS(krb5_free_unparsed_name krb5_get_init_creds_opt_alloc)
	AC_CHECK_FUNCS(krb5_get_error_message)
	CFLAGS="$savedCFLAGS"
	CPPFLAGS="$savedCPPFLAGS"
	LDFLAGS="$savedLDFLAGS"

	AM_CONDITIONAL(HAVE_OPENSSL,test x$withopenssl != xno)
	if test x$withopenssl != xno ; then
		if pkg-config libcrypto 2> /dev/null ; then
			PKG_CHECK_MODULES(OPENSSL,libcrypto)
			PKG_CHECK_MODULES(OPENSSL_SSL,libssl libcrypto)
		else
			PKG_CHECK_MODULES(OPENSSL,openssl)
			PKG_CHECK_MODULES(OPENSSL_SSL,openssl)
		fi
		AC_DEFINE(HAVE_OPENSSL,1,[Define if you have OpenSSL.])
		CFLAGSsave="$CFLAGS"
		LIBSsave="$LIBS"
		CFLAGS="$OPENSSL_CFLAGS $CFLAGS -DOPENSSL_NO_DEPRECATED"
		LIBS="$OPENSSL_LIBS $LIBS"
		AC_CHECK_DECLS([OpenSSL_add_all_algorithms,OpenSSL_add_ssl_algorithms],,,[#include <openssl/ssl.h>])
		AC_CHECK_DECLS(OPENSSL_free,,,[#include <openssl/crypto.h>])
		AC_CHECK_FUNCS(ASN1_BIT_STRING_new)
		AC_CHECK_FUNCS(ASN1_GENERALIZEDTIME_new)
		AC_CHECK_FUNCS(ASN1_IA5STRING_new)
		AC_CHECK_FUNCS(ASN1_INTEGER_new)
		AC_CHECK_FUNCS(ASN1_OCTET_STRING_new)
		AC_CHECK_FUNCS(ASN1_OCTET_STRING_set)
		AC_CHECK_FUNCS(ASN1_PRINTABLESTRING_new)
		AC_CHECK_FUNCS(ASN1_STRING_get0_data)
		AC_CHECK_FUNCS(ASN1_STRING_get_data)
		AC_CHECK_FUNCS(ASN1_STRING_length)
		AC_CHECK_FUNCS(ASN1_STRING_new)
		AC_CHECK_FUNCS(ASN1_TIME_dup)
		AC_CHECK_FUNCS(ASN1_TIME_new)
		AC_CHECK_FUNCS(ASN1_TIME_set)
		AC_CHECK_FUNCS(EVP_PKEY_base_id)
		AC_CHECK_FUNCS(EVP_PKEY_id)
		AC_CHECK_FUNCS(EVP_PKEY_get_id)
		AC_CHECK_FUNCS(OBJ_get0_data)
		AC_CHECK_FUNCS(OBJ_length)
		AC_CHECK_FUNCS(X509_ATTRIBUTE_get0_object)
		AC_CHECK_FUNCS(X509_get0_notAfter)
		AC_CHECK_FUNCS(X509_get0_pubkey)
		AC_CHECK_FUNCS(X509_get0_serialNumber)
		AC_CHECK_FUNCS(X509_get_issuer_name)
		AC_CHECK_FUNCS(X509_get_key_usage)
		AC_CHECK_FUNCS(X509_get_subject_name)
		AC_CHECK_FUNCS(X509_REQ_get0_pubkey)
		AC_CHECK_FUNCS(X509_REQ_get0_signature)
		AC_CHECK_FUNCS(X509_REQ_set_subject_name)
		AC_CHECK_FUNCS(X509_set1_notAfter)
		AC_CHECK_FUNCS(X509_set1_notBefore)
		AC_CHECK_FUNCS(X509_set_issuer_name)
		AC_CHECK_FUNCS(X509_set_pubkey)
		AC_CHECK_FUNCS(X509_set_subject_name)
		AC_CHECK_FUNCS(X509_set_version)
		AC_CHECK_MEMBERS(X509.cert_info,,,
				 [
				 #include <openssl/x509.h>
				 ])
		AC_MSG_CHECKING([if NETSCAPE_SPKI.sig_algor is a pointer or a struct])
		have_sig_algor_pointer=unknown
		AC_LINK_IFELSE(AC_LANG_PROGRAM([
			#include <stddef.h>
			#include <openssl/x509.h>
			],[
			NETSCAPE_SPKI spki;
			spki.sig_algor = NULL;
			]),
			AC_DEFINE(CM_NETSCAPE_SPKI_SIG_ALGOR_IS_POINTER,1,[Define if NETSCAPE_SPKI.sig_algor is a pointer])
			have_sig_algor_pointer="pointer to X509_ALGOR",
			have_sig_algor_pointer=X509_ALGOR
		)
		AC_MSG_RESULT($have_sig_algor_pointer)
		CFLAGS="$CFLAGSsave"
		LIBS="$LIBSsave"
	fi

	AM_CONDITIONAL(HAVE_NSS,test x$withnss != xno)
	if test x$withnss != xno ; then
		if pkg-config mozilla-nss 2> /dev/null ; then
			PKG_CHECK_MODULES(NSS,mozilla-nss)
		else
			PKG_CHECK_MODULES(NSS,nss)
		fi
		AC_DEFINE(HAVE_NSS,1,[Define if you have NSS.])
		savedCFLAGS="$CFLAGS"
		savedCPPFLAGS="$CPPFLAGS"
		savedLDFLAGS="$LDFLAGS"
		savedLIBS="$LIBS"
		CFLAGS="$CFLAGS $NSS_CFLAGS"
		CPPFLAGS="$CPPFLAGS $NSS_CFLAGS"
		LDFLAGS="$LDFLAGS"
		LIBS="$NSS_LIBS"
		AC_MSG_CHECKING([if NSS supports "sql:" databases])
		mkdir _nss_db_testdir || :
		AC_TRY_RUN([
				#include <stdio.h>
				#include <prerror.h>
				#include <nss.h>
				int
				main(int argc, char **argv)
				{
					SECStatus status;
					PRErrorCode err;
					status = NSS_InitReadWrite((argc > 1) ? argv[1] : "sql:_nss_db_testdir");
					if (status == SECSuccess) {
						return 0;
					}
					err = PR_GetError();
					printf("%s",
					       PR_ErrorToString(err,
								PR_LANGUAGE_I_DEFAULT));
					return 1;
				}
			],
			AC_DEFINE(HAVE_SQL_NSSDB,1,[Define if your copy of NSS supports SQLite databases.])
			have_sql_nssdb=yes,
			have_sql_nssdb=no,
			AC_DEFINE(HAVE_SQL_NSSDB,1,[Define if your copy of NSS supports SQLite databases.])
			have_sql_nssdb="guessing yes")
		rm -f -r _nss_db_testdir
		AC_MSG_RESULT($have_sql_nssdb)
		AM_CONDITIONAL(HAVE_SQL_NSSDB,[test "x$have_sql_nssdb" != xno])
		AC_MSG_CHECKING([if NSS supports "dbm:" databases])
		mkdir _nss_db_testdir || :
		AC_TRY_RUN([
				#include <stdio.h>
				#include <prerror.h>
				#include <nss.h>
				int
				main(int argc, char **argv)
				{
					SECStatus status;
					PRErrorCode err;
					status = NSS_InitReadWrite((argc > 1) ? argv[1] : "dbm:_nss_db_testdir");
					if (status == SECSuccess) {
						return 0;
					}
					err = PR_GetError();
					printf("%s",
					       PR_ErrorToString(err,
								PR_LANGUAGE_I_DEFAULT));
					return 1;
				}
			],
			AC_DEFINE(HAVE_DBM_NSSDB,1,[Define if your copy of NSS supports DBM databases.])
			have_dbm_nssdb=yes,
			have_dbm_nssdb=no,
			AC_DEFINE(HAVE_DBM_NSSDB,1,[Define if your copy of NSS supports DBM databases.])
			have_dbm_nssdb="guessing yes")
		rm -f -r _nss_db_testdir
		AC_MSG_RESULT($have_dbm_nssdb)
		AM_CONDITIONAL(HAVE_DBM_NSSDB,[test "x$have_dbm_nssdb" != xno])
		CFLAGS="$savedCFLAGS"
		CPPFLAGS="$savedCPPFLAGS"
		LDFLAGS="$savedLDFLAGS"
		LIBS="$savedLIBS"
	fi

	AC_ARG_WITH(gmp,
		    AS_HELP_STRING(--with-gmp,
				   [use gmp for converting hex serial numbers to decimal]),
		    withgmp=$withval,
		    withgmp=no)
	if test $withgmp != no ; then
		CFLAGSsave="$CFLAGS"
		LIBSsave="$LIBS"
		if test $withgmp != yes ; then
			GMP_CFLAGS="-I$withgmp/include"
			GMP_LIBS="-L$withgmp/lib"
		else
			GMP_CFLAGS=
			GMP_LIBS=
		fi
		CFLAGS="$GMP_CFLAGS $CFLAGS"
		LIBS="$GMP_LIBS $LIBS"
		AC_CHECK_HEADERS(gmp.h)
		AC_CHECK_FUNC(mpz_set_str,,
			      LIBS="-lgmp $LIBS"
			      AC_LINK_IFELSE([AC_LANG_PROGRAM([
				#include <stdlib.h>
				#include <gmp.h>
			      ],[mpz_get_str(NULL,10,NULL);])],
			      [GMP_LIBS="$GMP_LIBS -lgmp"]))
		AC_MSG_CHECKING([for GMP])
		if test $ac_cv_header_gmp_h = yes ; then
			AC_MSG_RESULT(found)
			AC_DEFINE(HAVE_GMP,1,[Define if you have GMP for hex-to-decimal conversions.])
		else
			AC_MSG_ERROR(not found)
		fi
		CFLAGS="$CFLAGSsave"
		LIBS="$LIBSsave"
	fi
	AC_SUBST(GMP_CFLAGS)
	AC_SUBST(GMP_LIBS)
	AM_CONDITIONAL(USE_GMP,test $withgmp != no)
	if test $withgmp = no && test x$withopenssl = xno ; then
		AC_MSG_ERROR([Need at least one of OpenSSL or GMP for big number operations.])
	fi

	SYSTEMD=no
	AC_ARG_ENABLE(systemd,
		      AS_HELP_STRING([--enable-systemd],[install unit files for systemd]),
		      SYSTEMD=$enableval,
		      SYSTEMD=no)
	AC_SUBST(SYSTEMD)
	AM_CONDITIONAL(SYSTEMD,test x$SYSTEMD != xno)
	AC_SUBST(SYSTEMDSYSTEMUNITDIR)
	if test x$SYSTEMD = xyes ; then
		SYSTEMDSYSTEMUNITDIR=`pkg-config --variable=systemdsystemunitdir systemd 2> /dev/null`
		AC_MSG_RESULT(will install systemd unit files to $SYSTEMDSYSTEMUNITDIR)
	fi

	TMPFILES=no
	AC_ARG_ENABLE(tmpfiles,
		      AS_HELP_STRING([--enable-tmpfiles],[install systemd tmpfiles.d configuration file for systemd (default: same as --enable-systemd)]),
		      TMPFILES=$enableval,
		      TMPFILES=$SYSTEMD)
	AC_SUBST(TMPFILES)
	AM_CONDITIONAL(TMPFILES,test x$TMPFILES != xno)
	if test x$TMPFILES = xyes ; then
		AC_MSG_RESULT(will install systemd tmpfiles.d file to ${prefix}/lib/tmpfiles.d)
	fi

	SYSVINIT=no
	AC_ARG_ENABLE(sysvinit,
		      AS_HELP_STRING([--enable-sysvinit=/etc/init.d],[install sysvinit script in specified location]),
		      SYSVINIT=$enableval,
		      SYSVINIT=no)
	AC_SUBST(SYSVINIT)
	AM_CONDITIONAL(SYSVINIT,test x$SYSVINIT != xno)
	if test x$SYSVINIT != xno ; then
		AC_MSG_RESULT(will install sysvinit init script to $SYSVINIT)
	fi

	AC_ARG_ENABLE(pie,
	AS_HELP_STRING(--enable-pie,[Build position-independent executables.]),
	pie=$enableval,
	pie=no)
	if test x$pie = xyes ; then
		AC_MSG_RESULT(building position-independent executables)
	else
		AC_MSG_RESULT(NOT building position-independent executables)
	fi
	AM_CONDITIONAL(PIE,[test x$pie = xyes])

	AC_ARG_ENABLE(now,
	AS_HELP_STRING(--enable-now,[Mark binaries with bind-now flag.]),
	now=$enableval,
	now=no)
	if test x$pie = xyes ; then
		AC_MSG_RESULT(building bind-now executables)
	else
		AC_MSG_RESULT(NOT building bind-now executables)
	fi
	AM_CONDITIONAL(NOW,[test x$now = xyes])

	AC_ARG_ENABLE(dsa,
	AS_HELP_STRING(--disable-dsa,[Disable DSA key support, even if available.]),
	dsa=$enableval,
	dsa=maybe)
	if test x$dsa != xno ; then
		CFLAGSsave="$CFLAGS"
		LIBSsave="$LIBS"
		CFLAGS="$OPENSSL_CFLAGS $CFLAGS"
		LIBS="$OPENSSL_LIBS $LIBS"
		AC_CHECK_LIB(crypto,DSA_new)
		CFLAGS="$NSS_CFLAGS $CFLAGS"
		LIBS="$NSS_LIBS $LIBS"
		AC_CHECK_TYPE(SECKEYDSAPublicKey,,,
			      [
			      AC_INCLUDES_DEFAULT
			      #include <nss3/keythi.h>
			      ])
		CFLAGS="$CFLAGSsave"
		LIBS="$LIBSsave"
		can_dsa=true
		if ! pkg-config --atleast-version=1.0 openssl ; then
			# CSR signing appears to be broken in 0.9.8e, so reject < 1.0
			can_dsa=false
		fi
		if test x$ac_cv_lib_crypto_DSA_new = xno ; then
			can_dsa=false
		fi
		if test x$ac_cv_type_SECKEYDSAPublicKey = xno ; then
			can_dsa=false
		fi
		AC_MSG_CHECKING([for DSA support])
		if $can_dsa ; then
			AC_MSG_RESULT(enabling DSA support)
			AC_DEFINE_UNQUOTED(CM_ENABLE_DSA,1,[Define to enable DSA support.])
			MAN_DSA=""
			NO_MAN_DSA=".\\\" "
			dsa=yes
		else
			if test x$dsa != xyes ; then
				AC_MSG_WARN([unavailable, disabling])
				dsa=no
			else
				AC_MSG_ERROR([unavailable])
			fi
			MAN_DSA=".\\\" "
			NO_MAN_DSA=""
		fi
	else
		AC_MSG_RESULT(NOT enabling DSA support)
		MAN_DSA=".\\\" "
		NO_MAN_DSA=""
		dsa=no
	fi
	AM_CONDITIONAL(HAVE_DSA,[test x$dsa = xyes])
	AC_SUBST(MAN_DSA)
	AC_SUBST(NO_MAN_DSA)

	AC_ARG_ENABLE(ec,
	AS_HELP_STRING(--disable-ec,[Disable EC key support, even if available.]),
	ec=$enableval,
	ec=maybe)
	if test x$ec != xno ; then
		CFLAGSsave="$CFLAGS"
		LIBSsave="$LIBS"
		CFLAGS="$OPENSSL_CFLAGS $CFLAGS"
		LIBS="$OPENSSL_LIBS $LIBS"
		AC_CHECK_LIB(crypto,EC_KEY_new_by_curve_name)
		CFLAGS="$NSS_CFLAGS $CFLAGS"
		LIBS="$NSS_LIBS $LIBS"
		AC_CHECK_FUNCS(SECKEY_CreateECPrivateKey)
		AC_CHECK_FUNCS(PK11_PrivDecrypt)
		AC_CHECK_FUNCS(NSS_OptionGet NSS_OptionSet)
		CFLAGS="$CFLAGSsave"
		LIBS="$LIBSsave"
		can_ec=true
		if test x$ac_cv_lib_crypto_EC_KEY_new_by_curve_name = xno ; then
			can_ec=false
		fi
		if test x$ac_cv_func_CreateECPrivateKey = xno ; then
			can_ec=false
		fi
		AC_MSG_CHECKING([for EC support])
		if $can_ec ; then
			AC_MSG_RESULT(enabling EC support)
			AC_DEFINE_UNQUOTED(CM_ENABLE_EC,1,[Define to enable EC support.])
			MAN_EC=""
			NO_MAN_EC=".\\\" "
			ec=yes
		else
			if test x$ec != xyes ; then
				AC_MSG_WARN([unavailable, disabling])
				ec=no
			else
				AC_MSG_ERROR([unavailable])
			fi
			MAN_EC=".\\\" "
			NO_MAN_EC=""
		fi
	else
		AC_MSG_RESULT(NOT enabling EC support)
		MAN_EC=".\\\" "
		NO_MAN_EC=""
		ec=no
	fi
	AM_CONDITIONAL(HAVE_EC,[test x$ec = xyes])
	AC_SUBST(MAN_EC)
	AC_SUBST(NO_MAN_EC)

	AC_ARG_ENABLE(ml_dsa,
	AS_HELP_STRING(--disable-ml-dsa,[Disable ML-DSA key support, even if available.]),
	ml_dsa=$enableval,
	ml_dsa=maybe)
	if test x$ml_dsa != xno ; then
		CFLAGSsave="$CFLAGS"
		LIBSsave="$LIBS"
		CFLAGS="$OPENSSL_CFLAGS $CFLAGS"
		LIBS="$OPENSSL_LIBS $LIBS"
		AC_CHECK_LIB(crypto,EVP_PKEY_Q_keygen)
		CFLAGS="$NSS_CFLAGS $CFLAGS"
		LIBS="$NSS_LIBS $LIBS"
		AC_CHECK_DECLS([CKM_ML_DSA_KEY_PAIR_GEN],,,[[#include <pkcs11t.h>]])
		AC_CHECK_FUNCS(PK11_GenerateKeyPair)
		AC_CHECK_FUNCS(NSS_OptionGet NSS_OptionSet)
		CFLAGS="$CFLAGSsave"
		LIBS="$LIBSsave"
		can_ml_dsa=true
		if test x$ac_cv_have_decl_CKM_ML_DSA_KEY_PAIR_GEN = xno ; then
			can_ml_dsa=false
		fi
		if test x$ac_cv_lib_crypto_EVP_PKEY_Q_keygen = xno ; then
			can_ml_dsa=false
		fi
		AC_MSG_CHECKING([for ML-DSA support])
		if $can_ml_dsa ; then
			AC_MSG_RESULT(enabling ML-DSA support)
			AC_DEFINE_UNQUOTED(CM_ENABLE_ML_DSA,1,[Define to enable ML-DSA support.])
			MAN_ML_DSA=""
			NO_MAN_ML_DSA=".\\\" "
			ml_dsa=yes
		else
			if test x$ml_dsa != xyes ; then
				AC_MSG_WARN([unavailable, disabling])
				ml_dsa=no
			else
				AC_MSG_ERROR([unavailable])
			fi
			MAN_ML_DSA=".\\\" "
			NO_MAN_ML_DSA=""
		fi
	else
		AC_MSG_RESULT(NOT enabling ML-DSA support)
		MAN_ML_DSA=".\\\" "
		NO_MAN_ML_DSA=""
		ml_dsa=no
	fi
	AM_CONDITIONAL(HAVE_ML_DSA,[test x$ml_dsa = xyes])
	AC_SUBST(MAN_ML_DSA)
	AC_SUBST(NO_MAN_ML_DSA)

	AC_DEFINE_UNQUOTED(CM_DEFAULT_KEY_STORAGE_TYPE,cm_key_storage_nssdb,[Define to the default type of storage used for keys.])
	AC_DEFINE_UNQUOTED(CM_DEFAULT_KEY_STORAGE_LOCATION,"/etc/pki/nssdb",[Define to the default location of storage used for keys.])
	AC_DEFINE_UNQUOTED(CM_DEFAULT_KEY_TOKEN,NULL,[Define to the default token used for holding keys.])
	AC_DEFINE_UNQUOTED(CM_DEFAULT_KEY_NICKNAME,"Server-Cert",[Define to the default nickname given to keys.])
	AC_DEFINE_UNQUOTED(CM_DEFAULT_CERT_STORAGE_TYPE,cm_cert_storage_nssdb,[Define to the default type of storage used for certificates.])
	AC_DEFINE_UNQUOTED(CM_DEFAULT_CERT_STORAGE_LOCATION,"/etc/pki/nssdb",[Define to the default location of storage used for certificates.])
	AC_DEFINE_UNQUOTED(CM_DEFAULT_CERT_TOKEN,NULL,[Define to the default token used to store certificates.])
	AC_DEFINE_UNQUOTED(CM_DEFAULT_CERT_NICKNAME,"Server-Cert",[Define to the default nickname given to certificates.])
	AC_DEFINE_UNQUOTED(CM_DEFAULT_PUBKEY_TYPE,cm_key_rsa,[Define to the default public key type.])
	AC_DEFINE_UNQUOTED(CM_DEFAULT_RSA_EXPONENT,0x10001,[Define to the default RSA key exponent.])
	AC_DEFINE_UNQUOTED(CM_DIGEST_MAX,(512/8),[Define to the maximum size (in bytes) of supported digests.])
	CM_DEFAULT_PUBKEY_SIZE=2048
	AC_DEFINE_UNQUOTED(CM_DEFAULT_PUBKEY_SIZE,$CM_DEFAULT_PUBKEY_SIZE,[Define to the default public key size.])
	AC_SUBST(CM_DEFAULT_PUBKEY_SIZE)
	CM_MINIMUM_RSA_KEY_SIZE=1024
	AC_SUBST(CM_MINIMUM_RSA_KEY_SIZE)
	CM_MINIMUM_DSA_KEY_SIZE=512
	CM_MINIMUM_EC_KEY_SIZE=256
	CM_MINIMUM_ML_DSA_KEY_SIZE=44
	AC_DEFINE_UNQUOTED(CM_MINIMUM_RSA_KEY_SIZE,$CM_MINIMUM_RSA_KEY_SIZE,[Define to the minimum key size when generating RSA keys.  Requests to generate smaller keys will be forced to this key size.])
	AC_DEFINE_UNQUOTED(CM_MINIMUM_DSA_KEY_SIZE,$CM_MINIMUM_DSA_KEY_SIZE,[Define to the minimum key size when generating DSA parameters and keys.  Requests to generate smaller keys will be forced to this key size.])
	AC_DEFINE_UNQUOTED(CM_MINIMUM_EC_KEY_SIZE,$CM_MINIMUM_EC_KEY_SIZE,[Define to the minimum key size when selecting elliptic curve parameters.  Requests to generate smaller keys will be forced to this key size.])
	AC_DEFINE_UNQUOTED(CM_MINIMUM_ML_DSA_KEY_SIZE,$CM_MINIMUM_ML_DSA_KEY_SIZE,[Define to the minimum key size when selecting ML-DSA parameters.  Requests to generate smaller keys will be forced to this key size.])
	AC_SUBST(CM_MINIMUM_RSA_KEY_SIZE)
	AC_SUBST(CM_MINIMUM_DSA_KEY_SIZE)
	AC_SUBST(CM_MINIMUM_EC_KEY_SIZE)
	CM_DEFAULT_TTL_LIST="2419200, 604800, 259200, 172800, 86400, 43200, 21600, 7200, 3600"
	AC_DEFINE_UNQUOTED(CM_DEFAULT_TTL_LIST,[$CM_DEFAULT_TTL_LIST],[Define to the list of default time-left thresholds at which we need to warn the user.])
	AC_SUBST(CM_DEFAULT_TTL_LIST)
	AC_DEFINE_UNQUOTED(CM_DEFAULT_CERT_SUBJECT_CN,"localhost",[Define to the last-ditch default CN value for a signing request.])
	CM_DEFAULT_CERT_LIFETIME=1y
	AC_DEFINE_UNQUOTED(CM_DEFAULT_CERT_LIFETIME,"$CM_DEFAULT_CERT_LIFETIME",[Define to the default certificate lifetime for self-signed certificates.])
	AC_SUBST(CM_DEFAULT_CERT_LIFETIME)
	AC_DEFINE_UNQUOTED(CM_DEFAULT_CERT_SERIAL,"01",[Define to the default starting serial number for self-signed certificates.])
	AC_DEFINE_UNQUOTED(CM_DEFAULT_NOTIFICATION_METHOD,cm_notification_syslog,[Define to the default method of notification.])
	AC_DEFINE_UNQUOTED(CM_DEFAULT_NOTIFICATION_MAIL,"root",[Define to the address where notification mail should be sent by default.])
	CM_DEFAULT_NOTIFICATION_SYSLOG_PRIORITY=daemon.notice
	AC_SUBST(CM_DEFAULT_NOTIFICATION_SYSLOG_PRIORITY)
	AC_DEFINE_UNQUOTED(CM_DEFAULT_NOTIFICATION_SYSLOG_PRIORITY,"$CM_DEFAULT_NOTIFICATION_SYSLOG_PRIORITY",[Define to the syslog facility from which notification messages should be sent by default.])
	AC_DEFINE(CM_DELAY_SOON,5,[Define to the time to wait for something that will happen soon.])
	AC_DEFINE(CM_DELAY_SOONISH,30,[Define to the time to wait for something that will happen soon, but not that soon.])
	AC_DEFINE(CM_DELAY_CA_POLL,(7 * 24 * 60 * 60),[Define to the time to wait between attempts to see if the CA issued a certificate.])
	AC_DEFINE(CM_DELAY_CADATA_POLL,(6 * 60 * 60),[Define to the time to wait between attempts to fetch the CA certificate, if it was unreachable.])
	AC_DEFINE(CM_DELAY_CA_POLL_MINIMUM,(5 * 60),[Define to the absolute minimum time to wait between attempts to see if the CA issued a certificate.])
	AC_DEFINE(CM_DELAY_CA_POLL_MAXIMUM,(365 * 24 * 60 * 60),[Define to the absolute maximum time to wait between attempts to see if the CA issued a certificate.])
	AC_DEFINE(CM_DELAY_MONITOR_POLL,(24 * 60 * 60),[Define to the time to wait between attempts to re-read a certificate and check for expiration.])
	AC_DEFINE(CM_DELAY_MONITOR_POLL_MINIMUM,(30 * 60),[Define to the absolute minimum time to wait between attempts to re-read a certificate and check for expiration.])
	AC_DEFINE(CM_DELAY_MONITOR_POLL_MAXIMUM,(7 * 24 * 60 * 60),[Define to the absolute maximum time to wait between attempts to re-read a certificate and check for expiration.])
	AC_DEFINE(CM_DELAY_NETLINK,(60),[Define to the time to wait after a netlink routing notification to retry submissions.])

	CM_SELF_SIGN_CA_NAME=SelfSign
	AC_SUBST(CM_SELF_SIGN_CA_NAME)
	AC_DEFINE_UNQUOTED(CM_SELF_SIGN_CA_NAME,"$CM_SELF_SIGN_CA_NAME",[Define to the name that the internal self-signing not-really-a-CA will be known by.])

	AC_DEFINE_UNQUOTED(CM_DEFAULT_HELPER_PATH,"$mylibexecdir",[Define to the default path of submission helpers.])

	AC_DEFINE(WITH_IPA,1,[Define to ensure that there's always an IPA CA defined.])
	CM_IPA_CA_NAME=IPA
	AC_SUBST(CM_IPA_CA_NAME)
	AC_DEFINE_UNQUOTED(CM_IPA_CA_NAME,"$CM_IPA_CA_NAME",[Define to the name that the default IPA CA will be known by.])
	AC_DEFINE_UNQUOTED(CM_IPA_HELPER_PATH,"$mylibexecdir/ipa-submit",[Define to the path of the IPA submission helper.])
	AM_CONDITIONAL(WITH_IPA,true)

	AC_DEFINE(WITH_CERTMASTER,1,[Define to ensure that there's always a CERTMASTER CA defined.])
	CM_CERTMASTER_CA_NAME=certmaster
	AC_SUBST(CM_CERTMASTER_CA_NAME)
	AC_DEFINE_UNQUOTED(CM_CERTMASTER_CA_NAME,"$CM_CERTMASTER_CA_NAME",[Define to the name that the default certmaster CA will be known by.])
	AC_DEFINE_UNQUOTED(CM_CERTMASTER_HELPER_PATH,"$mylibexecdir/certmaster-submit",[Define to the path of the CERTMASTER submission helper.])
	AM_CONDITIONAL(WITH_CERTMASTER,true)

	AC_DEFINE(WITH_LOCAL,1,[Define to ensure that there's always a local CA defined.])
	CM_LOCAL_CA_NAME=local
	AC_SUBST(CM_LOCAL_CA_NAME)
	AC_DEFINE_UNQUOTED(CM_LOCAL_CA_NAME,"$CM_LOCAL_CA_NAME",[Define to the name that the local CA will be known by.])
	AC_DEFINE_UNQUOTED(CM_LOCAL_HELPER_PATH,"$mylibexecdir/local-submit",[Define to the path of the local submission helper.])
	AM_CONDITIONAL(WITH_LOCAL,true)

	AC_DEFINE_UNQUOTED(CM_SCEP_HELPER_PATH,"$mylibexecdir/scep-submit",[Define to the path of the SCEP submission helper.])

	CM_DEFAULT_IDLE_TIMEOUT=300
	AC_SUBST(CM_DEFAULT_IDLE_TIMEOUT)
	AC_DEFINE_UNQUOTED(CM_DEFAULT_IDLE_TIMEOUT,$CM_DEFAULT_IDLE_TIMEOUT,[Define to the default idle-timeout when bus-activated.])

	CFLAGSsave="$CFLAGS"
	LIBSsave="$LIBS"
	AC_CHECK_HEADER(ldap.h,,AC_MSG_ERROR(ldap.h not found))
	AC_CHECK_FUNC(ldap_initialize,,AC_CHECK_LIB(ldap,ldap_initialize))
	AC_CHECK_FUNC(ldap_sasl_interactive_bind_s,,AC_CHECK_LIB(ldap,ldap_sasl_interactive_bind_s))
	AC_CHECK_FUNC(ldap_str2dn,,AC_CHECK_LIB(ldap,ldap_str2dn))
	AC_CHECK_FUNC(ldap_dnfree,,AC_CHECK_LIB(ldap,ldap_dnfree))
	LDAP_CFLAGS="$CFLAGS"
	LDAP_LIBS="$LIBS"
	CFLAGS="$CFLAGSsave"
	LIBS="$LIBSsave"
	AC_SUBST(LDAP_CFLAGS)
	AC_SUBST(LDAP_LIBS)

	AC_ARG_WITH(idn,
	AS_HELP_STRING([--without-idn],[do not handle international dnsName subjectAltNames or international domain names during service location]),
	if test x$with_idn = xno ; then
		idn=false
	else
		idn=true
	fi,
	idn=true)
	if $idn ; then
		PKG_CHECK_MODULES(IDN,libidn2)
		AC_DEFINE(CM_USE_IDN,1,[Define if dnsName subjectAltNames should be encoded properly, and if international domain names should be handled during service location.])
	fi

	AC_ARG_WITH(uuid,
	AS_HELP_STRING([--with-uuid],[populate subjectUniqueID in self-signed certs]),
	[uuid=$with_uuid],
	[uuid=auto])
	if test x$with_uuid = xyes ; then
		PKG_CHECK_MODULES(UUID,uuid)
	else
		if test x$with_uuid != xno ; then
			if pkg-config uuid ; then
				PKG_CHECK_MODULES(UUID,uuid)
				uuid=yes
			fi
		fi
	fi
	# Older uuid pkgconfig sets us up to need <uuid/uuid.h>.  Newer
	# versions set us up to need <uuid.h>.
	if test x$uuid = xyes ; then
		savedCFLAGS="$CFLAGS"
		CFLAGS="$UUID_CFLAGS"
		AC_CHECK_HEADERS(uuid.h uuid/uuid.h)
		CFLAGS="$savedCFLAGS"
		if test x$ac_cv_header_uuid_uuid_h = xno ; then
			if test x$ac_cv_header_uuid_h = xno ; then
				AC_MSG_ERROR(uuid.h header file not found)
			fi
		fi
		AC_DEFINE(HAVE_UUID,1,[Define to have the ability to populate subjectUniqueID in self-signed certs.])
	fi
	CM_DEFAULT_POPULATE_UNIQUE_ID=no
	AC_SUBST(CM_DEFAULT_POPULATE_UNIQUE_ID)
	AC_DEFINE_UNQUOTED(CM_DEFAULT_POPULATE_UNIQUE_ID,"$CM_DEFAULT_POPULATE_UNIQUE_ID",[Define to the default for the selfsign/populate_unique_id configuration setting.])
	AM_CONDITIONAL(HAVE_UUID,test x$uuid = xyes)
	AC_SUBST(UUID_CFLAGS)
	AC_SUBST(UUID_LIBS)
	LIBSsave="$LIBS"
	AC_CHECK_HEADERS(popt.h)
	if test x$ac_cv_header_popt_h != xyes ; then
		AC_MSG_ERROR(popt.h header file not found)
	fi
	AC_CHECK_FUNC(poptGetContext,,AC_CHECK_LIB(popt,poptGetContext))
	if test x$ac_cv_func_poptGetContext != xyes ; then
		if test x$ac_cv_lib_popt_poptGetContext != xyes ; then
			AC_MSG_ERROR(libpopt not found)
		fi
	fi
	POPT_LIBS="$LIBS"
	LIBS="$LIBSsave"
	AC_SUBST(POPT_CFLAGS)
	AC_SUBST(POPT_LIBS)
else
	AM_CONDITIONAL(SESSIONBUS,false)
	AM_CONDITIONAL(SYSTEMBUS,false)
	AM_CONDITIONAL(HAVE_OPENSSL,false)
	AM_CONDITIONAL(HAVE_NSS,false)
	AM_CONDITIONAL(HAVE_SQL_NSSDB,false)
	AM_CONDITIONAL(HAVE_DBM_NSSDB,false)
	AM_CONDITIONAL(USE_GMP,false)
	AM_CONDITIONAL(SYSTEMD,false)
	AM_CONDITIONAL(TMPFILES,false)
	AM_CONDITIONAL(SYSVINIT,false)
	AM_CONDITIONAL(PIE,false)
	AM_CONDITIONAL(NOW,false)
	AM_CONDITIONAL(HAVE_DSA,false)
	AM_CONDITIONAL(HAVE_EC,false)
	AM_CONDITIONAL(HAVE_ML_DSA,false)
	AM_CONDITIONAL(WITH_IPA,false)
	AM_CONDITIONAL(WITH_CERTMASTER,false)
	AM_CONDITIONAL(WITH_XMLRPC,false)
	AM_CONDITIONAL(WITH_LOCAL,false)
	AM_CONDITIONAL(HAVE_UUID,false)
fi

AC_CONFIG_COMMANDS(src_introspect_sh,[chmod +x src/introspect.sh])
AC_CONFIG_FILES([Makefile src/Makefile dbus/Makefile systemd/Makefile sysvinit/Makefile sysvinit/certmonger tests/Makefile tests/tools/Makefile dbus/org.fedorahosted.certmonger.conf dbus/org.fedorahosted.certmonger.service src/introspect.sh src/certmonger.8 src/getcert.1 src/getcert-request.1 src/getcert-list.1 src/getcert-list-cas.1 src/getcert-start-tracking.1 src/getcert-stop-tracking.1 src/selfsign-getcert.1 src/ipa-getcert.1 src/getcert-resubmit.1 src/certmonger-certmaster-submit.8 src/certmonger-ipa-submit.8 src/certmonger-dogtag-ipa-renew-agent-submit.8 src/certmaster-getcert.1 src/certmonger.conf.5 po/Makefile.in src/certmonger.conf systemd/certmonger.service systemd/certmonger.conf systemd/org.fedorahosted.certmonger.service src/getcert-refresh.1 src/getcert-refresh-ca.1 src/local-getcert.1 src/certmonger-local-submit.8 src/getcert-status.1 src/certmonger-dogtag-submit.8 src/certmonger-scep-submit.8 src/getcert-add-ca.1 src/getcert-add-scep-ca.1 src/getcert-modify-ca.1 src/getcert-remove-ca.1 src/getcert-rekey.1])

AC_OUTPUT

echo "
        prefix:                   ${prefix}
        exec_prefix:              ${exec_prefix}
        libdir:                   ${libdir}
        bindir:                   ${bindir}
        sbindir:                  ${sbindir}
        sysconfdir:               ${sysconfdir}
        localstatedir:            ${localstatedir}
        datadir:                  ${datadir}
        source code location:     ${srcdir}
        compiler:                 ${CC}
        cflags:                   ${CFLAGS}
        LDAP libs:                ${LDAP_LIBS}
        OpenSSL crypto libs:      ${OPENSSL_LIBS}
        NSS libs:                 ${NSS_LIBS}
        JANSSON libs:             ${JANSSON_LIBS}"

AM_COND_IF([HAVE_DSA], [
    echo "\
        DSA support enabled:      yes"
], [
    echo "\
        DSA support enabled:      no"
])

AM_COND_IF([HAVE_EC], [
    echo "\
        EC support enabled:       yes"
], [
    echo "\
        EC support enabled:       no"
])

AM_COND_IF([HAVE_ML_DSA], [
    echo "\
        ML-DSA support enabled:   yes"
], [
    echo "\
        ML-DSA support enabled:   no"
])
