AM_CFLAGS = $(TALLOC_CFLAGS) $(TEVENT_CFLAGS) $(DBUS_CFLAGS) $(KRB5_CFLAGS) \
	    $(XMLRPC_CFLAGS) $(IDN_CFLAGS) $(UUID_CFLAGS) $(LDAP_CFLAGS) \
	    $(POPT_CFLAGS) -I$(top_builddir)/src -I$(top_srcdir)/src
LDADD = libtools.a $(top_builddir)/src/libcm.a $(top_srcdir)/src/env-system.c \
	libtools.a $(OPENSSL_LIBS) $(CERTMONGER_LIBS) $(KRB5_LIBS) $(IDN_LIBS) \
	$(GMP_LIBS) $(UUID_LIBS) $(RESOLV_LIBS) $(POPT_LIBS) $(LTLIBICONV) \
	$(LDAP_LIBS)

noinst_SCRIPTS = cachain.sh

if PIE
CFLAGS += -fPIC
LDFLAGS += -fPIC -pie
endif

noinst_PROGRAMS = keyiread keygen csrgen submit certread certsave oid2name \
		  name2oid iterate prefs dates listnicks pem2base base2pem \
		  dparse payload checksig base64 cadata citerate casave hooks \
		  libexecdir canon srv addcinfo ls json json-utf8 printenv fromfile \
		  pem timestamp validate_sm_fromfile
noinst_LIBRARIES = libtools.a
if HAVE_OPENSSL
noinst_PROGRAMS += pk7parse pk7env scepgen pk7verify pk7decrypt
endif

libtools_a_SOURCES = $(top_srcdir)/src/tm.h tm.c tools.h tools.c
listnicks_CFLAGS = $(AM_CFLAGS) $(NSS_CFLAGS)

payload_CFLAGS = $(AM_CFLAGS) $(NSS_CFLAGS)
checksig_CFLAGS = $(AM_CFLAGS) $(NSS_CFLAGS)
addcinfo_CFLAGS = $(AM_CFLAGS) $(NSS_CFLAGS)

dparse_CFLAGS = $(AM_CFLAGS) $(XML_CFLAGS)
dparse_SOURCES = dparse.c
dparse_LDADD = $(top_srcdir)/src/submit-d.c $(LDADD) $(XML_LIBS) $(JANSSON_LIBS)

citerate_SOURCES = citerate.c
citerate_LDADD = $(top_srcdir)/src/store-gen.c $(LDADD)

timestamp_SOURCES = timestamp.c
timestamp_LDADD = $(top_srcdir)/src/store-gen.c $(LDADD)

srv_SOURCES = srv.c
srv_LDADD = $(top_srcdir)/src/srvloc.c $(LDADD)

fromfile_CFLAGS = $(AM_CFLAGS)
fromfile_SOURCES = fromfile.c
fromfile_LDADD = $(LDADD) $(UUID_LIBS)

validate_sm_fromfile_CFLAGS = $(AM_CFLAGS)
validate_sm_fromfile_SOURCES = validate_sm_fromfile.c
validate_sm_fromfile_LDADD = $(LDADD) $(UUID_LIBS)
