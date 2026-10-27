AM_CFLAGS = $(TALLOC_CFLAGS) $(TEVENT_CFLAGS) $(DBUS_CFLAGS) $(KRB5_CFLAGS) \
	    $(XMLRPC_CFLAGS) $(IDN_CFLAGS) $(UUID_CFLAGS) $(LDAP_CFLAGS) \
	    $(POPT_CFLAGS)
if PIE
CFLAGS += -fPIC
LDFLAGS += -fPIC -pie
endif
if NOW
LDFLAGS += -Wl,-z,relro,-z,now
endif
man_MANS = certmonger.8 getcert.1 getcert-request.1 getcert-list.1 \
	   getcert-list-cas.1 getcert-start-tracking.1 getcert-stop-tracking.1 \
	   selfsign-getcert.1 ipa-getcert.1 \
	   getcert-resubmit.1 certmonger-ipa-submit.8 \
	   certmonger-dogtag-ipa-renew-agent-submit.8 certmonger.conf.5 \
	   getcert-refresh.1 getcert-refresh-ca.1 local-getcert.1 \
	   certmonger-local-submit.8 getcert-status.1 \
	   certmonger-dogtag-submit.8 certmonger-scep-submit.8 \
	   getcert-add-ca.1 getcert-add-scep-ca.1 getcert-modify-ca.1 \
	   getcert-remove-ca.1 getcert-rekey.1 \
	   certmonger-est-submit.8 getcert-add-est-ca.1 \
	   certmonger-acme-submit.8 getcert-add-acme-ca.1
if WITH_XMLRPC
man_MANS += certmaster-getcert.1 certmonger-certmaster-submit.8
endif
pkgsysconfdir = $(sysconfdir)/$(PACKAGE)
pkgsysconf_DATA = certmonger.conf
EXTRA_PROGRAMS =
install-data-hook::
	chmod go-rwx $(DESTDIR)$(pkgsysconfdir)/certmonger.conf
	mkdir -m 700 -p $(DESTDIR)@CM_STORE_CAS_DIRECTORY@
	mkdir -m 700 -p $(DESTDIR)@CM_STORE_REQUESTS_DIRECTORY@
	mkdir -m 700 -p $(DESTDIR)@CM_STORE_LOCAL_CA_DIRECTORY@
noinst_LIBRARIES = libcm.a libcm-o.a
libcm_a_CFLAGS = $(AM_CFLAGS) $(NSS_CFLAGS)
libcm_a_SOURCES = \
	cadata.c \
	cadata.h \
	casave.c \
	casave.h \
	canalyze.c \
	canalyze.h \
	certext.c \
	certext.h \
	certext-n.h \
	certread.c \
	certread.h \
	certread-int.h \
	certread-n.c \
	certsave.c \
	certsave.h \
	certsave-int.h \
	certsave-n.c \
	cm.c \
	cm.h \
	csrgen.c \
	csrgen.h \
	csrgen-int.h \
	csrgen-n.c \
	env.h \
	env-shared.c \
	hook.c \
	hook.h \
	iterate.c \
	iterate.h \
	json.c \
	json.h \
	keygen.c \
	keygen.h \
	keygen-int.h \
	keygen-n.c \
	keyiread.c \
	keyiread.h \
	keyiread-int.h \
	keyiread-n.c \
	keyiread-n.h \
	kudict.c \
	kudict.h \
	log.c \
	log.h \
	netlink.c \
	netlink.h \
	notify.c \
	notify.h \
	oiddict.c \
	oiddict.h \
	pin.c \
	pin.h \
	prefs.c \
	prefs.h \
	prefs-n.c \
	prefs-n.h \
	scep.h \
	scepgen.c \
	scepgen.h \
	scepgen-int.h \
	scepgen-n.c \
	store-files.c \
	store-gen.c \
	store.h \
	store-int.h \
	submit.c \
	submit-e.c \
	submit-e.h \
	submit.h \
	submit-int.h \
	submit-n.c \
	submit-sn.c \
	submit-u.c \
	submit-u.h \
	subproc.c \
	subproc.h \
	tdbus.c \
	tdbus.h \
	tdbush.c \
	tdbush.h \
	tdbusm.c \
	tdbusm.h \
	tpm-token.c \
	tpm-token.h \
	tpm-token-dir.c \
	tpm-token-n.c \
	util.c \
	util.h \
	util-m.c \
	util-m.h \
	util-n.c \
	util-n.h \
	util-ipa.c \
	util-ipa.h
if WITH_XMLRPC
libcm_a_SOURCES += \
	submit-x.c \
	submit-x.h
endif
libcm_o_a_SOURCES =
if HAVE_OPENSSL
libcm_o_a_SOURCES += \
	certread-o.c \
	certsave-o.c \
	csrgen-o.c \
	keygen-o.c \
	keyiread-o.c \
	pkcs7.c \
	pkcs7.h \
	prefs-o.c \
	prefs-o.h \
	scep-o.c \
	scep-o.h \
	scepgen-o.c \
	submit-so.c \
	submit-o.c \
	submit-o.h \
	util-o.c \
	util-o.h \
	util-ipa.c \
	util-ipa.h
endif
libcm_o_a_CFLAGS = $(AM_CFLAGS) $(NSS_CFLAGS) $(OPENSSL_CFLAGS)
libcm_a_LIBADD = $(libcm_o_a_OBJECTS)
bin_PROGRAMS = getcert
pkglibexec_PROGRAMS = certmonger-session
pkglibexecdir = $(libexecdir)/$(PACKAGE)
getcert_CFLAGS = $(AM_CFLAGS) $(NSS_CFLAGS) $(UUID_CFLAGS)
getcert_SOURCES = getcert.c tm.c tm.h
getcert_LDADD = libcm.a $(GETCERT_LIBS) $(KRB5_LIBS) $(NSS_LIBS) $(UUID_LIBS) \
			$(POPT_LIBS) $(LTLIBICONV) $(LDAP_LIBS) $(OPENSSL_LIBS)
if WITH_IPA
bin_PROGRAMS += ipa-getcert
ipa_getcert_CFLAGS = $(getcert_CFLAGS)
ipa_getcert_SOURCES = ipa-getcert.c tm.c tm.h
ipa_getcert_LDADD = $(getcert_LDADD)
endif
if WITH_IPA
if WITH_XMLRPC
bin_PROGRAMS += certmaster-getcert
certmaster_getcert_CFLAGS = $(getcert_CFLAGS)
certmaster_getcert_SOURCES = certmaster-getcert.c tm.c tm.h
certmaster_getcert_LDADD = $(getcert_LDADD)
endif
endif
bin_PROGRAMS += selfsign-getcert
selfsign_getcert_CFLAGS = $(getcert_CFLAGS)
selfsign_getcert_SOURCES = selfsign-getcert.c tm.c tm.h
selfsign_getcert_LDADD = $(getcert_LDADD)
bin_PROGRAMS += local-getcert
local_getcert_CFLAGS = $(getcert_CFLAGS)
local_getcert_SOURCES = local-getcert.c tm.c tm.h
local_getcert_LDADD = $(getcert_LDADD)
sbin_PROGRAMS = certmonger
certmonger_getcert_CFLAGS = $(getcert_CFLAGS)
certmonger_SOURCES = main.c env-system.c tm.c tm.h
certmonger_LDADD = libcm.a \
		   $(OPENSSL_LIBS) $(CERTMONGER_LIBS) $(KRB5_LIBS) $(IDN_LIBS) \
		   $(GMP_LIBS) $(UUID_LIBS) $(POPT_LIBS) $(LTLIBICONV) $(LDAP_LIBS)
certmonger_session_SOURCES = main.c env-session.c tm.c tm.h
certmonger_session_LDADD = libcm.a \
		   $(OPENSSL_LIBS) $(CERTMONGER_LIBS) $(KRB5_LIBS) $(IDN_LIBS) \
		   $(GMP_LIBS) $(UUID_LIBS) $(POPT_LIBS) $(LTLIBICONV) $(LDAP_LIBS)
noinst_PROGRAMS = tdbusm-check serial-check nl-check toklist
if WITH_XMLRPC
noinst_PROGRAMS += submit-x
endif
tdbusm_check_SOURCES = tdbusm-check.c tm.c tm.h
tdbusm_check_LDADD = libcm.a $(CERTMONGER_LIBS) $(POPT_LIBS) $(LDAP_LIBS) \
			$(OPENSSL_LIBS) $(NSS_LIBS)
serial_check_LDADD = libcm.a $(CERTMONGER_LIBS) $(LTLIBICONV) $(LDAP_LIBS)
nl_check_LDADD = libcm.a $(CERTMONGER_LIBS) $(LDAP_LIBS)
if WITH_XMLRPC
submit_x_CFLAGS = $(AM_CFLAGS) $(NSS_CFLAGS) -DCM_SUBMIT_X_MAIN
submit_x_SOURCES = submit-x.c submit-x.h submit-u.c submit-u.h log.c log.h \
	tm.c tm.h
submit_x_LDADD = $(XMLRPC_LIBS) $(KRB5_LIBS) $(TALLOC_LIBS) \
		 $(GMP_LIBS) $(UUID_LIBS) $(POPT_LIBS)
endif
toklist_CFLAGS = $(AM_CFLAGS) $(NSS_CFLAGS)
toklist_LDADD = $(NSS_LIBS) $(POPT_LIBS)
if WITH_CERTMASTER
if WITH_XMLRPC
pkglibexec_PROGRAMS += certmaster-submit
endif
endif
if WITH_IPA
pkglibexec_PROGRAMS += ipa-submit
endif
pkglibexec_PROGRAMS += dogtag-ipa-renew-agent-submit dogtag-submit
if HAVE_OPENSSL
pkglibexec_PROGRAMS += local-submit
pkglibexec_PROGRAMS += scep-submit
pkglibexec_PROGRAMS += est-submit
pkglibexec_PROGRAMS += acme-submit
endif
noinst_PROGRAMS += submit-h submit-d
ipa_submit_CFLAGS = $(AM_CFLAGS) $(NSS_CFLAGS) $(CURL_CFLAGS) $(JANSSON_CFLAGS)
ipa_submit_SOURCES = ipa.c srvloc.c srvloc.h store.h store-gen.c \
		submit-h.c submit-h.h submit-u.c submit-u.h \
		submit-e.h util.c util.h log.c log.h tm.c tm.h \
		util-ipa.c util-ipa.h
ipa_submit_LDADD = $(XMLRPC_LIBS) $(LDAP_LIBS) $(KRB5_LIBS) $(TALLOC_LIBS) \
		   $(GMP_LIBS) $(IDN_LIBS) $(OPENSSL_LIBS) $(UUID_LIBS) \
		   $(RESOLV_LIBS) $(LTLIBICONV) $(POPT_LIBS) $(CURL_LIBS) \
		   $(JANSSON_LIBS) $(OPENSSL_LIBS) $(NSS_LIBS)
if WITH_XMLRPC
certmaster_submit_CFLAGS = $(AM_CFLAGS) $(NSS_CFLAGS)
certmaster_submit_SOURCES = certmaster.c submit-x.c submit-x.h \
		submit-e.h submit-u.c submit-u.h util.c util.h log.c log.h \
		tm.c tm.h
certmaster_submit_LDADD = $(XMLRPC_LIBS) $(KRB5_LIBS) $(TALLOC_LIBS) \
			  $(GMP_LIBS) $(UUID_LIBS) $(LTLIBICONV) $(POPT_LIBS)
endif
dogtag_ipa_renew_agent_submit_CFLAGS = $(AM_CFLAGS) $(XML_CFLAGS) \
				       $(NSS_CFLAGS) $(CURL_CFLAGS) $(LDAP_CFLAGS) \
				       $(KRB5_CFLAGS) $(JANSSON_CFLAGS) \
				       $(IDN_CFLAGS) $(RESOLV_CFLAGS) \
				       -DDOGTAG_IPA_RENEW_AGENT=1
dogtag_ipa_renew_agent_submit_SOURCES = dogtag.c submit-d.c submit-d.h \
		submit-h.c submit-h.h util-m.c util-m.h util-n.c util-n.h \
		submit-u.c submit-u.h submit-e.h util.c util.h log.c log.h \
		store.h store-gen.c tm.c tm.h prefs.c prefs.h \
		dogtag-ipa.c dogtag-ipa.h env.h env-system.c util-ipa.c \
		srvloc.c srvloc.h
dogtag_ipa_renew_agent_submit_LDADD = $(CURL_LIBS) $(XML_LIBS) $(NSS_LIBS) \
				      $(OPENSSL_LIBS) $(TALLOC_LIBS) \
				      $(GMP_LIBS) $(UUID_LIBS) $(LTLIBICONV) \
				      $(POPT_LIBS) $(LDAP_LIBS) $(KRB5_LIBS) $(JANSSON_LIBS) \
				      $(IDN_LIBS) $(RESOLV_LIBS)
dogtag_submit_CFLAGS = $(AM_CFLAGS) $(XML_CFLAGS) $(NSS_CFLAGS) $(CURL_CFLAGS) \
					$(JANSSON_CFLAGS) $(LDAP_CFLAGS) $(IDN_FLAGS) \
					$(RESOLV_FLAGS) $(KRB5_FLAGS)
dogtag_submit_SOURCES = dogtag.c submit-d.c submit-d.h \
		submit-h.c submit-h.h util-m.c util-m.h util-n.c util-n.h \
		submit-u.c submit-u.h submit-e.h util.c util.h log.c log.h \
		store.h store-gen.c tm.c tm.h prefs.c prefs.h \
		env.h env-system.c util-ipa.c util-ipa.h \
		srvloc.c srvloc.h
dogtag_submit_LDADD = $(CURL_LIBS) $(XML_LIBS) $(NSS_LIBS) \
		      $(OPENSSL_LIBS) $(TALLOC_LIBS) \
		      $(GMP_LIBS) $(UUID_LIBS) $(LTLIBICONV) \
		      $(POPT_LIBS) $(LDAP_LIBS) $(KRB5_LIBS) $(JANSSON_LIBS) \
			  $(IDN_LIBS) $(RESOLV_LIBS)
scep_submit_CFLAGS = $(AM_CFLAGS) $(XML_CFLAGS) $(NSS_CFLAGS) $(CURL_CFLAGS)
scep_submit_SOURCES = scep.c scep.h \
		submit-h.c submit-h.h util-m.c util-m.h util-o.c util-o.h \
		submit-u.c submit-u.h submit-e.h util.c util.h log.c log.h \
		pkcs7.c pkcs7.h store.h store-gen.c tm.c tm.h prefs.c prefs.h \
		prefs-o.c prefs-o.h scep-o.c scep-o.h env.h env-system.c
scep_submit_LDADD = $(CURL_LIBS) $(XML_LIBS) $(NSS_LIBS) \
		      $(OPENSSL_LIBS) $(TALLOC_LIBS) \
		      $(GMP_LIBS) $(UUID_LIBS) $(LTLIBICONV) $(POPT_LIBS)
est_submit_CFLAGS = $(AM_CFLAGS) $(NSS_CFLAGS) $(CURL_CFLAGS) \
		    $(OPENSSL_CFLAGS)
est_submit_SOURCES = est.c est-n.c est.h \
		submit-h.c submit-h.h submit-u.c submit-u.h submit-e.h \
		util-o.c util-o.h util.c util.h log.c log.h json.c json.h \
		store.h store-gen.c tm.c tm.h
est_submit_LDADD = $(CURL_LIBS) $(NSS_LIBS) $(OPENSSL_SSL_LIBS) $(TALLOC_LIBS) \
		   $(KRB5_LIBS) $(UUID_LIBS) $(LTLIBICONV) $(POPT_LIBS)
acme_submit_CFLAGS = $(AM_CFLAGS) $(NSS_CFLAGS) $(CURL_CFLAGS) \
		     $(OPENSSL_CFLAGS) $(JANSSON_CFLAGS)
acme_submit_SOURCES = acme.c acme-jose.c acme.h \
		submit-h.c submit-h.h submit-u.c submit-u.h submit-e.h \
		util-o.c util-o.h util.c util.h log.c log.h \
		store.h store-gen.c tm.c tm.h
acme_submit_LDADD = $(CURL_LIBS) $(NSS_LIBS) $(OPENSSL_LIBS) $(JANSSON_LIBS) \
		    $(TALLOC_LIBS) $(KRB5_LIBS) $(UUID_LIBS) $(LTLIBICONV) \
		    $(POPT_LIBS)
if HAVE_TSS2
acme_submit_CFLAGS += $(TSS2_CFLAGS)
acme_submit_SOURCES += acme-tpm.c acme-tpm.h acme-tpm-p11.c
acme_submit_LDADD += $(TSS2_LIBS)
endif
local_submit_CFLAGS = $(AM_CFLAGS) $(NSS_CFLAGS)
local_submit_SOURCES = local.c env.h store.h store-gen.c submit-o.c submit-o.h \
		       submit-u.c submit-u.h env-system.c env-shared.c log.c \
		       log.h prefs.c prefs.h prefs-o.c prefs-o.h tm.c tm.h \
		       util.c util.h util-o.c util-o.h pin.c pin.h \
		       tpm-token-dir.c tpm-token.h
local_submit_LDADD = $(NSS_LIBS) $(OPENSSL_LIBS) $(TALLOC_LIBS) $(UUID_LIBS) \
		     $(POPT_LIBS)
submit_d_CFLAGS = $(AM_CFLAGS) $(CURL_CFLAGS) $(XML_CFLAGS) $(OPENSSL_CFLAGS) \
		 $(NSS_CFLAGS) -DCM_SUBMIT_D_MAIN
submit_d_SOURCES = submit-d.c submit-d.h submit-h.c submit-h.h \
		   submit-u.c submit-u.h log.c log.h tm.c tm.h util-m.c util-m.h
submit_d_LDADD = libcm-o.a $(CURL_LIBS) $(OPENSSL_LIBS) $(XML_LIBS) \
		 $(TALLOC_LIBS) $(GMP_LIBS) $(UUID_LIBS) $(LTLIBICONV) \
		 $(POPT_LIBS) $(JANSSON_LIBS) $(OPENSSL_LIBS) $(NSS_LIBS)
submit_h_CFLAGS = $(AM_CFLAGS) $(NSS_CFLAGS) $(CURL_CFLAGS) $(XML_CFLAGS) \
		 $(JANSSON_CFLAGS) -DCM_SUBMIT_H_MAIN
submit_h_SOURCES = submit-h.c submit-h.h log.c log.h tm.c tm.h
submit_h_LDADD = $(NSS_LIBS) $(OPENSSL_LIBS) $(CURL_LIBS) $(XML_LIBS) $(TALLOC_LIBS) \
		 $(LTLIBICONV) $(POPT_LIBS)

.PHONY: manlint
manlint: $(man_MANS)
	for page in $(MANS); do \
		mandoc -T lint $${page}; \
	done
