/*
 * Copyright (C) 2009 Red Hat, Inc.
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef cmtdbusm_h
#define cmtdbusm_h

int cm_tdbusm_get_b(DBusMessage *msg, void *parent, dbus_bool_t *b);
int cm_tdbusm_get_n(DBusMessage *msg, void *parent, long *n);
int cm_tdbusm_get_p(DBusMessage *msg, void *parent, char **p);
int cm_tdbusm_get_s(DBusMessage *msg, void *parent, char **s);
int cm_tdbusm_get_vs(DBusMessage *msg, void *parent, char **s);
int cm_tdbusm_get_vn(DBusMessage *msg, void *parent, long *n);
int cm_tdbusm_get_bp(DBusMessage *msg, void *parent, dbus_bool_t *b, char **p);
int cm_tdbusm_get_bs(DBusMessage *msg, void *parent, dbus_bool_t *b, char **s);
int cm_tdbusm_get_sb(DBusMessage *msg, void *parent, char **s, dbus_bool_t *b);
int cm_tdbusm_get_sn(DBusMessage *msg, void *parent, char **s, long *n);
int cm_tdbusm_get_ss(DBusMessage *msg, void *parent, char **s1, char **s2);
int cm_tdbusm_get_ap(DBusMessage *msg, void *parent, char ***ap);
int cm_tdbusm_get_as(DBusMessage *msg, void *parent, char ***as);
int cm_tdbusm_get_ass(DBusMessage *msg, void *parent, char ***ass);
int cm_tdbusm_get_sss(DBusMessage *msg, void *parent,
		      char **s1, char **s2, char **s3);
int cm_tdbusm_get_ssb(DBusMessage *msg, void *parent,
		      char **s1, char **s2, dbus_bool_t *b);
int cm_tdbusm_get_ssn(DBusMessage *msg, void *parent,
		      char **s1, char **s2, long *n);
int cm_tdbusm_get_ssas(DBusMessage *msg, void *parent,
		       char **s1, char **s2, char ***as);
int cm_tdbusm_get_ssass(DBusMessage *msg, void *parent,
			char **s1, char **s2, char ***ass);
int cm_tdbusm_get_ssss(DBusMessage *msg, void *parent,
		       char **s1, char **s2, char **s3, char **s4);
int cm_tdbusm_get_ssosos(DBusMessage *msg, void *parent,
			 char **s1, char **s2, char **s3, char **s4);
int cm_tdbusm_get_sososos(DBusMessage *msg, void *parent,
			  char **s1, char **s2, char **s3, char **s4);
int cm_tdbusm_get_ssoas(DBusMessage *msg, void *parent,
			char **s1, char **s2, char ***as);
int cm_tdbusm_get_sssas(DBusMessage *msg, void *parent,
			char **s1, char **s2, char **s3, char ***as);
int cm_tdbusm_get_ss_as_s(DBusMessage *msg, void *parent,
			  char **s1, char **s2, char ***as, char **s3);
int cm_tdbusm_get_sssnasasasnas(DBusMessage *msg, void *parent,
			        char **s1, char **s2, char **s3, long *n1,
			        char ***as1, char ***as2,
			        char ***as3, long *n2, char ***as4);
int cm_tdbusm_get_sssnasasasnasn(DBusMessage *msg, void *parent,
			        char **s1, char **s2, char **s3, long *n1,
			        char ***as1, char ***as2,
			        char ***as3, long *n2, char ***as4, long *n3);
int cm_tdbusm_get_sasasasnas(DBusMessage *msg, void *parent,
			     char **s,
			     char ***as1, char ***as2,
			     char ***as3, long *n, char ***as4);
struct cm_tdbusm_dict {
	char *key;
	enum cm_tdbusm_dict_value_type {
		cm_tdbusm_dict_invalid,
		cm_tdbusm_dict_s,
		cm_tdbusm_dict_p,
		cm_tdbusm_dict_as,
		cm_tdbusm_dict_ass,
		cm_tdbusm_dict_n,
		cm_tdbusm_dict_b,
		cm_tdbusm_dict_d,
	} value_type;
	union cm_tdbusm_variant {
		char *s;
		char **as;
		char **ass;
		long n;
		dbus_bool_t b;
		const struct cm_tdbusm_dict **d;
	} value;
};
int cm_tdbusm_get_d(DBusMessage *msg, void *parent, struct cm_tdbusm_dict ***d);
int cm_tdbusm_get_sd(DBusMessage *msg, void *parent,
		     char **s, struct cm_tdbusm_dict ***d);

int cm_tdbusm_set_b(DBusMessage *msg, dbus_bool_t b);
int cm_tdbusm_set_n(DBusMessage *msg, long n);
int cm_tdbusm_set_p(DBusMessage *msg, const char *p);
int cm_tdbusm_set_s(DBusMessage *msg, const char *s);
int cm_tdbusm_set_bp(DBusMessage *msg, dbus_bool_t b, const char *p);
int cm_tdbusm_set_bs(DBusMessage *msg, dbus_bool_t b, const char *s);
int cm_tdbusm_set_sb(DBusMessage *msg, const char *s, dbus_bool_t b);
int cm_tdbusm_set_sn(DBusMessage *msg, const char *s, long n);
int cm_tdbusm_set_ss(DBusMessage *msg, const char *s1, const char *s2);
int cm_tdbusm_set_ap(DBusMessage *msg, const char **p);
int cm_tdbusm_set_as(DBusMessage *msg, const char **s);
int cm_tdbusm_set_ass(DBusMessage *msg, const char **ss);
int cm_tdbusm_set_sss(DBusMessage *msg,
		      const char *s1, const char *s2, const char *s3);
int cm_tdbusm_get_ssv(DBusMessage *msg, void *parent, char **s1, char **s2,
		      enum cm_tdbusm_dict_value_type *type,
		      union cm_tdbusm_variant *value);
int cm_tdbusm_set_ssb(DBusMessage *msg,
		      const char *s1, const char *s2, dbus_bool_t b);
int cm_tdbusm_set_ssn(DBusMessage *msg,
		      const char *s1, const char *s2, long n);
int cm_tdbusm_set_ssas(DBusMessage *msg,
		       const char *s1, const char *s2, const char **as);
int cm_tdbusm_set_ssass(DBusMessage *msg,
			const char *s1, const char *s2, const char **ass);
int cm_tdbusm_set_ssss(DBusMessage *msg,
		       const char *s1, const char *s2,
		       const char *s3, const char *s4);
int cm_tdbusm_set_ssvs(DBusMessage *msg, const char *s1, const char *s2,
		       const char *s3);
int cm_tdbusm_set_ssoas(DBusMessage *msg,
			const char *s1, const char *s2, const char **as);
int cm_tdbusm_set_ss_as_s(DBusMessage *msg, const char *s1, const char *s2,
			  const char **as, const char *s3);
int cm_tdbusm_set_sssas(DBusMessage *msg,
		        const char *s1, const char *s2,
		        const char *s3, const char **as);
int cm_tdbusm_set_sssnasasasnas(DBusMessage *msg,
			        const char *s1, const char *s2,
			        const char *s3, long n1,
			        const char **as1, const char **as2,
			        const char **as3, long n2, const char **as4);
int cm_tdbusm_set_sssnasasasnasn(DBusMessage *msg,
			        const char *s1, const char *s2,
			        const char *s3, long n1,
			        const char **as1, const char **as2,
			        const char **as3, long n2, const char **as4, long n3);
int cm_tdbusm_set_sasasasnas(DBusMessage *msg,
			     const char *s,
			     const char **as1, const char **as2,
			     const char **as3, long n, const char **as4);
int cm_tdbusm_set_d(DBusMessage *msg, const struct cm_tdbusm_dict **d);
int cm_tdbusm_set_v(DBusMessage *msg, enum cm_tdbusm_dict_value_type value_type,
		    const union cm_tdbusm_variant *value);
int cm_tdbusm_set_sd(DBusMessage *msg,
		     const char *s, const struct cm_tdbusm_dict **d);
struct cm_tdbusm_dict *cm_tdbusm_find_dict_entry(struct cm_tdbusm_dict **d,
						 const char *key,
						 enum cm_tdbusm_dict_value_type value_type);
char *cm_tdbusm_hint(void *parent, const char *error, const char *message);

#endif
