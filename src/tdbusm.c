/*
 * Copyright (C) 2009,2010,2011,2012,2014,2015 Red Hat, Inc.
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

#include "config.h"

#include <sys/types.h>
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <talloc.h>

#include <dbus/dbus.h>

#include "log.h"
#include "tdbusm.h"

#define N_(_text) _text

static char empty_string[] = "";
static const char *empty_string_array[] = {NULL};
static struct cm_tdbusm_dict **cm_tdbusm_get_d_array(DBusMessageIter *array,
						     void *parent);
static struct cm_tdbusm_dict *cm_tdbusm_get_d_item(DBusMessageIter *item,
						   void *parent);
static struct cm_tdbusm_dict *cm_tdbusm_get_d_value(DBusMessageIter *item,
						    void *parent,
						    struct cm_tdbusm_dict *dict);
static int cm_tdbusm_append_d(DBusMessage *msg, DBusMessageIter *args,
			      const struct cm_tdbusm_dict **d);
static int cm_tdbusm_append_d_value(DBusMessage *msg, DBusMessageIter *args,
				    enum cm_tdbusm_dict_value_type value_type,
				    const union cm_tdbusm_variant *value);

static int
cm_tdbusm_array_length(const char **array)
{
	int i;
	for (i = 0; (array != NULL) && (array[i] != NULL); i++) {
		continue;
	}
	return i;
}

static char **
cm_tdbusm_take_dbus_string_array(void *parent, char **array, int len)
{
	int i;
	char **ret;
	if (len == -1) {
		len = cm_tdbusm_array_length((const char **) array);
	}
	if (len > 0) {
		ret = talloc_zero_array(parent, char *, len + 1);
		if (ret != NULL) {
			for (i = 0;
			     (array != NULL) && (i < len) && (array[i] != NULL);
			     i++) {
				ret[i] = talloc_strdup(ret, array[i]);
			}
			ret[i] = NULL;
		}
	} else {
		ret = NULL;
	}
	if (array != NULL) {
		dbus_free_string_array(array);
	}
	return ret;
}

int
cm_tdbusm_get_b(DBusMessage *msg, void *parent, dbus_bool_t *b)
{
	DBusError err;
	dbus_error_init(&err);
	if (dbus_message_get_args(msg, &err,
				  DBUS_TYPE_BOOLEAN, b,
				  DBUS_TYPE_INVALID)) {
		return 0;
	} else {
		if (dbus_error_is_set(&err)) {
			dbus_error_free(&err);
			dbus_error_init(&err);
		}
		return -1;
	}
}

int
cm_tdbusm_get_n(DBusMessage *msg, void *parent, long *n)
{
	DBusError err;
	int64_t i64;
	int32_t i32;
	uint32_t u32;
	int16_t i16;
	dbus_error_init(&err);
	if (dbus_message_get_args(msg, &err,
				  DBUS_TYPE_INT64, &i64,
				  DBUS_TYPE_INVALID)) {
		*n = i64;
		return 0;
	} else {
		if (dbus_error_is_set(&err)) {
			dbus_error_free(&err);
			dbus_error_init(&err);
		}
		if (dbus_message_get_args(msg, &err,
					  DBUS_TYPE_INT32, &i32,
					  DBUS_TYPE_INVALID)) {
			*n = i32;
			return 0;
		} else {
			if (dbus_error_is_set(&err)) {
				dbus_error_free(&err);
				dbus_error_init(&err);
			}
			if (dbus_message_get_args(msg, &err,
						  DBUS_TYPE_UINT32, &u32,
						  DBUS_TYPE_INVALID)) {
				*n = u32;
				return 0;
			} else {
				if (dbus_error_is_set(&err)) {
					dbus_error_free(&err);
					dbus_error_init(&err);
				}
				if (dbus_message_get_args(msg, &err,
							  DBUS_TYPE_INT16, &i16,
							  DBUS_TYPE_INVALID)) {
					*n = i16;
					return 0;
				} else {
					if (dbus_error_is_set(&err)) {
						dbus_error_free(&err);
						dbus_error_init(&err);
					}
					return -1;
				}
			}
		}
	}
}

int
cm_tdbusm_get_p(DBusMessage *msg, void *parent, char **p)
{
	DBusError err;
	*p = NULL;
	dbus_error_init(&err);
	if (dbus_message_get_args(msg, &err,
				  DBUS_TYPE_OBJECT_PATH, p,
				  DBUS_TYPE_INVALID)) {
		*p = *p ? talloc_strdup(parent, *p) : NULL;
		return 0;
	} else {
		if (dbus_error_is_set(&err)) {
			dbus_error_free(&err);
			dbus_error_init(&err);
		}
		return -1;
	}
}

int
cm_tdbusm_get_vs(DBusMessage *msg, void *parent, char **s)
{
	DBusError err;
	DBusMessageIter iter, sub_iter;

	*s = NULL;
	dbus_error_init(&err);

	if (dbus_message_iter_init(msg, &iter) == FALSE) {
		if (dbus_error_is_set(&err)) {
			cm_log(3, "DBus error: %s", err.message);
			dbus_error_free(&err);
		} else {
			cm_log(3, "Unknown DBus error.");
		}
		return -1;
	}

	if (dbus_message_iter_get_arg_type(&iter) == DBUS_TYPE_VARIANT) {
		dbus_message_iter_recurse(&iter, &sub_iter);
		if (dbus_message_iter_get_arg_type(&sub_iter) == DBUS_TYPE_STRING) {
			dbus_message_iter_get_basic(&sub_iter, s);
			*s = *s ? talloc_strdup(parent, *s) : NULL;
			return 0;
		}
	}

	if (dbus_error_is_set(&err)) {
		cm_log(3, "Failed to extract data from DBus message: %s", err.message);
		dbus_error_free(&err);
	} else {
		cm_log(3, "Failed to extract data from DBus message.");
	}
	*s = NULL;
	return -1;
}

int
cm_tdbusm_get_vn(DBusMessage *msg, void *parent, long *n)
{
	DBusError err;
	DBusMessageIter iter, sub_iter;
	int64_t i64;

	dbus_error_init(&err);

	if (dbus_message_iter_init(msg, &iter) == FALSE) {
		if (dbus_error_is_set(&err)) {
			cm_log(3, "DBus error: %s", err.message);
			dbus_error_free(&err);
		} else {
			cm_log(3, "Unknown DBus error.");
		}
		return -1;
	}

	if (dbus_message_iter_get_arg_type(&iter) == DBUS_TYPE_VARIANT) {
		dbus_message_iter_recurse(&iter, &sub_iter);
		if (dbus_message_iter_get_arg_type(&sub_iter) == DBUS_TYPE_INT64) {
			dbus_message_iter_get_basic(&sub_iter, &i64);
			*n = i64;
			return 0;
		}
	}

	if (dbus_error_is_set(&err)) {
		cm_log(3, "Failed to extract data from DBus message: %s", err.message);
		dbus_error_free(&err);
	} else {
		cm_log(3, "Failed to extract data from DBus message.");
	}
	*n = 0;
	return -1;
}

int
cm_tdbusm_get_s(DBusMessage *msg, void *parent, char **s)
{
	DBusError err;
	*s = NULL;
	dbus_error_init(&err);
	if (dbus_message_get_args(msg, &err,
				  DBUS_TYPE_STRING, s,
				  DBUS_TYPE_INVALID)) {
		*s = *s ? talloc_strdup(parent, *s) : NULL;
		return 0;
	} else {
		if (dbus_error_is_set(&err)) {
			dbus_error_free(&err);
			dbus_error_init(&err);
		}
		return -1;
	}
}

int
cm_tdbusm_get_bp(DBusMessage *msg, void *parent, dbus_bool_t *b, char **p)
{
	DBusError err;
	*p = NULL;
	dbus_error_init(&err);
	if (dbus_message_get_args(msg, &err,
				  DBUS_TYPE_BOOLEAN, b,
				  DBUS_TYPE_OBJECT_PATH, p,
				  DBUS_TYPE_INVALID)) {
		*p = *p ? talloc_strdup(parent, *p) : NULL;
		return 0;
	} else {
		if (dbus_error_is_set(&err)) {
			dbus_error_free(&err);
			dbus_error_init(&err);
		}
		return -1;
	}
}

int
cm_tdbusm_get_bs(DBusMessage *msg, void *parent, dbus_bool_t *b, char **s)
{
	DBusError err;
	*s = NULL;
	dbus_error_init(&err);
	if (dbus_message_get_args(msg, &err,
				  DBUS_TYPE_BOOLEAN, b,
				  DBUS_TYPE_STRING, s,
				  DBUS_TYPE_INVALID)) {
		*s = *s ? talloc_strdup(parent, *s) : NULL;
		return 0;
	} else {
		if (dbus_error_is_set(&err)) {
			dbus_error_free(&err);
			dbus_error_init(&err);
		}
		return -1;
	}
}

int
cm_tdbusm_get_sb(DBusMessage *msg, void *parent, char **s, dbus_bool_t *b)
{
	DBusError err;
	*s = NULL;
	dbus_error_init(&err);
	if (dbus_message_get_args(msg, &err,
				  DBUS_TYPE_STRING, s,
				  DBUS_TYPE_BOOLEAN, b,
				  DBUS_TYPE_INVALID)) {
		*s = *s ? talloc_strdup(parent, *s) : NULL;
		return 0;
	} else {
		if (dbus_error_is_set(&err)) {
			dbus_error_free(&err);
			dbus_error_init(&err);
		}
		return -1;
	}
}

int
cm_tdbusm_get_sn(DBusMessage *msg, void *parent, char **s, long *n)
{
	DBusError err;
	int64_t i64;
	int64_t i32;
	int64_t i16;
	*s = NULL;
	dbus_error_init(&err);
	if (dbus_message_get_args(msg, &err,
				  DBUS_TYPE_STRING, s,
				  DBUS_TYPE_INT64, &i64,
				  DBUS_TYPE_INVALID)) {
		*s = *s ? talloc_strdup(parent, *s) : NULL;
		*n = i64;
		return 0;
	} else {
		if (dbus_error_is_set(&err)) {
			dbus_error_free(&err);
			dbus_error_init(&err);
		}
		if (dbus_message_get_args(msg, &err,
					  DBUS_TYPE_STRING, s,
					  DBUS_TYPE_INT32, &i32,
					  DBUS_TYPE_INVALID)) {
			*s = *s ? talloc_strdup(parent, *s) : NULL;
			*n = i32;
			return 0;
		} else {
			if (dbus_error_is_set(&err)) {
				dbus_error_free(&err);
				dbus_error_init(&err);
			}
			if (dbus_message_get_args(msg, &err,
						  DBUS_TYPE_STRING, s,
						  DBUS_TYPE_INT16, &i16,
						  DBUS_TYPE_INVALID)) {
				*s = *s ? talloc_strdup(parent, *s) : NULL;
				*n = i16;
				return 0;
			} else {
				if (dbus_error_is_set(&err)) {
					dbus_error_free(&err);
					dbus_error_init(&err);
				}
				return -1;
			}
		}
	}
}

int
cm_tdbusm_get_ss(DBusMessage *msg, void *parent, char **s1, char **s2)
{
	DBusError err;
	*s1 = NULL;
	*s2 = NULL;
	dbus_error_init(&err);
	if (dbus_message_get_args(msg, &err,
				  DBUS_TYPE_STRING, s1,
				  DBUS_TYPE_STRING, s2,
				  DBUS_TYPE_INVALID)) {
		*s1 = *s1 ? talloc_strdup(parent, *s1) : NULL;
		*s2 = *s2 ? talloc_strdup(parent, *s2) : NULL;

		if (*s1 == NULL || *s2 == NULL) {
			errno = ENOMEM;
			return -1;
		}

		return 0;
	} else {
		if (dbus_error_is_set(&err)) {
			dbus_error_free(&err);
			dbus_error_init(&err);
		}

		errno = EINVAL;
		return -1;
	}
}

int
cm_tdbusm_get_ap(DBusMessage *msg, void *parent, char ***ap)
{
	DBusError err;
	char **tmp;
	int i;

	*ap = NULL;
	dbus_error_init(&err);
	if (dbus_message_get_args(msg, &err,
				  DBUS_TYPE_ARRAY, DBUS_TYPE_OBJECT_PATH,
				  &tmp, &i,
				  DBUS_TYPE_INVALID)) {
		*ap = cm_tdbusm_take_dbus_string_array(parent, tmp, i);
		return 0;
	} else {
		if (dbus_error_is_set(&err)) {
			dbus_error_free(&err);
			dbus_error_init(&err);
		}
		return -1;
	}
}

int
cm_tdbusm_get_ass(DBusMessage *msg, void *parent, char ***ass)
{
	DBusMessageIter args, array, element;
	const char *p, *q;
	char **ret, **tmp;
	int i = 0;

	ret = NULL;
	if (!dbus_message_iter_init(msg, &args)) {
		talloc_free(ret);
		return -1;
	}

	if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_ARRAY) {
		talloc_free(ret);
		return -1;
	}
	memset(&array, 0, sizeof(array));
	dbus_message_iter_recurse(&args, &array);

	for (;;) {
		if (dbus_message_iter_get_arg_type(&array) != DBUS_TYPE_STRUCT) {
			talloc_free(ret);
			return -1;
		}
		dbus_message_iter_recurse(&array, &element);

		if (dbus_message_iter_get_arg_type(&element) != DBUS_TYPE_STRING) {
			talloc_free(ret);
			return -1;
		}
		p = NULL;
		dbus_message_iter_get_basic(&element, &p);
		if (!dbus_message_iter_has_next(&element) ||
		    !dbus_message_iter_next(&element) ||
		    (dbus_message_iter_get_arg_type(&element) != DBUS_TYPE_STRING)) {
			talloc_free(ret);
			return -1;
		}
		q = NULL;
		dbus_message_iter_get_basic(&element, &q);
		tmp = talloc_realloc(parent, ret, char *, i + 3);
		if (tmp == NULL) {
			talloc_free(ret);
			return -1;
		}
		ret = tmp;
		ret[i++] = talloc_strdup(ret, p);
		ret[i++] = talloc_strdup(ret, q);
		ret[i] = NULL;
		if (!dbus_message_iter_has_next(&array)) {
			break;
		}
		if (!dbus_message_iter_next(&array)) {
			talloc_free(ret);
			return -1;
		}
	}
	*ass = ret;
	return 0;
}

int
cm_tdbusm_get_as(DBusMessage *msg, void *parent, char ***as)
{
	DBusError err;
	char **tmp;
	int i;
	*as = NULL;
	dbus_error_init(&err);
	if (dbus_message_get_args(msg, &err,
				  DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &tmp, &i,
				  DBUS_TYPE_INVALID)) {
		*as = cm_tdbusm_take_dbus_string_array(parent, tmp, i);
		return 0;
	} else {
		if (dbus_error_is_set(&err)) {
			dbus_error_free(&err);
			dbus_error_init(&err);
		}
		return -1;
	}
}

int
cm_tdbusm_get_sss(DBusMessage *msg, void *parent, char **s1, char **s2,
		  char **s3)
{
	DBusError err;
	*s1 = NULL;
	*s2 = NULL;
	*s3 = NULL;
	dbus_error_init(&err);
	if (dbus_message_get_args(msg, &err,
				  DBUS_TYPE_STRING, s1,
				  DBUS_TYPE_STRING, s2,
				  DBUS_TYPE_STRING, s3,
				  DBUS_TYPE_INVALID)) {
		*s1 = *s1 ? talloc_strdup(parent, *s1) : NULL;
		*s2 = *s2 ? talloc_strdup(parent, *s2) : NULL;
		*s3 = *s3 ? talloc_strdup(parent, *s3) : NULL;
		return 0;
	} else {
		if (dbus_error_is_set(&err)) {
			dbus_error_free(&err);
			dbus_error_init(&err);
		}
		return -1;
	}
}

int
cm_tdbusm_get_ssv(DBusMessage *msg, void *parent, char **s1, char **s2,
		  enum cm_tdbusm_dict_value_type *type,
		  union cm_tdbusm_variant *value)
{
	DBusMessageIter iter;
	struct cm_tdbusm_dict *d;

	*s1 = NULL;
	*s2 = NULL;
	if (!dbus_message_iter_init(msg, &iter)) {
		errno = EINVAL;
		return -1;
	}

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING) {
		errno = EINVAL;
		return -1;
	}
	dbus_message_iter_get_basic(&iter, s1);

	if (!dbus_message_iter_has_next(&iter) ||
	    !dbus_message_iter_next(&iter)) {
		errno = EINVAL;
		return -1;
	}
	d = cm_tdbusm_get_d_item(&iter, parent);
	if (d == NULL) {
		errno = EINVAL;
		return -1;
	}

	*s1 = *s1 ? talloc_strdup(parent, *s1) : NULL;
	*s2 = talloc_strdup(parent, d->key);

	if (*s1 == NULL || *s2 == NULL) {
		errno = ENOMEM;
		return -1;
	}

	*type = d->value_type;
	*value = d->value;
	return 0;
}

int
cm_tdbusm_get_ssb(DBusMessage *msg, void *parent, char **s1, char **s2,
		  dbus_bool_t *b)
{
	DBusError err;
	*s1 = NULL;
	*s2 = NULL;
	dbus_error_init(&err);
	if (dbus_message_get_args(msg, &err,
				  DBUS_TYPE_STRING, s1,
				  DBUS_TYPE_STRING, s2,
				  DBUS_TYPE_BOOLEAN, b,
				  DBUS_TYPE_INVALID)) {
		*s1 = *s1 ? talloc_strdup(parent, *s1) : NULL;
		*s2 = *s2 ? talloc_strdup(parent, *s2) : NULL;
		return 0;
	} else {
		if (dbus_error_is_set(&err)) {
			dbus_error_free(&err);
			dbus_error_init(&err);
		}
		return -1;
	}
}

int
cm_tdbusm_get_ssn(DBusMessage *msg, void *parent, char **s1, char **s2, long *l)
{
	DBusError err;
	int64_t i64;
	int32_t i32;
	int16_t i16;
	*s1 = NULL;
	*s2 = NULL;

	dbus_error_init(&err);
	if (!dbus_message_get_args(msg, &err,
				   DBUS_TYPE_STRING, s1,
				   DBUS_TYPE_STRING, s2,
				   DBUS_TYPE_INT64, &i64,
				   DBUS_TYPE_INVALID)) {
		if (dbus_error_is_set(&err)) {
			dbus_error_free(&err);
			dbus_error_init(&err);
		}
		if (!dbus_message_get_args(msg, &err,
					   DBUS_TYPE_STRING, s1,
					   DBUS_TYPE_STRING, s2,
					   DBUS_TYPE_INT32, &i32,
					   DBUS_TYPE_INVALID)) {
			if (dbus_error_is_set(&err)) {
				dbus_error_free(&err);
				dbus_error_init(&err);
			}
			if (!dbus_message_get_args(msg, &err,
						   DBUS_TYPE_STRING, s1,
						   DBUS_TYPE_STRING, s2,
						   DBUS_TYPE_INT16, &i16,
						   DBUS_TYPE_INVALID)) {
				if (dbus_error_is_set(&err)) {
					dbus_error_free(&err);
					dbus_error_init(&err);
				}
				return -1;
			}
			i32 = i16;
		}
		i64 = i32;
	}
	*l = i64;
	*s1 = *s1 ? talloc_strdup(parent, *s1) : NULL;
	*s2 = *s2 ? talloc_strdup(parent, *s2) : NULL;
	return 0;
}

int
cm_tdbusm_get_ssss(DBusMessage *msg, void *parent, char **s1, char **s2,
		   char **s3, char **s4)
{
	DBusError err;
	*s1 = NULL;
	*s2 = NULL;
	*s3 = NULL;
	*s4 = NULL;
	dbus_error_init(&err);
	if (dbus_message_get_args(msg, &err,
				  DBUS_TYPE_STRING, s1,
				  DBUS_TYPE_STRING, s2,
				  DBUS_TYPE_STRING, s3,
				  DBUS_TYPE_STRING, s4,
				  DBUS_TYPE_INVALID)) {
		*s1 = *s1 ? talloc_strdup(parent, *s1) : NULL;
		*s2 = *s2 ? talloc_strdup(parent, *s2) : NULL;
		*s3 = *s3 ? talloc_strdup(parent, *s3) : NULL;
		*s4 = *s4 ? talloc_strdup(parent, *s4) : NULL;
		return 0;
	} else {
		if (dbus_error_is_set(&err)) {
			dbus_error_free(&err);
			dbus_error_init(&err);
		}
		return -1;
	}
}

int
cm_tdbusm_get_ssosos(DBusMessage *msg, void *parent, char **s1, char **s2,
		     char **s3, char **s4)
{
	int i;
	i = cm_tdbusm_get_ssss(msg, parent, s1, s2, s3, s4);
	if (i != 0) {
		*s4 = NULL;
		i = cm_tdbusm_get_sss(msg, parent, s1, s2, s3);
		if (i != 0) {
			*s3 = NULL;
			i = cm_tdbusm_get_ss(msg, parent, s1, s2);
		}
	}
	return i;
}

int
cm_tdbusm_get_sososos(DBusMessage *msg, void *parent, char **s1, char **s2,
		      char **s3, char **s4)
{
	int i;
	i = cm_tdbusm_get_ssss(msg, parent, s1, s2, s3, s4);
	if (i != 0) {
		*s4 = NULL;
		i = cm_tdbusm_get_sss(msg, parent, s1, s2, s3);
		if (i != 0) {
			*s3 = NULL;
			i = cm_tdbusm_get_ss(msg, parent, s1, s2);
			if (i != 0) {
				*s2 = NULL;
				i = cm_tdbusm_get_s(msg, parent, s1);
			}
		}
	}
	return i;
}

int
cm_tdbusm_get_ssas(DBusMessage *msg, void *parent,
		   char **s1, char **s2, char ***as)
{
	DBusError err;
	char **tmp;
	int i;
	*s1 = NULL;
	*s2 = NULL;
	*as = NULL;
	dbus_error_init(&err);
	if (dbus_message_get_args(msg, &err,
				  DBUS_TYPE_STRING, s1,
				  DBUS_TYPE_STRING, s2,
				  DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &tmp, &i,
				  DBUS_TYPE_INVALID)) {
		*s1 = *s1 ? talloc_strdup(parent, *s1) : NULL;
		*s2 = *s2 ? talloc_strdup(parent, *s2) : NULL;
		*as = cm_tdbusm_take_dbus_string_array(parent, tmp, i);
		return 0;
	} else {
		if (dbus_error_is_set(&err)) {
			dbus_error_free(&err);
			dbus_error_init(&err);
		}
		return -1;
	}
}

int
cm_tdbusm_get_ssass(DBusMessage *msg, void *parent,
		    char **s1, char **s2, char ***ass)
{
	DBusMessageIter args, array, element;
	const char *p, *q, *r, *s;
	char **ret, **tmp;
	int i = 0;

	ret = NULL;
	if (!dbus_message_iter_init(msg, &args)) {
		return -1;
	}
	if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_STRING) {
		return -1;
	}
	dbus_message_iter_get_basic(&args, &p);
	if (!dbus_message_iter_has_next(&args) ||
	    !dbus_message_iter_next(&args) ||
	    (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_STRING)) {
		return -1;
	}
	dbus_message_iter_get_basic(&args, &q);
	if (!dbus_message_iter_has_next(&args) ||
	    !dbus_message_iter_next(&args) ||
	    (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_ARRAY)) {
		return -1;
	}

	memset(&array, 0, sizeof(array));
	dbus_message_iter_recurse(&args, &array);

	for (;;) {
		if (dbus_message_iter_get_arg_type(&array) != DBUS_TYPE_STRUCT) {
			talloc_free(ret);
			return -1;
		}
		dbus_message_iter_recurse(&array, &element);

		if (dbus_message_iter_get_arg_type(&element) != DBUS_TYPE_STRING) {
			talloc_free(ret);
			return -1;
		}
		r = NULL;
		dbus_message_iter_get_basic(&element, &r);
		if (!dbus_message_iter_has_next(&element) ||
		    !dbus_message_iter_next(&element) ||
		    (dbus_message_iter_get_arg_type(&element) != DBUS_TYPE_STRING)) {
			talloc_free(ret);
			return -1;
		}
		s = NULL;
		dbus_message_iter_get_basic(&element, &s);
		tmp = talloc_realloc(parent, ret, char *, i + 3);
		if (tmp == NULL) {
			talloc_free(ret);
			return -1;
		}
		ret = tmp;
		ret[i++] = talloc_strdup(ret, r);
		ret[i++] = talloc_strdup(ret, s);
		ret[i] = NULL;
		if (!dbus_message_iter_has_next(&array)) {
			break;
		}
		if (!dbus_message_iter_next(&array)) {
			talloc_free(ret);
			return -1;
		}
	}
	*s1 = talloc_strdup(parent, p);
	*s2 = talloc_strdup(parent, q);
	*ass = ret;
	return 0;
}

int
cm_tdbusm_get_sssas(DBusMessage *msg, void *parent,
		    char **s1, char **s2, char **s3, char ***as)
{
	DBusError err;
	char **tmp;
	int i;
	*s1 = NULL;
	*s2 = NULL;
	*s3 = NULL;
	*as = NULL;
	dbus_error_init(&err);
	if (dbus_message_get_args(msg, &err,
				  DBUS_TYPE_STRING, s1,
				  DBUS_TYPE_STRING, s2,
				  DBUS_TYPE_STRING, s3,
				  DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &tmp, &i,
				  DBUS_TYPE_INVALID)) {
		*s1 = *s1 ? talloc_strdup(parent, *s1) : NULL;
		*s2 = *s2 ? talloc_strdup(parent, *s2) : NULL;
		*s3 = *s3 ? talloc_strdup(parent, *s3) : NULL;
		*as = cm_tdbusm_take_dbus_string_array(parent, tmp, i);
		return 0;
	} else {
		if (dbus_error_is_set(&err)) {
			dbus_error_free(&err);
			dbus_error_init(&err);
		}
		return -1;
	}
}

int
cm_tdbusm_get_ssoas(DBusMessage *msg, void *parent,
		    char **s1, char **s2, char ***as)
{
	int i;
	i = cm_tdbusm_get_ssas(msg, parent, s1, s2, as);
	if (i != 0) {
		*as = NULL;
		i = cm_tdbusm_get_ss(msg, parent, s1, s2);
		if (i != 0) {
			*s2 = NULL;
			i = cm_tdbusm_get_s(msg, parent, s1);
		}
	}
	return i;
}

int
cm_tdbusm_get_sssnasasasnas(DBusMessage *msg, void *parent,
			    char **s1, char **s2, char **s3, long *n1,
			    char ***as1, char ***as2, char ***as3,
			    long *n2, char ***as4)
{
	DBusError err;
	char **tmp1, **tmp2, **tmp3, **tmp4;
	int64_t i641, i642;
	int32_t i321, i322;
	int16_t i161, i162;
	int i, j, k, l;
	*s1 = NULL;
	*s2 = NULL;
	*s3 = NULL;
	*as1 = NULL;
	*as2 = NULL;
	*as3 = NULL;
	*as4 = NULL;
	dbus_error_init(&err);
	if (!dbus_message_get_args(msg, &err,
				   DBUS_TYPE_STRING, s1,
				   DBUS_TYPE_STRING, s2,
				   DBUS_TYPE_STRING, s3,
				   DBUS_TYPE_INT64, &i641,
				   DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &tmp1, &i,
				   DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &tmp2, &j,
				   DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &tmp3, &k,
				   DBUS_TYPE_INT64, &i642,
				   DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &tmp4, &l,
				   DBUS_TYPE_INVALID)) {
		if (dbus_error_is_set(&err)) {
			dbus_error_free(&err);
			dbus_error_init(&err);
		}
		if (!dbus_message_get_args(msg, &err,
					   DBUS_TYPE_STRING, s1,
					   DBUS_TYPE_STRING, s2,
					   DBUS_TYPE_STRING, s3,
					   DBUS_TYPE_INT32, &i321,
					   DBUS_TYPE_ARRAY, DBUS_TYPE_STRING,
					   &tmp1, &i,
					   DBUS_TYPE_ARRAY, DBUS_TYPE_STRING,
					   &tmp2, &j,
					   DBUS_TYPE_ARRAY, DBUS_TYPE_STRING,
					   &tmp3, &k,
					   DBUS_TYPE_INT32, &i322,
					   DBUS_TYPE_ARRAY, DBUS_TYPE_STRING,
					   &tmp4, &l,
					   DBUS_TYPE_INVALID)) {
			if (dbus_error_is_set(&err)) {
				dbus_error_free(&err);
				dbus_error_init(&err);
			}
			if (!dbus_message_get_args(msg, &err,
						   DBUS_TYPE_STRING, s1,
						   DBUS_TYPE_STRING, s2,
						   DBUS_TYPE_STRING, s3,
						   DBUS_TYPE_INT16, &i161,
						   DBUS_TYPE_ARRAY,
						   DBUS_TYPE_STRING, &tmp1, &i,
						   DBUS_TYPE_ARRAY,
						   DBUS_TYPE_STRING, &tmp2, &j,
						   DBUS_TYPE_ARRAY,
						   DBUS_TYPE_STRING, &tmp3, &k,
						   DBUS_TYPE_INT16, &i162,
						   DBUS_TYPE_ARRAY,
						   DBUS_TYPE_STRING, &tmp4, &l,
						   DBUS_TYPE_INVALID)) {
				if (dbus_error_is_set(&err)) {
					dbus_error_free(&err);
					dbus_error_init(&err);
				}
				return -1;
			}
			i321 = i161;
			i322 = i162;
		}
		i641 = i321;
		i642 = i322;
	}
	*s1 = *s1 ? talloc_strdup(parent, *s1) : NULL;
	*s2 = *s2 ? talloc_strdup(parent, *s2) : NULL;
	*s3 = *s3 ? talloc_strdup(parent, *s3) : NULL;
	*n1 = i641;
	*n2 = i642;
	*as1 = cm_tdbusm_take_dbus_string_array(parent, tmp1, i);
	*as2 = cm_tdbusm_take_dbus_string_array(parent, tmp2, j);
	*as3 = cm_tdbusm_take_dbus_string_array(parent, tmp3, k);
	*as4 = cm_tdbusm_take_dbus_string_array(parent, tmp4, l);
	return 0;
}

int
cm_tdbusm_get_sssnasasasnasn(DBusMessage *msg, void *parent,
			    char **s1, char **s2, char **s3, long *n1,
			    char ***as1, char ***as2, char ***as3,
			    long *n2, char ***as4, long *n3)
{
	DBusError err;
	char **tmp1, **tmp2, **tmp3, **tmp4;
	int64_t i641, i642, i643;
	int32_t i321, i322, i323;
	int16_t i161, i162, i163;
	int i, j, k, l;
	*s1 = NULL;
	*s2 = NULL;
	*s3 = NULL;
	*as1 = NULL;
	*as2 = NULL;
	*as3 = NULL;
	*as4 = NULL;
	dbus_error_init(&err);
	if (!dbus_message_get_args(msg, &err,
				   DBUS_TYPE_STRING, s1,
				   DBUS_TYPE_STRING, s2,
				   DBUS_TYPE_STRING, s3,
				   DBUS_TYPE_INT64, &i641,
				   DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &tmp1, &i,
				   DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &tmp2, &j,
				   DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &tmp3, &k,
				   DBUS_TYPE_INT64, &i642,
				   DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &tmp4, &l,
				   DBUS_TYPE_INT64, &i643,
				   DBUS_TYPE_INVALID)) {
		if (dbus_error_is_set(&err)) {
			dbus_error_free(&err);
			dbus_error_init(&err);
		}
		if (!dbus_message_get_args(msg, &err,
					   DBUS_TYPE_STRING, s1,
					   DBUS_TYPE_STRING, s2,
					   DBUS_TYPE_STRING, s3,
					   DBUS_TYPE_INT32, &i321,
					   DBUS_TYPE_ARRAY, DBUS_TYPE_STRING,
					   &tmp1, &i,
					   DBUS_TYPE_ARRAY, DBUS_TYPE_STRING,
					   &tmp2, &j,
					   DBUS_TYPE_ARRAY, DBUS_TYPE_STRING,
					   &tmp3, &k,
					   DBUS_TYPE_INT32, &i322,
					   DBUS_TYPE_ARRAY, DBUS_TYPE_STRING,
					   &tmp4, &l,
					   DBUS_TYPE_INT32, &i323,
					   DBUS_TYPE_INVALID)) {
			if (dbus_error_is_set(&err)) {
				dbus_error_free(&err);
				dbus_error_init(&err);
			}
			if (!dbus_message_get_args(msg, &err,
						   DBUS_TYPE_STRING, s1,
						   DBUS_TYPE_STRING, s2,
						   DBUS_TYPE_STRING, s3,
						   DBUS_TYPE_INT16, &i161,
						   DBUS_TYPE_ARRAY,
						   DBUS_TYPE_STRING, &tmp1, &i,
						   DBUS_TYPE_ARRAY,
						   DBUS_TYPE_STRING, &tmp2, &j,
						   DBUS_TYPE_ARRAY,
						   DBUS_TYPE_STRING, &tmp3, &k,
						   DBUS_TYPE_INT16, &i162,
						   DBUS_TYPE_ARRAY,
						   DBUS_TYPE_STRING, &tmp4, &l,
						   DBUS_TYPE_INT16, &i163,
						   DBUS_TYPE_INVALID)) {
				if (dbus_error_is_set(&err)) {
					dbus_error_free(&err);
					dbus_error_init(&err);
				}
				return -1;
			}
			i321 = i161;
			i322 = i162;
			i323 = i163;
		}
		i641 = i321;
		i642 = i322;
		i643 = i323;
	}
	*s1 = *s1 ? talloc_strdup(parent, *s1) : NULL;
	*s2 = *s2 ? talloc_strdup(parent, *s2) : NULL;
	*s3 = *s3 ? talloc_strdup(parent, *s3) : NULL;
	*n1 = i641;
	*n2 = i642;
	*n3 = i643;
	*as1 = cm_tdbusm_take_dbus_string_array(parent, tmp1, i);
	*as2 = cm_tdbusm_take_dbus_string_array(parent, tmp2, j);
	*as3 = cm_tdbusm_take_dbus_string_array(parent, tmp3, k);
	*as4 = cm_tdbusm_take_dbus_string_array(parent, tmp4, l);
	return 0;
}

int
cm_tdbusm_get_sasasasnas(DBusMessage *msg, void *parent, char **s,
			 char ***as1, char ***as2, char ***as3,
			 long *n, char ***as4)
{
	DBusError err;
	char **tmp1, **tmp2, **tmp3, **tmp4;
	int64_t i64;
	int32_t i32;
	int16_t i16;
	int i, j, k, l;
	*s = NULL;
	*as1 = NULL;
	*as2 = NULL;
	*as3 = NULL;
	*as4 = NULL;
	dbus_error_init(&err);
	if (!dbus_message_get_args(msg, &err,
				   DBUS_TYPE_STRING, s,
				   DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &tmp1, &i,
				   DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &tmp2, &j,
				   DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &tmp3, &k,
				   DBUS_TYPE_INT64, &i64,
				   DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &tmp4, &l,
				   DBUS_TYPE_INVALID)) {
		if (dbus_error_is_set(&err)) {
			dbus_error_free(&err);
			dbus_error_init(&err);
		}
		if (!dbus_message_get_args(msg, &err,
					   DBUS_TYPE_STRING, s,
					   DBUS_TYPE_ARRAY,
					   DBUS_TYPE_STRING, &tmp1, &i,
					   DBUS_TYPE_ARRAY,
					   DBUS_TYPE_STRING, &tmp2, &j,
					   DBUS_TYPE_ARRAY,
					   DBUS_TYPE_STRING, &tmp3, &k,
					   DBUS_TYPE_INT32, &i32,
					   DBUS_TYPE_ARRAY,
					   DBUS_TYPE_STRING, &tmp4, &l,
					   DBUS_TYPE_INVALID)) {
			if (dbus_error_is_set(&err)) {
				dbus_error_free(&err);
				dbus_error_init(&err);
			}
			if (!dbus_message_get_args(msg, &err,
						   DBUS_TYPE_STRING, s,
						   DBUS_TYPE_ARRAY,
						   DBUS_TYPE_STRING, &tmp1, &i,
						   DBUS_TYPE_ARRAY,
						   DBUS_TYPE_STRING, &tmp2, &j,
						   DBUS_TYPE_ARRAY,
						   DBUS_TYPE_STRING, &tmp3, &k,
						   DBUS_TYPE_INT16, &i16,
						   DBUS_TYPE_ARRAY,
						   DBUS_TYPE_STRING, &tmp4, &l,
						   DBUS_TYPE_INVALID)) {
				if (dbus_error_is_set(&err)) {
					dbus_error_free(&err);
					dbus_error_init(&err);
				}
				return -1;
			}
			i32 = i16;
		}
		i64 = i32;
	}
	*s = *s ? talloc_strdup(parent, *s) : NULL;
	*as1 = cm_tdbusm_take_dbus_string_array(parent, tmp1, i);
	*as2 = cm_tdbusm_take_dbus_string_array(parent, tmp2, j);
	*as3 = cm_tdbusm_take_dbus_string_array(parent, tmp3, k);
	*n = i64;
	*as4 = cm_tdbusm_take_dbus_string_array(parent, tmp4, l);
	return 0;
}

static struct cm_tdbusm_dict *
cm_tdbusm_get_d_value(DBusMessageIter *item, void *parent,
		      struct cm_tdbusm_dict *dict)
{
	struct cm_tdbusm_dict **dicts;
	char *s, **as, **ass;
	int64_t i64;
	int32_t i32;
	int16_t i16;
	int n_values;
	DBusMessageIter value, sval, fields;

	/* Pull out a variant. */
	switch (dbus_message_iter_get_arg_type(item)) {
	case DBUS_TYPE_VARIANT:
		memset(&value, 0, sizeof(value));
		dbus_message_iter_recurse(item, &value);
		switch (dbus_message_iter_get_arg_type(&value)) {
		/* The variant value can be a boolean. */
		case DBUS_TYPE_BOOLEAN:
			dict->value_type = cm_tdbusm_dict_b;
			dbus_message_iter_get_basic(&value, &dict->value.b);
			break;
		/* It can be a path. */
		case DBUS_TYPE_OBJECT_PATH:
			dict->value_type = cm_tdbusm_dict_p;
			dbus_message_iter_get_basic(&value, &s);
			dict->value.s = talloc_strdup(dict, s);
			break;
		/* It can be a string. */
		case DBUS_TYPE_STRING:
			dict->value_type = cm_tdbusm_dict_s;
			dbus_message_iter_get_basic(&value, &s);
			dict->value.s = talloc_strdup(dict, s);
			break;
		/* It can be an integer type. */
		case DBUS_TYPE_INT16:
			dict->value_type = cm_tdbusm_dict_n;
			dbus_message_iter_get_basic(&value, &i16);
			dict->value.n = i16;
			break;
		case DBUS_TYPE_INT32:
			dict->value_type = cm_tdbusm_dict_n;
			dbus_message_iter_get_basic(&value, &i32);
			dict->value.n = i32;
			break;
		case DBUS_TYPE_INT64:
			dict->value_type = cm_tdbusm_dict_n;
			dbus_message_iter_get_basic(&value, &i64);
			dict->value.n = i64;
			break;
		/* It can be an array of strings. */
		case DBUS_TYPE_ARRAY:
			memset(&sval, 0, sizeof(sval));
			dbus_message_iter_recurse(&value, &sval);
			as = NULL;
			ass = NULL;
			n_values = 0;
			for (;;) {
				/* This had better be a string or a struct
				 * containing two strings. */
				switch (dbus_message_iter_get_arg_type(&sval)) {
				case DBUS_TYPE_STRING:
					dict->value_type = cm_tdbusm_dict_as;
					dbus_message_iter_get_basic(&sval, &s);
					as = talloc_realloc(dict, as, char *,
							    n_values + 2);
					if (as == NULL) {
						talloc_free(dict);
						return NULL;
					}
					as[n_values] = talloc_strdup(as, s);
					if (as[n_values] == NULL) {
						talloc_free(dict);
						return NULL;
					}
					n_values++;
					as[n_values] = NULL;
					dict->value.as = as;
					break;
				case DBUS_TYPE_STRUCT:
					dict->value_type = cm_tdbusm_dict_ass;
					dbus_message_iter_recurse(&sval, &fields);
					if (dbus_message_iter_get_arg_type(&fields) != DBUS_TYPE_STRING) {
						talloc_free(dict);
						return NULL;
					}
					ass = talloc_realloc(dict, ass, char *,
							     n_values + 3);
					if (ass == NULL) {
						talloc_free(dict);
						return NULL;
					}
					dbus_message_iter_get_basic(&fields, &s);
					ass[n_values] = talloc_strdup(ass, s);
					if (!dbus_message_iter_has_next(&fields) ||
					    (dbus_message_iter_get_arg_type(&fields) != DBUS_TYPE_STRING) ||
					    !dbus_message_iter_next(&fields)) {
						talloc_free(dict);
						return NULL;
					}
					dbus_message_iter_get_basic(&fields, &s);
					ass[n_values + 1] = talloc_strdup(ass, s);
					n_values += 2;
					ass[n_values] = NULL;
					dict->value.ass = ass;
					break;
				case DBUS_TYPE_DICT_ENTRY:
					dict->value_type = cm_tdbusm_dict_d;
					dicts = cm_tdbusm_get_d_array(&sval, dict);
					dict->value.d = (const struct cm_tdbusm_dict **) dicts;
					break;
				case DBUS_TYPE_INVALID:
					dict->value_type = cm_tdbusm_dict_invalid;
					memset(&dict->value, 0, sizeof(dict->value));
					break;
				default:
					cm_log(6, "Unexpected array member type %c (%d)\n",
					       dbus_message_iter_get_arg_type(&sval),
					       dbus_message_iter_get_arg_type(&sval));
					talloc_free(dict);
					return NULL;
					break;
				}
				/* Move on to the next element. */
				if (dbus_message_iter_has_next(&sval)) {
					if (!dbus_message_iter_next(&sval)) {
						talloc_free(dict);
						return NULL;
					}
				} else {
					/* Out of elements. */
					break;
				}
			}
			break;
		default:
			/* It had better not be something else. */
			talloc_free(dict);
			return NULL;
			break;
		}
		break;
	default:
		talloc_free(dict);
		return NULL;
		break;
	}
	return dict;
}

static struct cm_tdbusm_dict *
cm_tdbusm_get_d_item(DBusMessageIter *item, void *parent)
{
	struct cm_tdbusm_dict *dict;
	char *s;

	dict = talloc_ptrtype(parent, dict);
	if (dict == NULL) {
		return NULL;
	}
	memset(dict, 0, sizeof(*dict));

	/* Pull out a string. */
	switch (dbus_message_iter_get_arg_type(item)) {
	case DBUS_TYPE_STRING:
		dbus_message_iter_get_basic(item, &s);
		dict->key = talloc_strdup(dict, s);
		break;
	default:
		talloc_free(dict);
		return NULL;
		break;
	}
	if (!dbus_message_iter_has_next(item) ||
	    !dbus_message_iter_next(item)) {
		talloc_free(dict);
		return NULL;
	}
	/* Pull out the corresponding value, whatever it is. */
	return cm_tdbusm_get_d_value(item, parent, dict);
}

static struct cm_tdbusm_dict **
cm_tdbusm_get_d_array(DBusMessageIter *array, void *parent)
{
	struct cm_tdbusm_dict *ditem, **dict, **tmp;
	int n_items;
	DBusMessageIter item;

	dict = NULL;
	n_items = 0;
	for (;;) {
		/* We'd better be walking a list of dictionary entries. */
		switch (dbus_message_iter_get_arg_type(array)) {
		case DBUS_TYPE_DICT_ENTRY:
			/* Found a dictionary entry. */
			memset(&item, 0, sizeof(item));
			dbus_message_iter_recurse(array, &item);
			ditem = cm_tdbusm_get_d_item(&item, parent);
			if (ditem == NULL) {
				talloc_free(dict);
				return NULL;
			}
			tmp = talloc_realloc(parent, dict,
					     struct cm_tdbusm_dict *,
					     n_items + 2);
			if (tmp != NULL) {
				tmp[n_items] = ditem;
				n_items++;
				tmp[n_items] = NULL;
				dict = tmp;
			}
			break;
		default:
			/* Found... something else. */
			talloc_free(dict);
			return NULL;
			break;
		}
		if (dbus_message_iter_has_next(array)) {
			if (!dbus_message_iter_next(array)) {
				talloc_free(dict);
				return NULL;
			}
		} else {
			break;
		}
	}
	return dict;
}

int
cm_tdbusm_get_d(DBusMessage *msg, void *parent, struct cm_tdbusm_dict ***d)
{
	struct cm_tdbusm_dict **tdicts, **dicts, **tmp;
	DBusMessageIter args, array;
	int i, n_dicts;

	*d = NULL;
	dicts = NULL;
	n_dicts = 0;
	memset(&args, 0, sizeof(args));
	if (dbus_message_iter_init(msg, &args)) {
		for (;;) {
			switch (dbus_message_iter_get_arg_type(&args)) {
			case DBUS_TYPE_ARRAY:
				memset(&array, 0, sizeof(array));
				dbus_message_iter_recurse(&args, &array);
				tdicts = cm_tdbusm_get_d_array(&array, parent);
				if (tdicts == NULL) {
					talloc_free(dicts);
					return -1;
				}
				for (i = 0; tdicts[i] != NULL; i++) {
					continue;
				}
				tmp = talloc_realloc(parent, dicts,
						     struct cm_tdbusm_dict *,
						     n_dicts + i + 1);
				if (tmp != NULL) {
					memcpy(tmp + n_dicts,
					       tdicts,
					       i * sizeof(tdicts[0]));
					n_dicts += i;
					tmp[n_dicts] = NULL;
					dicts = tmp;
				} else {
					talloc_free(tdicts);
					talloc_free(dicts);
					return -1;
				}
				break;
			default:
				talloc_free(dicts);
				return -1;
				break;
			}
			if (dbus_message_iter_has_next(&args)) {
				if (!dbus_message_iter_next(&args)) {
					talloc_free(dicts);
					return -1;
				}
			} else {
				break;
			}
		}
		*d = dicts;
		return 0;
	}
	return -1;
}

int
cm_tdbusm_get_sd(DBusMessage *msg, void *parent,
		 char **s, struct cm_tdbusm_dict ***d)
{
	struct cm_tdbusm_dict **tdicts, **dicts, **tmp;
	DBusMessageIter args, array;
	int i, n_dicts;
	*d = NULL;
	dicts = NULL;
	n_dicts = 0;
	memset(&args, 0, sizeof(args));
	if (dbus_message_iter_init(msg, &args)) {
		if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_STRING) {
			return -1;
		}
		dbus_message_iter_get_basic(&args, s);
		if (*s == NULL) {
			return -1;
		}
		*s = talloc_strdup(parent, *s);
		if (!dbus_message_iter_has_next(&args) ||
		    !dbus_message_iter_next(&args)) {
			return -1;
		}
		if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_ARRAY) {
			return -1;
		}
		memset(&array, 0, sizeof(array));
		dbus_message_iter_recurse(&args, &array);
		tdicts = cm_tdbusm_get_d_array(&array, parent);
		if (tdicts != NULL) {
			for (i = 0; tdicts[i] != NULL; i++) {
				continue;
			}
			tmp = talloc_realloc(parent, dicts,
					     struct cm_tdbusm_dict *,
					     n_dicts + i + 1);
			if (tmp != NULL) {
				memcpy(tmp + n_dicts,
				       tdicts,
				       i * sizeof(tdicts[0]));
				n_dicts += i;
				tmp[n_dicts] = NULL;
				dicts = tmp;
			} else {
				talloc_free(tdicts);
				talloc_free(dicts);
				return -1;
			}
		}
		if (dbus_message_iter_has_next(&args)) {
			if (!dbus_message_iter_next(&args)) {
				talloc_free(dicts);
				return -1;
			}
		}
		*d = dicts;
		return 0;
	}
	return -1;
}

int
cm_tdbusm_set_b(DBusMessage *msg, dbus_bool_t b)
{
	if (dbus_message_append_args(msg,
				     DBUS_TYPE_BOOLEAN, &b,
				     DBUS_TYPE_INVALID)) {
		return 0;
	} else {
		return -1;
	}
}

int
cm_tdbusm_set_n(DBusMessage *msg, long n)
{
	int64_t i = n;
	if (dbus_message_append_args(msg,
				     DBUS_TYPE_INT64, &i,
				     DBUS_TYPE_INVALID)) {
		return 0;
	} else {
		return -1;
	}
}

int
cm_tdbusm_set_p(DBusMessage *msg, const char *p)
{
	if (dbus_message_append_args(msg,
				     DBUS_TYPE_OBJECT_PATH, &p,
				     DBUS_TYPE_INVALID)) {
		return 0;
	} else {
		return -1;
	}
}

int
cm_tdbusm_set_s(DBusMessage *msg, const char *s)
{
	if (s == NULL) {
		s = empty_string;
	}
	if (dbus_message_append_args(msg,
				     DBUS_TYPE_STRING, &s,
				     DBUS_TYPE_INVALID)) {
		return 0;
	} else {
		return -1;
	}
}

int
cm_tdbusm_set_bs(DBusMessage *msg, dbus_bool_t b, const char *s)
{
	if (s == NULL) {
		s = empty_string;
	}
	if (dbus_message_append_args(msg,
				     DBUS_TYPE_BOOLEAN, &b,
				     DBUS_TYPE_STRING, &s,
				     DBUS_TYPE_INVALID)) {
		return 0;
	} else {
		return -1;
	}
}

int
cm_tdbusm_set_bp(DBusMessage *msg, dbus_bool_t b, const char *p)
{
	if (dbus_message_append_args(msg,
				     DBUS_TYPE_BOOLEAN, &b,
				     DBUS_TYPE_OBJECT_PATH, &p,
				     DBUS_TYPE_INVALID)) {
		return 0;
	} else {
		return -1;
	}
}

int
cm_tdbusm_set_sb(DBusMessage *msg, const char *s, dbus_bool_t b)
{
	if (s == NULL) {
		s = empty_string;
	}
	if (dbus_message_append_args(msg,
				     DBUS_TYPE_STRING, &s,
				     DBUS_TYPE_BOOLEAN, &b,
				     DBUS_TYPE_INVALID)) {
		return 0;
	} else {
		return -1;
	}
}

int
cm_tdbusm_set_sn(DBusMessage *msg, const char *s, long n)
{
	int64_t i = n;
	if (s == NULL) {
		s = empty_string;
	}
	if (dbus_message_append_args(msg,
				     DBUS_TYPE_STRING, &s,
				     DBUS_TYPE_INT64, &i,
				     DBUS_TYPE_INVALID)) {
		return 0;
	} else {
		return -1;
	}
}

int
cm_tdbusm_set_ss(DBusMessage *msg, const char *s1, const char *s2)
{
	if (s1 == NULL) {
		s1 = empty_string;
	}
	if (s2 == NULL) {
		s2 = empty_string;
	}
	if (dbus_message_append_args(msg,
				     DBUS_TYPE_STRING, &s1,
				     DBUS_TYPE_STRING, &s2,
				     DBUS_TYPE_INVALID)) {
		return 0;
	} else {
		return -1;
	}
}

int
cm_tdbusm_set_ssb(DBusMessage *msg, const char *s1, const char *s2,
		  dbus_bool_t b)
{
	if (s1 == NULL) {
		s1 = empty_string;
	}
	if (s2 == NULL) {
		s2 = empty_string;
	}
	if (dbus_message_append_args(msg,
				     DBUS_TYPE_STRING, &s1,
				     DBUS_TYPE_STRING, &s2,
				     DBUS_TYPE_BOOLEAN, &b,
				     DBUS_TYPE_INVALID)) {
		return 0;
	} else {
		return -1;
	}
}

int
cm_tdbusm_set_ssn(DBusMessage *msg, const char *s1, const char *s2,
		  long n)
{
	int64_t i = n;
	if (s1 == NULL) {
		s1 = empty_string;
	}
	if (s2 == NULL) {
		s2 = empty_string;
	}
	if (dbus_message_append_args(msg,
				     DBUS_TYPE_STRING, &s1,
				     DBUS_TYPE_STRING, &s2,
				     DBUS_TYPE_INT64, &i,
				     DBUS_TYPE_INVALID)) {
		return 0;
	} else {
		return -1;
	}
}

int
cm_tdbusm_set_ap(DBusMessage *msg, const char **ap)
{
	if (dbus_message_append_args(msg,
				     DBUS_TYPE_ARRAY, DBUS_TYPE_OBJECT_PATH,
				     &ap, cm_tdbusm_array_length(ap),
				     DBUS_TYPE_INVALID)) {
		return 0;
	} else {
		return -1;
	}
}

int
cm_tdbusm_set_as(DBusMessage *msg, const char **as)
{
	if (as == NULL) {
		as = empty_string_array;
	}
	if (dbus_message_append_args(msg,
				     DBUS_TYPE_ARRAY, DBUS_TYPE_STRING,
				     &as, cm_tdbusm_array_length(as),
				     DBUS_TYPE_INVALID)) {
		return 0;
	} else {
		return -1;
	}
}

int
cm_tdbusm_set_ass(DBusMessage *msg, const char **ss)
{
	DBusMessageIter args, array, entry;
	const char *p;
	int i;

	memset(&args, 0, sizeof(args));
	dbus_message_iter_init_append(msg, &args);
	memset(&array, 0, sizeof(array));
	dbus_message_iter_open_container(&args,
					 DBUS_TYPE_ARRAY,
					 DBUS_STRUCT_BEGIN_CHAR_AS_STRING
					 DBUS_TYPE_STRING_AS_STRING
					 DBUS_TYPE_STRING_AS_STRING
					 DBUS_STRUCT_END_CHAR_AS_STRING,
					 &array);
	for (i = 0;
	     (ss != NULL) && (ss[i] != NULL) && (ss[i + 1] != NULL);
	     i += 2) {
		memset(&entry, 0, sizeof(entry));
		dbus_message_iter_open_container(&array, DBUS_TYPE_STRUCT,
						 NULL, &entry);
		p = ss[i];
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &p);
		p = ss[i + 1];
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &p);
		dbus_message_iter_close_container(&array, &entry);
	}
	dbus_message_iter_close_container(&args, &array);
	return (i > 0) ? 0 : -1;
}

int
cm_tdbusm_set_sss(DBusMessage *msg, const char *s1, const char *s2,
		  const char *s3)
{
	if (s1 == NULL) {
		s1 = empty_string;
	}
	if (s2 == NULL) {
		s2 = empty_string;
	}
	if (s3 == NULL) {
		s3 = empty_string;
	}
	if (dbus_message_append_args(msg,
				     DBUS_TYPE_STRING, &s1,
				     DBUS_TYPE_STRING, &s2,
				     DBUS_TYPE_STRING, &s3,
				     DBUS_TYPE_INVALID)) {
		return 0;
	} else {
		return -1;
	}
}

int
cm_tdbusm_set_ssvs(DBusMessage *msg, const char *s1, const char *s2,
		   const char *s3)
{
	DBusMessageIter args;
	union cm_tdbusm_variant v;
	char *p;

	memset(&args, 0, sizeof(args));
	dbus_message_iter_init_append(msg, &args);
	dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &s1);
	dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &s2);
	p = strdup(s3);
	memset(&v, 0, sizeof(v));
	v.s = p;
	cm_tdbusm_append_d_value(msg, &args, cm_tdbusm_dict_s, &v);
	free(p);
	return 0;
}

int
cm_tdbusm_set_ssss(DBusMessage *msg, const char *s1, const char *s2,
		   const char *s3, const char *s4)
{
	if (s1 == NULL) {
		s1 = empty_string;
	}
	if (s2 == NULL) {
		s2 = empty_string;
	}
	if (s3 == NULL) {
		s3 = empty_string;
	}
	if (s4 == NULL) {
		s4 = empty_string;
	}
	if (dbus_message_append_args(msg,
				     DBUS_TYPE_STRING, &s1,
				     DBUS_TYPE_STRING, &s2,
				     DBUS_TYPE_STRING, &s3,
				     DBUS_TYPE_STRING, &s4,
				     DBUS_TYPE_INVALID)) {
		return 0;
	} else {
		return -1;
	}
}

int
cm_tdbusm_set_ssas(DBusMessage *msg,
		   const char *s1, const char *s2, const char **as)
{
	if (s1 == NULL) {
		s1 = empty_string;
	}
	if (s2 == NULL) {
		s2 = empty_string;
	}
	if (as == NULL) {
		as = empty_string_array;
	}
	if (dbus_message_append_args(msg,
				     DBUS_TYPE_STRING, &s1,
				     DBUS_TYPE_STRING, &s2,
				     DBUS_TYPE_ARRAY, DBUS_TYPE_STRING,
				     &as, cm_tdbusm_array_length(as),
				     DBUS_TYPE_INVALID)) {
		return 0;
	} else {
		return -1;
	}
}

int
cm_tdbusm_set_ssass(DBusMessage *msg,
		    const char *s1, const char *s2, const char **ass)
{
	DBusMessageIter args, elt, fields;
	int i;

	memset(&args, 0, sizeof(args));
	if (s1 == NULL) {
		s1 = empty_string;
	}
	if (s2 == NULL) {
		s2 = empty_string;
	}
	if (ass == NULL) {
		ass = empty_string_array;
	}
	if (dbus_message_append_args(msg,
				     DBUS_TYPE_STRING, &s1,
				     DBUS_TYPE_STRING, &s2,
				     DBUS_TYPE_INVALID)) {
		dbus_message_iter_init_append(msg, &args);
		dbus_message_iter_open_container(&args,
						 DBUS_TYPE_ARRAY,
						 DBUS_STRUCT_BEGIN_CHAR_AS_STRING
						 DBUS_TYPE_STRING_AS_STRING
						 DBUS_TYPE_STRING_AS_STRING
						 DBUS_STRUCT_END_CHAR_AS_STRING,
						 &elt);
		for (i = 0;
		     (ass != NULL) && (ass[i] != NULL) && (ass[i + 1] != NULL);
		     i += 2) {
			dbus_message_iter_open_container(&elt,
							 DBUS_TYPE_STRUCT,
							 NULL,
							 &fields);
			dbus_message_iter_append_basic(&fields,
						       DBUS_TYPE_STRING,
						       &ass[i]);
			dbus_message_iter_append_basic(&fields,
						       DBUS_TYPE_STRING,
						       &ass[i + 1]);
			dbus_message_iter_close_container(&elt, &fields);
		}
		dbus_message_iter_close_container(&args, &elt);
		return 0;
	} else {
		return -1;
	}
}

int
cm_tdbusm_set_ssoas(DBusMessage *msg,
		    const char *s1, const char *s2, const char **as)
{
	if (s1 == NULL) {
		s1 = empty_string;
	}
	if (s2 == NULL) {
		s2 = empty_string;
	}
	if (as == NULL) {
		as = empty_string_array;
	}
	if (dbus_message_append_args(msg,
				     DBUS_TYPE_STRING, &s1,
				     DBUS_TYPE_STRING, &s2,
				     DBUS_TYPE_ARRAY, DBUS_TYPE_STRING,
				     &as, cm_tdbusm_array_length(as),
				     DBUS_TYPE_INVALID)) {
		return 0;
	} else {
		return -1;
	}
}

int
cm_tdbusm_set_sssas(DBusMessage *msg,
		    const char *s1, const char *s2,
		    const char *s3, const char **as)
{
	if (s1 == NULL) {
		s1 = empty_string;
	}
	if (s2 == NULL) {
		s2 = empty_string;
	}
	if (s3 == NULL) {
		s3 = empty_string;
	}
	if (as == NULL) {
		as = empty_string_array;
	}
	if (dbus_message_append_args(msg,
				     DBUS_TYPE_STRING, &s1,
				     DBUS_TYPE_STRING, &s2,
				     DBUS_TYPE_STRING, &s3,
				     DBUS_TYPE_ARRAY, DBUS_TYPE_STRING,
				     &as, cm_tdbusm_array_length(as),
				     DBUS_TYPE_INVALID)) {
		return 0;
	} else {
		return -1;
	}
}

int
cm_tdbusm_set_sssnasasasnas(DBusMessage *msg,
			    const char *s1, const char *s2, const char *s3,
			    long n1, const char **as1, const char **as2,
			    const char **as3, long n2, const char **as4)
{
	int64_t i1 = n1, i2 = n2;
	if (s1 == NULL) {
		s1 = empty_string;
	}
	if (s2 == NULL) {
		s2 = empty_string;
	}
	if (s3 == NULL) {
		s3 = empty_string;
	}
	if (as1 == NULL) {
		as1 = empty_string_array;
	}
	if (as2 == NULL) {
		as2 = empty_string_array;
	}
	if (as3 == NULL) {
		as3 = empty_string_array;
	}
	if (as4 == NULL) {
		as4 = empty_string_array;
	}
	if (dbus_message_append_args(msg,
				     DBUS_TYPE_STRING, &s1,
				     DBUS_TYPE_STRING, &s2,
				     DBUS_TYPE_STRING, &s3,
				     DBUS_TYPE_INT64, &i1,
				     DBUS_TYPE_ARRAY, DBUS_TYPE_STRING,
				     &as1, cm_tdbusm_array_length(as1),
				     DBUS_TYPE_ARRAY, DBUS_TYPE_STRING,
				     &as2, cm_tdbusm_array_length(as2),
				     DBUS_TYPE_ARRAY, DBUS_TYPE_STRING,
				     &as3, cm_tdbusm_array_length(as3),
				     DBUS_TYPE_INT64, &i2,
				     DBUS_TYPE_ARRAY, DBUS_TYPE_STRING,
				     &as4, cm_tdbusm_array_length(as4),
				     DBUS_TYPE_INVALID)) {
		return 0;
	} else {
		return -1;
	}
}

int
cm_tdbusm_set_sssnasasasnasn(DBusMessage *msg,
			    const char *s1, const char *s2, const char *s3,
			    long n1, const char **as1, const char **as2,
			    const char **as3, long n2, const char **as4,
			    long n3)
{
	int64_t i1 = n1, i2 = n2, i3 = n3;
	if (s1 == NULL) {
		s1 = empty_string;
	}
	if (s2 == NULL) {
		s2 = empty_string;
	}
	if (s3 == NULL) {
		s3 = empty_string;
	}
	if (as1 == NULL) {
		as1 = empty_string_array;
	}
	if (as2 == NULL) {
		as2 = empty_string_array;
	}
	if (as3 == NULL) {
		as3 = empty_string_array;
	}
	if (as4 == NULL) {
		as4 = empty_string_array;
	}
	if (dbus_message_append_args(msg,
				     DBUS_TYPE_STRING, &s1,
				     DBUS_TYPE_STRING, &s2,
				     DBUS_TYPE_STRING, &s3,
				     DBUS_TYPE_INT64, &i1,
				     DBUS_TYPE_ARRAY, DBUS_TYPE_STRING,
				     &as1, cm_tdbusm_array_length(as1),
				     DBUS_TYPE_ARRAY, DBUS_TYPE_STRING,
				     &as2, cm_tdbusm_array_length(as2),
				     DBUS_TYPE_ARRAY, DBUS_TYPE_STRING,
				     &as3, cm_tdbusm_array_length(as3),
				     DBUS_TYPE_INT64, &i2,
				     DBUS_TYPE_ARRAY, DBUS_TYPE_STRING,
				     &as4, cm_tdbusm_array_length(as4),
				     DBUS_TYPE_INT64, &i3,
				     DBUS_TYPE_INVALID)) {
		return 0;
	} else {
		return -1;
	}
}

int
cm_tdbusm_set_sasasasnas(DBusMessage *msg, const char *s,
			 const char **as1, const char **as2,
			 const char **as3, long n, const char **as4)
{
	int64_t i = n;
	if (s == NULL) {
		s = empty_string;
	}
	if (as1 == NULL) {
		as1 = empty_string_array;
	}
	if (as2 == NULL) {
		as2 = empty_string_array;
	}
	if (as3 == NULL) {
		as3 = empty_string_array;
	}
	if (as4 == NULL) {
		as4 = empty_string_array;
	}
	if (dbus_message_append_args(msg,
				     DBUS_TYPE_STRING, &s,
				     DBUS_TYPE_ARRAY, DBUS_TYPE_STRING,
				     &as1, cm_tdbusm_array_length(as1),
				     DBUS_TYPE_ARRAY, DBUS_TYPE_STRING,
				     &as2, cm_tdbusm_array_length(as2),
				     DBUS_TYPE_ARRAY, DBUS_TYPE_STRING,
				     &as3, cm_tdbusm_array_length(as3),
				     DBUS_TYPE_INT64, &i,
				     DBUS_TYPE_ARRAY, DBUS_TYPE_STRING,
				     &as4, cm_tdbusm_array_length(as4),
				     DBUS_TYPE_INVALID)) {
		return 0;
	} else {
		return -1;
	}
}

static int
cm_tdbusm_append_d_value(DBusMessage *msg, DBusMessageIter *args,
			 enum cm_tdbusm_dict_value_type value_type,
			 const union cm_tdbusm_variant *value)
{
	DBusMessageIter val, elt, fields;
	int subs = 0;
	int64_t l;

	memset(&val, 0, sizeof(val));
	switch (value_type) {
	case cm_tdbusm_dict_invalid:
		dbus_message_iter_open_container(args,
						 DBUS_TYPE_VARIANT,
						 DBUS_TYPE_INVALID_AS_STRING,
						 &val);
		dbus_message_iter_append_basic(&val,
					       DBUS_TYPE_INVALID,
					       NULL);
		dbus_message_iter_close_container(args, &val);
		break;
	case cm_tdbusm_dict_b:
		dbus_message_iter_open_container(args,
						 DBUS_TYPE_VARIANT,
						 DBUS_TYPE_BOOLEAN_AS_STRING,
						 &val);
		dbus_message_iter_append_basic(&val,
					       DBUS_TYPE_BOOLEAN,
					       &value->b);
		dbus_message_iter_close_container(args, &val);
		break;
	case cm_tdbusm_dict_n:
		dbus_message_iter_open_container(args,
						 DBUS_TYPE_VARIANT,
						 DBUS_TYPE_INT64_AS_STRING,
						 &val);
		l = value->n;
		dbus_message_iter_append_basic(&val,
					       DBUS_TYPE_INT64,
					       &l);
		dbus_message_iter_close_container(args, &val);
		break;
	case cm_tdbusm_dict_p:
		dbus_message_iter_open_container(args,
						 DBUS_TYPE_VARIANT,
						 DBUS_TYPE_OBJECT_PATH_AS_STRING,
						 &val);
		dbus_message_iter_append_basic(&val,
					       DBUS_TYPE_OBJECT_PATH,
					       &value->s);
		dbus_message_iter_close_container(args, &val);
		break;
	case cm_tdbusm_dict_s:
		dbus_message_iter_open_container(args,
						 DBUS_TYPE_VARIANT,
						 DBUS_TYPE_STRING_AS_STRING,
						 &val);
		dbus_message_iter_append_basic(&val,
					       DBUS_TYPE_STRING,
					       &value->s);
		dbus_message_iter_close_container(args, &val);
		break;
	case cm_tdbusm_dict_as:
		dbus_message_iter_open_container(args,
						 DBUS_TYPE_VARIANT,
						 DBUS_TYPE_ARRAY_AS_STRING
						 DBUS_TYPE_STRING_AS_STRING,
						 &val);
		memset(&elt, 0, sizeof(elt));
		dbus_message_iter_open_container(&val,
						 DBUS_TYPE_ARRAY,
						 DBUS_TYPE_STRING_AS_STRING,
						 &elt);
		for (l = 0;
		     (value->as != NULL) && (value->as[l] != NULL);
		     l++) {
			dbus_message_iter_append_basic(&elt,
						       DBUS_TYPE_STRING,
						       &value->as[l]);
		}
		dbus_message_iter_close_container(&val, &elt);
		dbus_message_iter_close_container(args, &val);
		break;
	case cm_tdbusm_dict_ass:
		dbus_message_iter_open_container(args,
						 DBUS_TYPE_VARIANT,
						 DBUS_TYPE_ARRAY_AS_STRING
						 DBUS_STRUCT_BEGIN_CHAR_AS_STRING
						 DBUS_TYPE_STRING_AS_STRING
						 DBUS_TYPE_STRING_AS_STRING
						 DBUS_STRUCT_END_CHAR_AS_STRING,
						 &val);
		memset(&elt, 0, sizeof(elt));
		dbus_message_iter_open_container(&val,
						 DBUS_TYPE_ARRAY,
						 DBUS_STRUCT_BEGIN_CHAR_AS_STRING
						 DBUS_TYPE_STRING_AS_STRING
						 DBUS_TYPE_STRING_AS_STRING
						 DBUS_STRUCT_END_CHAR_AS_STRING,
						 &elt);
		for (l = 0;
		     (value->ass != NULL) &&
		     (value->ass[l] != NULL) &&
		     (value->ass[l + 1] != NULL);
		     l += 2) {
			memset(&fields, 0, sizeof(fields));
			dbus_message_iter_open_container(&elt,
							 DBUS_TYPE_STRUCT,
							 NULL,
							 &fields);
			dbus_message_iter_append_basic(&fields,
						       DBUS_TYPE_STRING,
						       &value->ass[l]);
			dbus_message_iter_append_basic(&fields,
						       DBUS_TYPE_STRING,
						       &value->ass[l + 1]);
			dbus_message_iter_close_container(&elt, &fields);
		}
		dbus_message_iter_close_container(&val, &elt);
		dbus_message_iter_close_container(args, &val);
		break;
	case cm_tdbusm_dict_d:
		dbus_message_iter_open_container(args,
						 DBUS_TYPE_VARIANT,
						 DBUS_TYPE_ARRAY_AS_STRING
						 DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
						 DBUS_TYPE_STRING_AS_STRING
						 DBUS_TYPE_VARIANT_AS_STRING
						 DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
						 &val);
		subs += cm_tdbusm_append_d(msg, &val,
					   (const struct cm_tdbusm_dict **) value->d);
		dbus_message_iter_close_container(args, &val);
		break;
	}
	return subs;
}

static int
cm_tdbusm_append_d_item(DBusMessage *msg, DBusMessageIter *args,
			const struct cm_tdbusm_dict *d)
{
	DBusMessageIter entry;
	int subs = 0;

	memset(&entry, 0, sizeof(entry));
	dbus_message_iter_open_container(args, DBUS_TYPE_DICT_ENTRY, NULL,
					 &entry);
	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &d->key);
	subs = cm_tdbusm_append_d_value(msg, &entry, d->value_type, &d->value);
	dbus_message_iter_close_container(args, &entry);
	return subs;
}

static int
cm_tdbusm_append_d(DBusMessage *msg, DBusMessageIter *args,
		   const struct cm_tdbusm_dict **d)
{
	DBusMessageIter array;
	int i, subs = 0;

	memset(&array, 0, sizeof(array));
	dbus_message_iter_open_container(args,
					 DBUS_TYPE_ARRAY,
					 DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
					 DBUS_TYPE_STRING_AS_STRING
					 DBUS_TYPE_VARIANT_AS_STRING
					 DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
					 &array);
	for (i = 0; (d != NULL) && (d[i] != NULL); i++) {
		subs += cm_tdbusm_append_d_item(msg, &array, d[i]);
	}
	dbus_message_iter_close_container(args, &array);
	return i + subs;
}

static int
cm_tdbusm_set_osd(DBusMessage *msg,
		  const char *s, const struct cm_tdbusm_dict **d)
{
	DBusMessageIter args;
	int i;

	memset(&args, 0, sizeof(args));
	dbus_message_iter_init_append(msg, &args);
	if (s != NULL) {
		dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &s);
	}
	i = cm_tdbusm_append_d(msg, &args, d);
	return (i > 0) ? 0 : -1;
}

int
cm_tdbusm_set_d(DBusMessage *msg, const struct cm_tdbusm_dict **d)
{
	return cm_tdbusm_set_osd(msg, NULL, d);
}

int
cm_tdbusm_set_v(DBusMessage *msg, enum cm_tdbusm_dict_value_type value_type,
		const union cm_tdbusm_variant *value)
{
	DBusMessageIter args;
	int i = 0;

	memset(&args, 0, sizeof(args));
	dbus_message_iter_init_append(msg, &args);
	if (value != NULL) {
		i = cm_tdbusm_append_d_value(msg, &args, value_type, value);
	}
	return (i > 0) ? 0 : -1;
}

int
cm_tdbusm_set_sd(DBusMessage *msg,
		 const char *s, const struct cm_tdbusm_dict **d)
{
	if (s == NULL) {
		return -1;
	}
	return cm_tdbusm_set_osd(msg, s, d);
}

struct cm_tdbusm_dict *
cm_tdbusm_find_dict_entry(struct cm_tdbusm_dict **d,
			  const char *key,
			  enum cm_tdbusm_dict_value_type value_type)
{
	int i;
	struct cm_tdbusm_dict *ret;
	ret = NULL;
	for (i = 0; (d != NULL) && (d[i] != NULL); i++) {
		if ((value_type == d[i]->value_type) &&
		    (strcasecmp(key, d[i]->key) == 0)) {
			ret = d[i];
		}
		if ((value_type == cm_tdbusm_dict_p) &&
		    (d[i]->value_type == cm_tdbusm_dict_s) &&
		    (strcasecmp(key, d[i]->key) == 0)) {
			ret = d[i];
		}
		if ((value_type == cm_tdbusm_dict_s) &&
		    (d[i]->value_type == cm_tdbusm_dict_p) &&
		    (strcasecmp(key, d[i]->key) == 0)) {
			ret = d[i];
		}
	}
	return ret;
}

char *
cm_tdbusm_hint(void *parent, const char *error, const char *message)
{
	char *text = NULL;
	if (error == NULL) {
		return NULL;
	}
	if (strcmp(error, DBUS_ERROR_ACCESS_DENIED) == 0) {
		text = N_("Insufficient access.  Please retry operation as root.\n");
	} else
	if ((strcmp(error, DBUS_ERROR_NAME_HAS_NO_OWNER) == 0) ||
	    (strcmp(error, DBUS_ERROR_SERVICE_UNKNOWN) == 0)) {
		text = N_("Please verify that the certmonger service has been started.\n");
	} else
	if (strcmp(error, DBUS_ERROR_NO_REPLY) == 0) {
		text = N_("Please verify that the certmonger service is still running.\n");
	} else
	if (strcmp(error, DBUS_ERROR_NO_SERVER) == 0) {
		text = N_("Please verify that the message bus (D-Bus) service is running.\n");
	}
	return text;
}
