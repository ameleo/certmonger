/*
 * Copyright (C) 2026 RusBITech-Astra
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../../src/store.h"

static int failures = 0;

/* Confirm that a well-formed timestamp parses and round-trips back to the
 * same 14-character string. */
static void
check_good(const char *input)
{
	time_t t;
	char out[15];

	t = cm_store_time_from_timestamp(input);
	cm_store_timestamp_from_time(t, out);
	if (strlen(out) != 14) {
		fprintf(stderr, "good \"%s\": round-trip produced \"%s\" "
			"(len %zu, expected 14)\n", input, out, strlen(out));
		failures++;
		return;
	}
	if (strcmp(out, input) != 0) {
		fprintf(stderr, "good \"%s\": round-trip mismatch: "
			"got \"%s\" via time_t %ld\n",
			input, out, (long) t);
		failures++;
		return;
	}
	printf("good \"%s\": OK\n", input);
}

/* Confirm that a timestamp with the right length but invalid content (not
 * all digits, or a field out of its calendar range) is rejected outright,
 * the way a hostile or corrupted certificate's ASN.1 notBefore/notAfter
 * content should be. */
static void
check_rejected(const char *input)
{
	time_t t;

	t = cm_store_time_from_timestamp(input);
	if (t != 0) {
		fprintf(stderr, "bad \"%s\": expected rejection, got time_t %ld\n",
			input, (long) t);
		failures++;
		return;
	}
	printf("bad \"%s\": correctly rejected\n", input);
}

/* Direct regression check for the buffer overflow itself: even if a time_t
 * with an out-of-range year ever reaches one of these formatters by some
 * other path than cm_store_time_from_timestamp(), none of the three
 * sprintf()-based formatters that share this "%hu"-truncated-year pattern
 * may write past their declared buffer bounds. */
static void
check_overflow_guard(const char *year_str)
{
	struct tm tm;
	time_t t;
	char out15[15], out25[25];
	char *local;
	int year, ok = 1;

	year = atoi(year_str);
	memset(&tm, 0, sizeof(tm));
	tm.tm_year = year - 1900;
	tm.tm_mday = 1;
	t = timegm(&tm);

	cm_store_timestamp_from_time(t, out15);
	if (strlen(out15) > 14) {
		fprintf(stderr, "overflow-guard %d: cm_store_timestamp_from_time "
			"output \"%s\" is %zu bytes, exceeds the 15-byte "
			"buffer contract\n", year, out15, strlen(out15));
		ok = 0;
	}

	cm_store_timestamp_from_time_for_display(t, out25);
	if (strlen(out25) > 24) {
		fprintf(stderr, "overflow-guard %d: "
			"cm_store_timestamp_from_time_for_display output "
			"\"%s\" is %zu bytes, exceeds the 25-byte buffer "
			"contract\n", year, out25, strlen(out25));
		ok = 0;
	}

	setenv("TZ", "UTC", 1);
	tzset();
	local = cm_store_local_timestamp_from_time_for_display(t);
	if (local == NULL) {
		fprintf(stderr, "overflow-guard %d: "
			"cm_store_local_timestamp_from_time_for_display "
			"returned NULL\n", year);
		ok = 0;
	} else {
		free(local);
	}

	if (!ok) {
		failures++;
		return;
	}
	printf("overflow-guard %d: OK (\"%s\", \"%s\")\n", year, out15, out25);
}

int
main(int argc, char **argv)
{
	void (*check)(const char *);
	int i;

	if (argc < 3) {
		fprintf(stderr,
			"Usage: %s good|bad|overflow-guard VALUE...\n",
			argv[0]);
		return 2;
	}

	if (strcmp(argv[1], "good") == 0) {
		check = check_good;
	} else if (strcmp(argv[1], "bad") == 0) {
		check = check_rejected;
	} else if (strcmp(argv[1], "overflow-guard") == 0) {
		check = check_overflow_guard;
	} else {
		fprintf(stderr, "Unknown mode \"%s\".\n", argv[1]);
		return 2;
	}

	for (i = 2; i < argc; i++) {
		check(argv[i]);
	}

	if (failures > 0) {
		fprintf(stderr, "%d failure(s).\n", failures);
		return 1;
	}
	printf("OK\n");
	return 0;
}
