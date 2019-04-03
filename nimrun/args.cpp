/*
 * Nimrod/G Embedded for RCC's HPC environment
 * https://github.com/UQ-RCC/nimrod-embedded
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 The University of Queensland
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include "parg.h"
#include "nimrun.hpp"

#define ARGDEF_DEBUG        		'd'
#define ARGDEF_TMPDIR				301
#define ARGDEF_OUTDIR				302
#define ARGDEF_QPID_MANAGEMENT_PORT	303
#define ARGDEF_QPID_HOME			304
#define ARGDEF_JAVA_HOME			305
#define ARGDEF_NIMROD_HOME			306
#define ARGDEF_HELP         		'h'

static struct parg_option argdefs[] = {
	{"debug",					PARG_NOARG,		nullptr,	ARGDEF_DEBUG},
	{"tmpdir",					PARG_REQARG,	nullptr,	ARGDEF_TMPDIR},
	{"outdir",					PARG_REQARG,	nullptr,	ARGDEF_OUTDIR},
	{"qpid-management-port",	PARG_REQARG,	nullptr,	ARGDEF_QPID_MANAGEMENT_PORT},
	{"qpid-home",				PARG_REQARG,	nullptr,	ARGDEF_QPID_HOME},
	{"java-home",				PARG_REQARG,	nullptr,	ARGDEF_JAVA_HOME},
	{"nimrod-home",				PARG_REQARG,	nullptr,	ARGDEF_NIMROD_HOME},
	{"help",					PARG_NOARG,		nullptr,	ARGDEF_HELP},
	{nullptr,					0,				nullptr,	0}
};

static const char *USAGE_OPTIONS2 = 
"  -d, --debug\n"
"                          Enable Debugging\n"
"  --tmpdir\n"
"                          The temporary directory to use. If unspecified, use $TMPDIR\n"
"  --outdir\n"
"                          The output directory to use. If unspecified, use the one provided by the batch system\n"
"  --qpid-management-port\n"
"                          Set the Qpid HTTP management port. Omit or set to 0 to disable\n"
"  --qpid-home\n"
"                          The Qpid home directory. If unspecified, use $QPID_HOME\n"
"  --java-home\n"
"                          The Java home directory. If unspecified, use $JAVA_HOME\n"
"  --nimrod-home\n"
"                          The Nimrod home directory. If unspecified, use $NIMROD_HOME\n"
"";

static const char *USAGE_OPTIONS = 
"  -d, --debug             Enable Debugging\n"
"  --tmpdir                The temporary directory to use. If unspecified, use $TMPDIR\n"
"  --outdir                The output directory to use. If unspecified, use the one provided by the batch system\n"
"  --qpid-management-port  Set the Qpid HTTP management port. Omit or set to 0 to disable\n"
"  --qpid-home             The Qpid home directory. If unspecified, use $QPID_HOME\n"
"  --java-home             The Java home directory. If unspecified, use $JAVA_HOME\n"
"  --nimrod-home           The Nimrod home directory. If unspecified, use $NIMROD_HOME\n"
"";

static int usage(int val, FILE *s, const char *argv0)
{
	fprintf(s, "Usage: %s [OPTIONS] <planfile> \nOptions:\n%s", argv0, USAGE_OPTIONS);
	return val;
}

static int parseerror(int val, FILE *s, const char *argv0, const char *msg)
{
	fprintf(s, "Error parsing arguments: %s\n", msg);
	return usage(val, s, argv0);
}

int parse_arguments(int argc, char **argv, FILE *out, FILE *err, nimrun_args *args)
{
	parg_state ps;
	parg_init(&ps);

	memset(args, 0, sizeof(nimrun_args));

	for(int c; (c = parg_getopt_long(&ps, argc, argv, "jd", argdefs, nullptr)) != -1; )
	{
		switch(c)
		{
			case ARGDEF_HELP:
				return usage(2, out, argv[0]);

			case ARGDEF_DEBUG:
				++args->debug;
				break;

			case ARGDEF_TMPDIR:
				args->tmpdir = ps.optarg;
				break;

			case ARGDEF_OUTDIR:
				args->outdir = ps.optarg;
				break;

			case ARGDEF_QPID_MANAGEMENT_PORT:
				if(sscanf(ps.optarg, "%hu", &args->qpid_management_port) != 1)
					return usage(2, out, argv[0]);
				break;

			case ARGDEF_QPID_HOME:
				args->qpid_home = ps.optarg;
				break;

			case ARGDEF_JAVA_HOME:
				args->java_home = ps.optarg;
				break;

			case ARGDEF_NIMROD_HOME:
				args->nimrod_home = ps.optarg;
				break;

			case 1:
				if(args->planfile != nullptr)
					return usage(2, out, argv[0]);
				args->planfile = ps.optarg;
				break;

			case '?':
			case ':':
			default:
				return usage(2, out, argv[0]);
		}
	}

	if(args->planfile == nullptr)
	{
		return usage(2, out, argv[0]);
	}

	if((args->tmpdir == nullptr && (args->tmpdir = getenv("TMPDIR")) == nullptr) || args->tmpdir[0] == '\0')
	{
		fprintf(stderr, "TMPDIR isn't set. Please use the --tmpdir option.\n");
		return 1;
	}

	if((args->qpid_home == nullptr && (args->qpid_home = getenv("QPID_HOME")) == nullptr) || args->qpid_home[0] == '\0')
	{
		fprintf(stderr, "QPID_HOME isn't set. Please use the --qpid-home option.\n");
		return 1;
	}

	if((args->java_home == nullptr && (args->java_home = getenv("JAVA_HOME")) == nullptr) || args->java_home[0] == '\0')
	{
		fprintf(stderr, "JAVA_HOME isn't set. Please use the --java-home option.\n");
		return 1;
	}

	if((args->nimrod_home == nullptr && (args->nimrod_home = getenv("NIMROD_HOME")) == nullptr) || args->nimrod_home[0] == '\0')
	{
		fprintf(stderr, "NIMROD_HOME isn't set. Please use the --nimrod-home option.\n");
		return 1;
	}
	return 0;
}
