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
#include <config.h>
#include "parg.h"
#include "nimrun.hpp"
#include "config.h"

#define ARGDEF_VERSION        		'v'
#define ARGDEF_DEBUG        		'd'
#define ARGDEF_CLUSTER				'c'
#define ARGDEF_TMPDIR				301
#define ARGDEF_OUTDIR				302
#define ARGDEF_QPID_MANAGEMENT_PORT	303
#define ARGDEF_QPID_HOME			304
#define ARGDEF_JAVA_HOME			305
#define ARGDEF_NIMROD_HOME			306
#define ARGDEF_HELP         		'h'

static struct parg_option argdefs[] = {
	{"version",					PARG_NOARG,		nullptr,	ARGDEF_VERSION},
	{"debug",					PARG_NOARG,		nullptr,	ARGDEF_DEBUG},
	{"cluster",					PARG_REQARG,	nullptr,	ARGDEF_CLUSTER},
	{"tmpdir",					PARG_REQARG,	nullptr,	ARGDEF_TMPDIR},
	{"outdir",					PARG_REQARG,	nullptr,	ARGDEF_OUTDIR},
	{"qpid-management-port",	PARG_REQARG,	nullptr,	ARGDEF_QPID_MANAGEMENT_PORT},
	{"qpid-home",				PARG_REQARG,	nullptr,	ARGDEF_QPID_HOME},
	{"java-home",				PARG_REQARG,	nullptr,	ARGDEF_JAVA_HOME},
	{"nimrod-home",				PARG_REQARG,	nullptr,	ARGDEF_NIMROD_HOME},
	{"help",					PARG_NOARG,		nullptr,	ARGDEF_HELP},
	{nullptr,					0,				nullptr,	0}
};

static const char *USAGE_OPTIONS =
"  -v, --version           Display version information\n"
"  -d, --debug             Enable Debugging\n"
"  -c, --cluster           The cluster name/type. If unspecified, use $NIMRUN_CLUSTER.\n"
"                          If $NIMRUN_CLUSTER isn't set or is empty, attempt to autodetect.\n"
"                          Valid options are:\n"
"                          - generic_{pbs,slurm,lsf}\n"
"  --tmpdir                The temporary directory to use. If unspecified, use $TMPDIR\n"
"  --outdir                The output directory to use. If unspecified, use the one provided by the batch system\n"
"  --qpid-management-port  Set the Qpid HTTP management port. Omit or set to 0 to disable\n"
"  --qpid-home             The Qpid home directory. If unspecified, use $QPID_HOME\n"
"  --java-home             The Java home directory. If unspecified, use $JAVA_HOME\n"
"  --nimrod-home           The Nimrod home directory. If unspecified, use $NIMROD_HOME\n"
"";

int parse_args_nimrun(int argc, char **argv, nimrun_args *args) noexcept
{
	parg_state ps{};
	parg_init(&ps);


	memset(args, 0, sizeof(nimrun_args));

	for(int c; (c = parg_getopt_long(&ps, argc, argv, "vdc", argdefs, nullptr)) != -1; )
	{
		switch(c)
		{
			case ARGDEF_HELP:
				return 2;

			case ARGDEF_VERSION:
				++args->version;
				return 0;

			case ARGDEF_DEBUG:
				++args->debug;
				break;

			case ARGDEF_CLUSTER:
				args->cluster = ps.optarg;
				break;

			case ARGDEF_TMPDIR:
				args->tmpdir = ps.optarg;
				break;

			case ARGDEF_OUTDIR:
				args->outdir = ps.optarg;
				break;

			case ARGDEF_QPID_MANAGEMENT_PORT:
				if(sscanf(ps.optarg, "%hu", &args->qpid_management_port) != 1)
					return 2;
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
					return 2;
				args->planfile = ps.optarg;
				break;

			case '?':
			case ':':
			default:
				return 2;
		}
	}

	if(args->planfile == nullptr)
		return 2;

	return 0;
}

static exec_mode_t get_execmode(std::string_view argv0) noexcept
{
    size_t idx = argv0.find_last_of(fs::path::preferred_separator);
    if(idx != std::string_view::npos)
        argv0 = argv0.substr(idx + 1);

    //return exec_mode_t::nimexec;
    if(argv0 == "nimexec")
        return exec_mode_t::nimexec;
    else
        return exec_mode_t::nimrun;
}

int parse_arguments(int argc, char **argv, FILE *out, FILE *err, nimrun_args *args)
{
	args->argc = argc;
	args->argv = argv;
	args->mode = get_execmode(argv[0]);
	if(args->mode == exec_mode_t::nimexec)
	{
		if(argc < 2)
		{
			fprintf(err, "Usage: %s <command> [arg]...\n", argv[0]);
			return 2;
		}
		args->version = 0;
		args->debug = 3;
		args->cluster = nullptr;
		args->planfile = argv[1];
		args->tmpdir = nullptr;
		args->outdir = nullptr;
		args->qpid_management_port = 0;
		args->qpid_home = nullptr;
		args->java_home = nullptr;
		args->nimrod_home = nullptr;
	}
	else
	{
		int status = parse_args_nimrun(argc, argv, args);
		if(status != 0)
		{
			fprintf(err, "Usage: %s [OPTIONS] <planfile> \nOptions:\n%s", argv[0], USAGE_OPTIONS);
			return status;
		}

		if(args->version)
		{
			fprintf(out, "nimrun %s OpenSSL/%s\n", g_compile_info.version.nimrun, g_compile_info.version.openssl);
			fprintf(out, "Commit: %s\n", g_compile_info.git.sha1);
			return status;
		}
	}


	auto checkarg = [args, err](const char *&val, const char *env, const char *arg) {

		if(val == nullptr || val[0] == '\0')
			val = getenv(env);

		if(val == nullptr || val[0] == '\0')
		{
			if(args->mode == exec_mode_t::nimexec)
				fprintf(err, "%s isn't set, cannot continue...\n", env);
			else
				fprintf(err, "%s isn't set. Please use the %s option.\n", env, arg);

			return false;
		}

		return true;
	};

	if(!checkarg(args->tmpdir, "TMPDIR", "--tmpdir"))
		return 1;

	if(!checkarg(args->qpid_home, "QPID_HOME", "--qpid-home"))
		return 1;

	if(!checkarg(args->java_home, "JAVA_HOME", "--java-home"))
		return 1;

	if(!checkarg(args->nimrod_home, "NIMROD_HOME", "--nimrod-home"))
		return 1;

	/* This isn't an error, we can attempt to autodetect otherwise. */
	if(args->cluster == nullptr || args->cluster[0] == '\0')
		args->cluster = getenv("NIMRUN_CLUSTER");

	if(args->cluster != nullptr && args->cluster[0] == '\0')
		args->cluster = nullptr;

	return 0;
}
