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
#include <sys/utsname.h>
#include <cstring>
#include "nimrun.hpp"

cluster_t detect_cluster(struct utsname *utsname) noexcept
{
	/* This one's easy. */
	const char *bsc_machine = getenv("BSC_MACHINE");
	if(bsc_machine && !strcmp(bsc_machine, "nord3"))
		return cluster_t::bsc_nord3;

	const char *slurm_cluster_name = getenv("SLURM_CLUSTER_NAME");
	/* Check for wiener. */
	if(slurm_cluster_name && !strcmp(slurm_cluster_name, "wiener"))
		return cluster_t::qbi_wiener;

	/* Tinaroo, Awoonga, and Flashlite are a little trickier. */
	struct utsname _utsname = *utsname;

	/* We only care about the first part. */
	char *dot = strstr(_utsname.nodename, ".");
	if(dot != nullptr)
		*dot = '\0';

	{ /* Check for Tinaroo */
		unsigned int num;
		char c;

		/* Management nodes. */
		if(sscanf(_utsname.nodename, "tinmgmr%u", &num) == 1)
			return cluster_t::rcc_tinaroo;

		if(sscanf(_utsname.nodename, "tinmgr%u", &num) == 1)
			return cluster_t::rcc_tinaroo;

		/* Login nodes. */
		if(sscanf(_utsname.nodename, "tinaroo%u", &num) == 1)
			return cluster_t::rcc_tinaroo;

		/* Compute nodes. */
		if(sscanf(_utsname.nodename, "tn%u%c", &num, &c) == 2)
			return cluster_t::rcc_tinaroo;

		/* I have no idea what these nodes are. */
		if(sscanf(_utsname.nodename, "ngw%u", &num) == 1)
			return cluster_t::rcc_tinaroo;
	}

	{ /* Check for Awoonga */
		unsigned int num;
		char c;

		/* Management nodes. */
		if(sscanf(_utsname.nodename, "awongmgmr%u", &num) == 1)
			return cluster_t::rcc_awoonga;

		if(sscanf(_utsname.nodename, "awongmgr%u", &num) == 1)
			return cluster_t::rcc_awoonga;

		/* Login nodes. */
		if(sscanf(_utsname.nodename, "awoonga%u", &num) == 1)
			return cluster_t::rcc_awoonga;

		/* Compute nodes. */
		if(sscanf(_utsname.nodename, "aw%u%c", &num, &c) == 2)
			return cluster_t::rcc_awoonga;

		if(sscanf(_utsname.nodename, "aw%u", &num) == 1)
			return cluster_t::rcc_awoonga;
	}

	{ /* Check for FlashLite */
		unsigned int num;

		/* Management nodes. */
		if(sscanf(_utsname.nodename, "flm%u", &num) == 1)
			return cluster_t::rcc_flashlite;

		if(sscanf(_utsname.nodename, "flashmgr%u", &num) == 1)
			return cluster_t::rcc_flashlite;

		/* Login nodes. */
		if(sscanf(_utsname.nodename, "flashlite%u", &num) == 1)
			return cluster_t::rcc_flashlite;

		/* Compute nodes. */
		if(sscanf(_utsname.nodename, "fl%u", &num) == 1)
			return cluster_t::rcc_flashlite;

		if(sscanf(_utsname.nodename, "flvc%u", &num) == 1)
			return cluster_t::rcc_flashlite;
	}

	{ /* Check for Wiener */
		unsigned int n1, n2;

		/* Comute nodes */
		if(sscanf(_utsname.nodename, "gpunode-%u-%u", &n1, &n2) == 2)
			return cluster_t::qbi_wiener;

		/* Login nodes */
		if(strcmp("wiener", _utsname.nodename) == 0)
			return cluster_t::qbi_wiener;
	}
	return cluster_t::unknown;
}
