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
#include <cstring>
#include "nimrun.hpp"

batch_info_t get_batch_info_bsc(const nimrun_args& args)
{
	batch_info_t bi;

	if(!(bi.job_id = getenv("LSB_JOBID")))
		throw std::runtime_error("LSB_JOBID isn't set");

	if(!(bi.outdir = getenv("LS_SUBCWD")))
		throw std::runtime_error("LS_SUBCWD isn't set");

	/* LSF is a tad nicer than PBS in this regard. */
	const char *lsb_mcpu_hosts = getenv("LSB_MCPU_HOSTS");
	if(lsb_mcpu_hosts == nullptr)
		throw std::runtime_error("LSB_MCPU_HOSTS isn't set");

	/* "s03r2b55 2 s03r2b27 2 s04r2b21 2 " */

	char hostname[64]; /* Will never be longer than this. */
	size_t count;

    for(const char *s = lsb_mcpu_hosts;;)
    {
        unsigned int n;
        int ret = sscanf(s, "%63s %zu%n", hostname, &count, &n);
        if(ret == EOF)
            break;
        else if(ret == 1)
            throw std::runtime_error("Invalid value in LSB_MCPU_HOSTS");

		hostname[63] = '\0';
		bi.nodes[hostname] = count;
        s += n;
    }

	bi.ompthreads = 1;

	const char *_ompthreads = getenv("OMPTHREADS");
	if(_ompthreads != nullptr)
		bi.ompthreads = static_cast<size_t>(atoll(_ompthreads));

	return bi;
}