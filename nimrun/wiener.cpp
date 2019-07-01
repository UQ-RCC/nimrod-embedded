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

#include "nimrun.hpp"
#include <fcntl.h>
#include <unistd.h>
#include <csignal>
#include <cstring>

struct popen_deleter
{
	void operator()(FILE *f) { pclose(f); }
};
using popen_ptr = std::unique_ptr<FILE, popen_deleter>;

batch_info_t get_batch_info_wiener()
{
	batch_info_t bi;

	if((bi.job_id = getenv("SLURM_JOB_ID")) == nullptr || bi.job_id[0] == '\0')
		throw std::runtime_error("SLURM_JOB_ID isn't set");

	if((bi.outdir = getenv("SLURM_SUBMIT_DIR")) == nullptr || bi.outdir[0] == '\0')
		throw std::runtime_error("SLURM_SUBMIT_DIR isn't set");

	const char *nodelist = getenv("SLURM_JOB_NODELIST");
	if(nodelist == nullptr || nodelist[0] == '\0')
		nodelist = getenv("SLURM_NODELIST");

	if(nodelist == nullptr || nodelist[0] == '\0')
		throw std::runtime_error("SLURM_JOB_NODELIST or SLURM_NODELIST aren't set");

	/*
	 * Ain't no way in hell am I parsing this manually.
	 * Abuse abuse "scontrol show hostnames" using SLURM_NODELIST then use popen
	 */
	if(setenv("SLURM_NODELIST", nodelist, 0) < 0)
		throw std::system_error(errno, std::system_category());

	popen_ptr proc(popen("scontrol show hostnames", "r"));
	if(!proc)
		throw std::system_error(errno, std::system_category());

	std::vector<char> output;
	for(;;)
	{
		char buf[1024];
		size_t nread = fread(buf, 1, sizeof(buf), proc.get());
		size_t old = output.size();
		output.resize(old + nread);
		memcpy(output.data() + old, buf, nread);

		if(feof(proc.get()))
			break;

		if(ferror(proc.get()))
			throw std::system_error(errno, std::system_category());
	}

	int ret = pclose(proc.release());
	if(ret < 0)
		throw std::system_error(errno, std::system_category());

	if(ret != 0)
		throw std::runtime_error("failed to parse hosts list");


	for_each_delim(output.data(), output.data() + output.size(), '\n', [&bi](const std::string_view& host, size_t idx){
		//fprintf(stderr, "%zu bytes: %.*s\n", host.size(), static_cast<int>(host.size()), host.data());
		bi.nodes[std::string(host)] = 0;
	});

	return bi;
}