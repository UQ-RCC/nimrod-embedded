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

static size_t read_all(FILE *f, std::vector<char>& data, size_t bufsize = 1024)
{
	char *buf = reinterpret_cast<char*>(alloca(bufsize * sizeof(char)));
	data.clear();
	for(;;)
	{
		size_t nread = fread(buf, 1, bufsize, f);
		size_t old = data.size();
		data.resize(old + nread);
		memcpy(data.data() + old, buf, nread);

		if(feof(f))
			break;

		if(ferror(f))
			throw std::system_error(EIO, std::system_category());
	}

	return data.size();
}

static std::vector<char> read_all(FILE *f, size_t bufsize = 1024)
{
	std::vector<char> data;
	read_all(f, data, bufsize);
	return data;
}

batch_info_t get_batch_info_slurm()
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

	const char *tasks_per_node = getenv("SLURM_TASKS_PER_NODE");
	if(tasks_per_node == nullptr || tasks_per_node[0] == '\0')
		throw std::runtime_error("SLURM_TASKS_PER_NODE isn't set");

	/*
	 * Ain't no way in hell am I parsing this manually.
	 * Abuse abuse "scontrol show hostnames" using SLURM_NODELIST then use popen
	 */
	if(setenv("SLURM_NODELIST", nodelist, 0) < 0)
		throw std::system_error(errno, std::system_category());

	popen_ptr proc(popen("scontrol show hostnames", "r"));
	if(!proc)
		throw std::system_error(errno, std::system_category());

	std::vector<char> output = read_all(proc.get(), 1024);

	int ret = pclose(proc.release());
	if(ret < 0)
		throw std::system_error(errno, std::system_category());

	if(ret != 0)
		throw std::runtime_error("failed to parse hosts list");

	std::vector<std::pair<std::string_view, size_t>> hosts;
	for_each_delim(output.data(), output.data() + output.size(), '\n', [&hosts](std::string_view host, size_t idx){
		hosts.emplace_back(std::make_pair(host, 0));
	});

	size_t i = 0;
	for_each_delim(tasks_per_node, tasks_per_node + strlen(tasks_per_node), ',', [&hosts, &i](std::string_view def, size_t idx){
		/* Can't use string_view as sscanf needs it NULL-terminated and I'm not game to use alloca() here. */
		std::string _def(def);

		if(i >= hosts.size())
			return;

		unsigned int ntasks, nnodes;
		int found = sscanf(_def.c_str(), "%u(x%u)", &ntasks, &nnodes);
		if(found == 1)
			nnodes = 1;
		else if(found != 2)
			throw std::runtime_error("Invalid value in SLURM_TASKS_PER_NODE");

		for(unsigned int j = 0; j < nnodes; ++j, ++i)
			hosts[i].second = ntasks;
	});

	for(const auto& h : hosts)
		bi.nodes[std::string(h.first)] = h.second;

	bi.ompthreads = 1;

	const char *_ompthreads = getenv("OMPTHREADS");
	if(_ompthreads != nullptr)
		bi.ompthreads = static_cast<size_t>(atoll(_ompthreads));

	return bi;
}
