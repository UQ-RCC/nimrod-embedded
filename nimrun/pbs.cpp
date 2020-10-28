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
#include <fstream>
#include "minipbs.hpp"
#include "nimrun.hpp"

using namespace minipbs;

struct pbs_deleter
{
	using pointer = file_desc; /* Same semantics */
	void operator()(pointer p) { pbs_disconnect(p); }
};
using pbs_ptr = std::unique_ptr<int, pbs_deleter>;

struct pbs_batch_status_deleter
{
	using pointer = struct batch_status*;
	void operator()(pointer p) { pbs_statfree(p); }
};
using pbs_batch_status_ptr = std::unique_ptr<struct batch_status, pbs_batch_status_deleter>;

class pbs_error_category_t : public std::error_category
{
public:
	const char *name() const noexcept override { return "pbs"; }
	std::string message(int e) const override { return e < PBSE_ ? strerror(e) : pbse_to_txt(e); }
};

static pbs_error_category_t pbs_error_category;

static void read_exechost_attribute(const struct attrl *a, batch_info_t& pi)
{
	/* tn109c/5*4+tn111c/3*4+tn119a/5*4+tn223b/3*41 */
	for(const char *s = a->value;;)
	{
		char namebuf[32];
		memset(namebuf, 0, sizeof(namebuf));

		unsigned int cpustart, ncpus;
		int n;
		if(sscanf(s, "%31[^/]/%u*%u%n", namebuf, &cpustart, &ncpus, &n) != 3)
			break;
		
		auto it = pi.nodes.find(namebuf);
		if(it == pi.nodes.end())
			pi.nodes[namebuf] = ncpus;
		else
			it->second += ncpus;

		/* If NULL, done. If not '+', then we can't handle the rest. */
		if(s[n] == '\0' || s[n] != '+')
			break;

		s += n + 1;
	}
}

static std::system_error make_pbs_exception(int err)
{
	return std::system_error(std::error_code(err, pbs_error_category));
}

static void get_pbs_info(const char *job, batch_info_t& pi)
{
	/* Now actually connect to MoM */
	pbs_ptr conn(pbs_connect(nullptr));
	if(!conn)
		throw make_pbs_exception(pbs_errno);

	struct attrl aa[] = {
		{&aa[1],	const_cast<char*>(ATTR_l),			nullptr, const_cast<char*>("")},
		{nullptr,	const_cast<char*>(ATTR_exechost),	nullptr, const_cast<char*>("")},
	};
	pbs_batch_status_ptr jobStatus(pbs_statjob(conn.get(), const_cast<char*>(job), aa, const_cast<char*>("")));

 	if(!jobStatus)
	{
		/* If the server does not contain any queryable jobs, a NULL pointer ia returned and pbs_errno is set to PBSE_NONE (0). */
		if(pbs_errno == PBSE_NONE)
			pbs_errno = PBSE_PERM;

		throw make_pbs_exception(pbs_errno);
	}

	for(struct attrl *a = jobStatus->attribs; a ; a = a->next)
	{
		if(!strcmp(a->name, ATTR_exechost))
		{
			read_exechost_attribute(a, pi);
			break;
		}
	}
}

static void read_nodesfile(batch_info_t& pi)
{
	const char *pbs_nodefile = getenv("PBS_NODEFILE");
	if(pbs_nodefile == nullptr)
		throw std::runtime_error("PBS_NODEFILE isn't set");

	std::ifstream f;
	f.exceptions(std::ifstream::badbit);
	f.open(pbs_nodefile, std::ios::in);

	for(std::string s; std::getline(f, s);)
	{
		if(auto it = pi.nodes.find(s); it != pi.nodes.end())
			++it->second;
		else
			pi.nodes[s] = 1;
	}
}

batch_info_t get_batch_info_pbs()
{
	batch_info_t bi{};

	if(!(bi.job_id = getenv("PBS_JOBID")))
		throw std::runtime_error("PBS_JOBID isn't set");

	if(!(bi.outdir = getenv("PBS_O_WORKDIR")))
		throw std::runtime_error("PBS_O_WORKDIR isn't set");

	/*
	 * RCC's clusters have libpbs.so in an odd place.
	 * Try to load it from LD_LIBRARY_PATH. If that fails,
	 * fallback to /opt/pbs/lib/libpbs.so
	 *
	 * The library cannot be loaded at all (ala when we're
	 * built statically) fall back to reading $PBS_NODEFILE.
	 */
	dl_ptr pbs(minipbs_loadlibrary("libpbs.so"));
	if(!pbs)
		pbs.reset(minipbs_loadlibrary("/opt/pbs/lib/libpbs.so"));

	if(pbs)
		get_pbs_info(bi.job_id, bi);
	else
		read_nodesfile(bi);

	bi.ompthreads = 1;
	if(const char *_ompthreads = getenv("OMP_NUM_THREADS"))
		bi.ompthreads = static_cast<size_t>(atoll(_ompthreads));

	bi.fwdenv.emplace_back("OMP_NUM_THREADS");
	/* Get all PBS_* environment variables to be forwarded through. */
	for(size_t i = 0; environ[i] != nullptr; ++i)
	{
		std::string_view env(environ[i]);
		if(env.find("PBS_") != 0)
			continue;

		size_t equal = env.find("=");
		if(equal == std::string_view::npos)
			continue;

		bi.fwdenv.emplace_back(env.substr(0, equal));
	}

	return bi;
}
