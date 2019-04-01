/*
Nimrod/G Embedded for RCC's HPC environment

https://github.com/UQ-RCC/nimrod-embedded

Licensed under the MIT License <http://opensource.org/licenses/MIT>.
SPDX-License-Identifier: MIT
Copyright (c) 2018 The University of Queensland.

Permission is hereby  granted, free of charge, to any  person obtaining a copy
of this software and associated  documentation files (the "Software"), to deal
in the Software  without restriction, including without  limitation the rights
to  use, copy,  modify, merge,  publish, distribute,  sublicense, and/or  sell
copies  of  the Software,  and  to  permit persons  to  whom  the Software  is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE  IS PROVIDED "AS  IS", WITHOUT WARRANTY  OF ANY KIND,  EXPRESS OR
IMPLIED,  INCLUDING BUT  NOT  LIMITED TO  THE  WARRANTIES OF  MERCHANTABILITY,
FITNESS FOR  A PARTICULAR PURPOSE AND  NONINFRINGEMENT. IN NO EVENT  SHALL THE
AUTHORS  OR COPYRIGHT  HOLDERS  BE  LIABLE FOR  ANY  CLAIM,  DAMAGES OR  OTHER
LIABILITY, WHETHER IN AN ACTION OF  CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE  OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
#include <cstring>
#include <dlfcn.h>
//#include <pbs_error.h>
//#include <pbs_ifl.h>
#include "minipbs.hpp"
#include "nimrun.hpp"

static PFNPBS_CONNECT			pbs_connect = nullptr;
static PFNPBS_DISCONNECT		pbs_disconnect = nullptr;
static PFNPBS_STATJOB			pbs_statjob = nullptr;
static PFNPBS_STATFREE			pbs_statfree = nullptr;
static PFNPBSE_TO_TXT			pbse_to_txt = nullptr;
static int						*_pbs_errno = nullptr;

#define pbs_errno (*_pbs_errno)

struct dl_deleter
{
	using pointer = void*;
	void operator()(pointer p) noexcept { dlclose(p); }
};
using dl_ptr = std::unique_ptr<void, dl_deleter>;

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

static void read_resource_attribute(const struct attrl *a, pbs_info& pi) noexcept
{
	/* Can't use it here, it's always 1 no matter what we do. */
	// if(!strcmp("ompthreads", a->resource))
	// {
	// 	pi.ompthreads = static_cast<size_t>(std::atoll(a->value));
	// 	return;
	// }

	if(!strcmp("select", a->resource))
	{
		constexpr const char *ompneedle = "ompthreads=";
		const char *ompstart = strstr(a->value, ompneedle);
		if(ompstart == nullptr)
			return;

		pi.ompthreads = static_cast<size_t>(std::atoll(ompstart + strlen(ompneedle)));
		return;
	}
}

static void read_exechost_attribute(const struct attrl *a, pbs_info& pi)
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

static void read_server_attribute(const struct attrl *a, pbs_info& pi)
{
	pi.server = a->value;
}

static std::system_error make_pbs_exception(int err)
{
	return std::system_error(std::error_code(err, pbs_error_category));
}

static dl_ptr minipbs_init() noexcept
{
	dl_ptr hpbs(dlopen("libpbs.so", RTLD_NOW));
	if(!hpbs)
		return nullptr;

	if(!(pbs_connect = reinterpret_cast<PFNPBS_CONNECT>(dlsym(hpbs.get(), "pbs_connect"))))
		return nullptr;

	if(!(pbs_disconnect = reinterpret_cast<PFNPBS_DISCONNECT>(dlsym(hpbs.get(), "pbs_disconnect"))))
		return nullptr;

	if(!(pbs_statjob = reinterpret_cast<PFNPBS_STATJOB>(dlsym(hpbs.get(), "pbs_statjob"))))
		return nullptr;

	if(!(pbs_statfree = reinterpret_cast<PFNPBS_STATFREE>(dlsym(hpbs.get(), "pbs_statfree"))))
		return nullptr;

	if(!(pbse_to_txt = reinterpret_cast<PFNPBSE_TO_TXT>(dlsym(hpbs.get(), "pbse_to_txt"))))
		return nullptr;

	if(!(_pbs_errno = reinterpret_cast<int*>(dlsym(hpbs.get(), "pbs_errno"))))
	{
		PFN__PBS_ERRNO_LOCATION __pbs_errno_location = reinterpret_cast<PFN__PBS_ERRNO_LOCATION>(dlsym(hpbs.get(), "__pbs_errno_location"));
		if(!__pbs_errno_location)
			return nullptr;

		if(!(_pbs_errno = __pbs_errno_location()))
			return nullptr;
	}

	return hpbs;
}

pbs_info get_pbs_info(const char *server, const char *job)
{
	dl_ptr pbs(minipbs_init());
	if(!pbs)
		throw std::runtime_error("can't load PBS library");

	/* Now actually connect to MoM */
	pbs_ptr conn(pbs_connect(const_cast<char*>(server)));
	if(!conn)
		throw make_pbs_exception(pbs_errno);

	struct attrl aa[] = {
		{&aa[1],	const_cast<char*>(ATTR_l),			nullptr, const_cast<char*>("")},
		{&aa[2],	const_cast<char*>(ATTR_server),		nullptr, const_cast<char*>("")},
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

	//fprintf(stderr, "name = %s, text = %s\n", jobStatus->name, jobStatus->text);

	// for(struct attrl *a = aa; a != nullptr; a = a->next)
	// 	fprintf(stderr, "name = %s, resource = %s, value = %s\n", a->name, a->resource, a->value);

	pbs_info pi;
	pi.ompthreads = 0;
	for(struct attrl *a = jobStatus->attribs; a ; a = a->next)
	{
		if(!strcmp(a->name, ATTR_l))
			read_resource_attribute(a, pi);
		else if(!strcmp(a->name, ATTR_exechost))
			read_exechost_attribute(a, pi);
		else if(!strcmp(a->name, ATTR_server))
			read_server_attribute(a, pi);

		//fprintf(stderr, "  name = %s, resource = %s, value = %s\n", a->name, a->resource, a->value);
	}

	/* Default to 1 if unspecified. */
	if(pi.ompthreads <= 0)
		pi.ompthreads = 1;

	return pi;
}



