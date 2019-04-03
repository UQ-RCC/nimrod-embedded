/*
 *         OpenPBS (Portable Batch System) v2.3 Software License
 *
 * Copyright (c) 1999-2000 Veridian Information Solutions, Inc.
 * All rights reserved.
 */
#include "minipbs.hpp"

using namespace minipbs;

using PFNPBS_CONNECT			= int(*)(char*);
using PFNPBS_DISCONNECT			= int(*)(int);
using PFNPBS_STATJOB			= struct batch_status*(*)(int, char*, struct attrl *, char*);
using PFNPBS_STATFREE			= void(*)(struct batch_status*);
using PFNPBSE_TO_TXT			= char*(*)(int);
using PFN__PBS_ERRNO_LOCATION	= int*(*)();

static PFNPBS_CONNECT		_pbs_connect = nullptr;
static PFNPBS_DISCONNECT	_pbs_disconnect = nullptr;
static PFNPBS_STATJOB		_pbs_statjob = nullptr;
static PFNPBS_STATFREE		_pbs_statfree = nullptr;
static PFNPBSE_TO_TXT		_pbse_to_txt = nullptr;
static int					*_pbs_errno = nullptr;

int minipbs::pbs_errno = PBSE_NONE;

int minipbs::pbs_connect(char *server) noexcept
{
	int ret = _pbs_connect(server);
	minipbs::pbs_errno = *_pbs_errno;
	return ret;
}

int minipbs::pbs_disconnect(int connect) noexcept
{
	int ret = _pbs_disconnect(connect);
	minipbs::pbs_errno = *_pbs_errno;
	return ret;
}

struct batch_status *minipbs::pbs_statjob(int connect, char *id, struct attrl *attrib, char *extend) noexcept
{
	struct batch_status *ret = _pbs_statjob(connect, id, attrib, extend);
	minipbs::pbs_errno = *_pbs_errno;
	return ret;
}

void minipbs::pbs_statfree(struct batch_status *status) noexcept
{
	_pbs_statfree(status);
	minipbs::pbs_errno = *_pbs_errno;
}

char *minipbs::pbse_to_txt(int err) noexcept
{
	return _pbse_to_txt(err);
}

#include <dlfcn.h>
void *minipbs::minipbs_loadlibrary(const char *libpath) noexcept
{
	void *hpbs = dlopen(libpath, RTLD_NOW);
	if(!hpbs)
		return nullptr;

	if(!(_pbs_connect = reinterpret_cast<PFNPBS_CONNECT>(dlsym(hpbs, "pbs_connect"))))
		goto dlsym_failed;

	if(!(_pbs_disconnect = reinterpret_cast<PFNPBS_DISCONNECT>(dlsym(hpbs, "pbs_disconnect"))))
		goto dlsym_failed;

	if(!(_pbs_statjob = reinterpret_cast<PFNPBS_STATJOB>(dlsym(hpbs, "pbs_statjob"))))
		goto dlsym_failed;

	if(!(_pbs_statfree = reinterpret_cast<PFNPBS_STATFREE>(dlsym(hpbs, "pbs_statfree"))))
		goto dlsym_failed;

	if(!(_pbse_to_txt = reinterpret_cast<PFNPBSE_TO_TXT>(dlsym(hpbs, "pbse_to_txt"))))
		goto dlsym_failed;

	if(!(_pbs_errno = reinterpret_cast<int*>(dlsym(hpbs, "pbs_errno"))))
	{
		PFN__PBS_ERRNO_LOCATION __pbs_errno_location = reinterpret_cast<PFN__PBS_ERRNO_LOCATION>(dlsym(hpbs, "__pbs_errno_location"));
		if(!__pbs_errno_location)
			goto dlsym_failed;

		if(!(_pbs_errno = __pbs_errno_location()))
			goto dlsym_failed;
	}

	pbs_errno = PBSE_NONE;
	return hpbs;

dlsym_failed:
	dlclose(hpbs);
	return nullptr;
}
