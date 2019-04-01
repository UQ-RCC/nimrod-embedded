/* ---------------------------------------------------------------------------
 * minipbs.hpp, just enough extracts from pbs_ifl.h and pbs_error.h for nimrun
 * to work. Tweaked for C++.
 * ---------------------------------------------------------------------------
 *         OpenPBS (Portable Batch System) v2.3 Software License
 *
 * Copyright (c) 1999-2000 Veridian Information Solutions, Inc.
 * All rights reserved.
 */
#ifndef _MINIPBS_HPP
#define _MINIPBS_HPP

/* pbs_error.h */
enum { PBSE_ = 15000, PBSE_NONE = 0, PBSE_PERM = PBSE_ + 7 };

/* pbs_ifl.h */
constexpr static const char *ATTR_l = "Resource_List";
constexpr static const char *ATTR_server = "server";
constexpr static const char *ATTR_exechost = "exec_host";

enum batch_op { _DUMMY };

struct attrl {
	struct attrl		*next;
	char				*name;
	char				*resource;
	char 				*value;
	enum batch_op		op;	/* not used */
};

struct batch_status {
	struct batch_status	*next;
	char 				*name;
	struct attrl		*attribs;
	char 				*text;
};

using PFNPBS_CONNECT			= int(*)(char*);
using PFNPBS_DISCONNECT			= int(*)(int);
using PFNPBS_STATJOB			= struct batch_status*(*)(int, char*, struct attrl *, char*);
using PFNPBS_STATFREE			= void(*)(struct batch_status*);
using PFNPBSE_TO_TXT			= char*(*)(int);
using PFN__PBS_ERRNO_LOCATION	= int*(*)();

#endif /* _MINIPBS_HPP */