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

namespace minipbs {
/* pbs_error.h */
enum { PBSE_ = 15000, PBSE_NONE = 0, PBSE_PERM = PBSE_ + 7 };

/* pbs_ifl.h */
constexpr static const char *ATTR_l = "Resource_List";
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

int		pbs_connect(char *server) noexcept;
int		pbs_disconnect(int connect) noexcept;
struct	batch_status *pbs_statjob(int connect, char *id, struct attrl *attrib, char *extend) noexcept;
void	pbs_statfree(struct batch_status *status) noexcept;
char	*pbse_to_txt(int e) noexcept;

extern int pbs_errno;


void *minipbs_loadlibrary(const char *libpath) noexcept;
}

#endif /* _MINIPBS_HPP */