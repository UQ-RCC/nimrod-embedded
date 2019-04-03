#include <cstring>
#include "nimrun.hpp"

batch_info_t get_batch_info_bsc(const nimrun_args& args)
{
	batch_info_t bi;

	/* LSF is a tad nicer than PBS in this regard. */
	const char *lsb_mcpu_hosts = getenv("LSB_MCPU_HOSTS");

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