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
#include <cstdarg>
#include <algorithm>
#include <atomic>
#include <unistd.h>
#include <pwd.h>
#include <sys/wait.h>
#include <sys/utsname.h>
#include "nimrun.hpp"

namespace fs = std::filesystem;

enum class cluster_t : size_t
{
	rcc_tinaroo = 0,
	rcc_awoonga,
	rcc_flashlite,
	bsc_nord3,
	unknown
};

/* These must match above. */
static batch_info_proc_t cluster_info_procs[] = {
	get_batch_info_rcc,
	get_batch_info_rcc,
	get_batch_info_rcc,
	get_batch_info_bsc,
	nullptr
};

struct nimrun_resource_info
{
	std::string name;
	std::string uri;
	size_t num_agents;
	bool local;
};


using node_map_type = std::unordered_map<std::string, size_t>;
using resource_vector_type = std::vector<nimrun_resource_info>;

struct nimrun_system_info {
	cluster_t cluster;
	struct utsname uname;

	std::string username;
	std::string hostname;
	std::string simple_hostname;

	batch_info_t batch_info;
	std::string pbs_jobid;

	resource_vector_type nimrod_resources;

	fs::path openssh;

	fs::path nimrod_home;
	fs::path tmpdir;

	fs::path outdir;

	fs::path java_home;
	fs::path java;

	fs::path qpid_home;
	fs::path qpid_work;
	fs::path qpid_cfg;
	fs::path nimrod_work;
	fs::path nimrod_dbpath;
	fs::path nimrod_ini;
	fs::path nimrod_setupini;
	fs::path pem_cert;
	fs::path pem_key;
	fs::path pkcs12_cert;

	std::vector<std::string> interfaces;
	std::string password;
};

static struct nimrun_state
{
	nimrun_args args;
	nimrun_system_info sysinfo;
	nimcli *cli;

	resource_vector_type::const_iterator resit;

	std::atomic_bool interrupt;

	std::atomic<pid_t> qpid;
	uint16_t qpid_port;
	int qpid_ret;

	bool resloop_started;
	std::atomic<pid_t> nimrod_pid;
	int nimrod_ret;
} nimrun;


enum class state_t : uint32_t
{
	none = 0,
	qpid_wait,
	nimrod_createfiles,
	nimrod_init,
	nimrod_addexp,
	nimrod_addresource,
	nimrod_assign,
	nimrod_master,
	nimrod_cleanup,
	qpid_cleanup,
	stopped
};

enum class state_mode_t {enter, run, leave};

using state_handler_fn = state_t(*)(state_t state, state_mode_t mode, nimrun_state& nimrun);

struct state_handler_t
{
	state_handler_fn handler;
	state_t interrupt_state;
};

static state_t handler_none(state_t state, state_mode_t mode, nimrun_state& nimrun);
static state_t handler_qpid_wait(state_t state, state_mode_t mode, nimrun_state& nimrun);
static state_t handler_nimrod_createfiles(state_t state, state_mode_t mode, nimrun_state& nimrun);
static state_t handler_nimrod_common_resource(state_t state, state_mode_t mode, nimrun_state& nimrun);
static state_t handler_nimrod_common(state_t state, state_mode_t mode, nimrun_state& nimrun);
static state_t handler_nimrod_cleanup(state_t state, state_mode_t mode, nimrun_state& nimrun) noexcept;
static state_t handler_qpid_cleanup(state_t state, state_mode_t mode, nimrun_state& nimrun) noexcept;

static state_handler_t state_handlers[] = {
	{handler_none,						state_t::stopped},			/* none					*/
	{handler_qpid_wait,					state_t::qpid_cleanup},		/* qpid_wait			*/
	{handler_nimrod_createfiles,		state_t::nimrod_cleanup},	/* nimrod_createfiles	*/
	{handler_nimrod_common,				state_t::nimrod_cleanup},	/* nimrod_init			*/
	{handler_nimrod_common,				state_t::nimrod_cleanup},	/* nimrod_addexp		*/
	{handler_nimrod_common_resource,	state_t::nimrod_cleanup},	/* nimrod_addresource	*/
	{handler_nimrod_common_resource,	state_t::nimrod_cleanup},	/* nimrod_assign		*/
	{handler_nimrod_common,				state_t::nimrod_cleanup},	/* nimrod_master		*/
	{handler_nimrod_cleanup,			state_t::qpid_cleanup},		/* nimrod_cleanup		*/
	{handler_qpid_cleanup,				state_t::qpid_cleanup},		/* qpid_cleanup			*/
	{nullptr,							state_t::none}				/* stopped				*/
};

static const char *state_strings[] = {
	"none",
	"qpid_wait",
	"nimrod_createfiles",
	"nimrod_init",
	"nimrod_addexp",
	"nimrod_addresource",
	"nimrod_assign",
	"nimrod_master",
	"nimrod_cleanup",
	"qpid_cleanup",
	"stopped",
	nullptr
};

constexpr static size_t log_level_none = 0;
constexpr static size_t log_level_debug = 1;
constexpr static size_t log_level_nimrod = 2;
constexpr static size_t log_level_nimrod_debug = 3;
constexpr static size_t log_level_state = 4;
constexpr static size_t log_level_signal = 5;

static void log_debug(uint32_t level, const char *fmt, ...) noexcept
{
	if(nimrun.args.debug < level)
		return;

	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

static void log_error(const char *fmt, ...) noexcept
{
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

static void do_reap(nimrun_state& nimrun) noexcept
{
	for(pid_t corpse;;)
	{
		int status;
		if((corpse = waitpid(-1, &status, WNOHANG)) < 0)
		{
			if(errno == EINTR)
				continue;

			if(errno == ECHILD)
				break;
		}

		if(corpse == 0)
			break;

		log_debug(log_level_signal, "SIGNAL: Caught SIGCHLD for PID %d\n", corpse);

		int ret;
		if(WIFEXITED(status))
			ret = WEXITSTATUS(status);
		else if(WIFSIGNALED(status))
			ret = 128 + WTERMSIG(status);
		else
			ret = -1;

		if(nimrun.qpid >= 1 && corpse == nimrun.qpid)
		{
			log_debug(log_level_signal, "SIGNAL: PID %d is QPID!\n", corpse);
			nimrun.qpid = -1;
			nimrun.qpid_ret = ret;
		}
		
		if(nimrun.nimrod_pid >= 1 && corpse == nimrun.nimrod_pid)
		{
			log_debug(log_level_signal, "SIGNAL: PID %d is Nimrod!\n", corpse);
			nimrun.nimrod_pid = -1;
			nimrun.nimrod_ret = ret;
		}
	}
}

static int install_signal_handlers()
{
	struct sigaction new_action;
	memset(&new_action, 0, sizeof(new_action));
	new_action.sa_handler = [](int signum){
		if(signum == SIGCHLD)
			do_reap(nimrun);
		else
			nimrun.interrupt = true;
	};
	new_action.sa_flags = 0;
	sigemptyset(&new_action.sa_mask);
	sigaddset(&new_action.sa_mask, SIGTERM);
	sigaddset(&new_action.sa_mask, SIGINT);
	sigaddset(&new_action.sa_mask, SIGCHLD);
	new_action.sa_restorer = nullptr;

	if(sigaction(SIGTERM, &new_action, nullptr) < 0)
		return -1;

	if(sigaction(SIGINT, &new_action, nullptr) < 0)
		return -1;

	if(sigaction(SIGCHLD, &new_action, nullptr) < 0)
		return -1;
	
	return 0;
}

static fs::path locate_openssh()
{
	fs::path ssh = "/usr/bin/ssh";
	if(fs::exists(ssh))
		return ssh;

	ssh = "/bin/ssh";
	if(fs::exists(ssh))
		return ssh;

	ssh = "/sbin/ssh";
	if(fs::exists(ssh))
		return ssh;

	return "";
}

static cluster_t detect_cluster(struct utsname *utsname) noexcept
{
	/* This one's easy. */
	const char *bsc_machine = getenv("BSC_MACHINE");
	if(bsc_machine && !strcmp(bsc_machine, "nord3"))
		return cluster_t::bsc_nord3;

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

	return cluster_t::unknown;
}

static nimrun_system_info gather_system_info(const nimrun_args& args)
{
	nimrun_system_info sysinfo;

	memset(&sysinfo.uname, 0, sizeof(sysinfo.uname));
	uname(&sysinfo.uname);

	sysinfo.cluster = detect_cluster(&sysinfo.uname);

	errno = 0;
	struct passwd *passwd = getpwuid(geteuid());
	if(passwd == nullptr)
		throw make_posix_exception(errno);

	sysinfo.username = passwd->pw_name;
	sysinfo.hostname = sysinfo.uname.nodename;
	sysinfo.simple_hostname = sysinfo.hostname.substr(0, sysinfo.hostname.find_first_of('.'));

	batch_info_proc_t infoproc = cluster_info_procs[static_cast<size_t>(sysinfo.cluster)];
	if(infoproc != nullptr)
	{
		sysinfo.batch_info = infoproc(args);
		sysinfo.pbs_jobid = args.jobid;

		for(const auto& e : sysinfo.batch_info.nodes)
		{
			nimrun_resource_info ri;
			ri.name = e.first;
			ri.uri = "ssh://";
			ri.uri.append(ri.name);
			ri.num_agents = e.second / sysinfo.batch_info.ompthreads;
			ri.local = e.first == sysinfo.simple_hostname;
			sysinfo.nimrod_resources.emplace_back(std::move(ri));
		}
	}

	std::sort(sysinfo.nimrod_resources.begin(), sysinfo.nimrod_resources.end(), [](const auto& a, const auto& b){
		return a.name < b.name;
	});

	sysinfo.openssh = locate_openssh();
	if(sysinfo.openssh.empty())
		throw make_posix_exception(ENOENT);

	sysinfo.nimrod_home = args.nimrod_home;
	sysinfo.tmpdir = args.tmpdir;
	sysinfo.outdir = args.outdir;
	sysinfo.java_home = args.java_home;
	sysinfo.java = sysinfo.java_home / "bin" / "java";
	sysinfo.qpid_home = args.qpid_home;
	sysinfo.qpid_work = sysinfo.tmpdir / "qpid-work";
	sysinfo.qpid_cfg = sysinfo.tmpdir / "qpid-initial-config.json";
	sysinfo.nimrod_work = sysinfo.tmpdir / "nimrod-work";
	sysinfo.nimrod_dbpath = sysinfo.nimrod_work / "nimrod.db";
	sysinfo.nimrod_ini = sysinfo.nimrod_work / "nimrod.ini";
	sysinfo.nimrod_setupini = sysinfo.nimrod_work / "nimrod-setup.ini";
	sysinfo.pem_cert = sysinfo.tmpdir / "cert.pem";
	sysinfo.pem_key = sysinfo.tmpdir / "key.pem";
	sysinfo.pkcs12_cert = sysinfo.tmpdir / "cert.p12";
	sysinfo.password = generate_random_password(32);

	if(get_ip_addrs(sysinfo.interfaces) < 0)
		throw make_posix_exception(errno);

	return sysinfo;
}

#include "json.hpp"
static void dump_system_info_json(const nimrun_state& nimrun)
{
	using json = nlohmann::json;

	const nimrun_system_info& si = nimrun.sysinfo;

	json ips = json::array();
	for(const auto& it : si.interfaces)
		ips.push_back(it);

	json res = json::array();
	for(const auto& it : si.nimrod_resources)
	{
		res.push_back({
			{"name", it.name},
			{"uri", it.uri},
			{"num_agents", it.num_agents},
			{"local", it.local}
		});
	}

	json nodes = json::object();
	for(const auto& it : si.batch_info.nodes)
		nodes[it.first] = it.second;

	const char *clustername;
	switch(si.cluster)
	{
		case cluster_t::rcc_flashlite: clustername = "rcc_flashlite"; break;
		case cluster_t::rcc_tinaroo: clustername = "rcc_tinaroo"; break;
		case cluster_t::rcc_awoonga: clustername = "rcc_awoonga"; break;
		case cluster_t::bsc_nord3: clustername = "bsc_nord3"; break;
		default: clustername = "unknown"; break;
	}

	json j = {
		{"cluster", clustername},
		{"uname", {
			{"sysname", si.uname.sysname},
			{"nodename", si.uname.nodename},
			{"release", si.uname.release},
			{"version", si.uname.version},
			{"machine", si.uname.machine},
		}},
		{"username", si.username},
		{"hostname", si.uname.nodename},
		{"simple_hostname", si.simple_hostname},
		{"pbs_jobid", si.pbs_jobid},
		{"batch_info", {
			{"ompthreads", si.batch_info.ompthreads},
			{"nodes", nodes}
		}},
		{"outdir", si.outdir},
		{"nimrod_resources", res},
		{"openssh", si.openssh},
		{"nimrod_home", si.nimrod_home},
		{"tmpdir", si.tmpdir},
		{"java_home", si.java_home},
		{"java", si.java},
		{"qpid_home", si.qpid_home},
		{"qpid_work", si.qpid_work},
		{"qpid_cfg", si.qpid_cfg},
		{"nimrod_work", si.nimrod_work},
		{"nimrod_dbpath", si.nimrod_dbpath},
		{"nimrod_ini", si.nimrod_ini},
		{"nimrod_setupini", si.nimrod_setupini},
		{"pem_cert", si.pem_cert},
		{"pem_key", si.pem_key},
		{"pkcs12_cert", si.pkcs12_cert},
		{"password", si.password},
		{"interfaces", ips}
	};

	std::string ss = j.dump(4, ' ');

	log_debug(log_level_debug, "%s\n", ss.c_str());
}

int main(int argc, char **argv)
{
	nimrun_args& args = nimrun.args;
	int status = parse_arguments(argc, argv, stdout, stderr, &args);
	if(status != 0)
		return status;

	nimrun_system_info& sysinfo = nimrun.sysinfo;
	sysinfo = gather_system_info(args);

	if(!fs::is_regular_file(sysinfo.java))
		return log_error("Unable to locate Java. Exiting...\n"), 1;

	if(args.debug >= log_level_debug)
		dump_system_info_json(nimrun);

	if(sysinfo.cluster == cluster_t::unknown)
	{
		return log_error("Unknown cluster, please contact your system administrator...\n"), 1;
	}

	/* Here all the system info should be already gathered. */
	init_openssl();

	auto sslcrap = make_protector(deinit_openssl);

	evp_pkey_ptr key = create_pkey(4096);
	if(!key)
		return dump_openssl_errors(stderr), 1;

	std::vector<std::string> certnames(sysinfo.interfaces);
	//certnames.push_back(sysinfo.hostname);
	certnames.push_back(sysinfo.simple_hostname);
	x509_ptr cert = create_cert(key.get(), 0, 3650, sysinfo.hostname, certnames);
	if(!cert)
		return dump_openssl_errors(stderr), 1;

	{ /* Write the PEM key */
		const char *fname = sysinfo.pem_key.c_str();
		file_ptr fp(fopen(fname, "wb"));
		if(!fp)
			throw make_posix_exception(errno);

		if(write_pem_key(key.get(), fp.get()) < 0)
			return dump_openssl_errors(stderr), 1;
	}

	{	/* Write the PEM certificate */
		const char *fname = sysinfo.pem_cert.c_str();
		file_ptr fp(fopen(fname, "wb"));
		if(!fp)
			throw make_posix_exception(errno);

		if(write_pem_cert(cert.get(), fp.get()) < 0)
			return dump_openssl_errors(stderr), 1;
	}

	{ /* Write the PKCS12 certificate */
		const char *fname = sysinfo.pkcs12_cert.c_str();
		file_ptr fp(fopen(fname, "wb"));
		if(!fp)
			throw make_posix_exception(errno);

		if(write_pkcs12(key.get(), cert.get(), "nimrod", sysinfo.password.c_str(), fp.get()) < 0)
			return dump_openssl_errors(stderr), 1;
	}

	/* Write the qpid config */
	write_file(sysinfo.qpid_cfg, generate_qpid_json(
		sysinfo.qpid_work,
		sysinfo.username.c_str(),
		sysinfo.password.c_str(),
		sysinfo.pkcs12_cert,
		sysinfo.password.c_str(),
		0,
		args.qpid_management_port
	));

	if(install_signal_handlers() < 0)
		throw make_posix_exception(errno);

	nimcli nimrod(sysinfo.java, sysinfo.openssh, sysinfo.tmpdir, sysinfo.nimrod_home, "x86_64-pc-linux-musl", sysinfo.nimrod_ini, sysinfo.outdir, args.debug >= log_level_nimrod_debug);

	nimrun.cli = &nimrod;
	nimrun.interrupt = false;
	nimrun.qpid = launch_qpid(sysinfo.java, sysinfo.qpid_home, sysinfo.qpid_work, sysinfo.qpid_cfg);

	using state_base_type = std::underlying_type_t<state_t>;

	/* Start our event loop. */
	for(state_t state = state_t::qpid_wait, old_state = state_t::none;;)
	{
		state_base_type istate = static_cast<state_base_type>(state);
		state_base_type ostate = static_cast<state_base_type>(old_state);

		if(state != old_state)
		{
			try
			{
				log_debug(log_level_state, "LEAVE %s\n", state_strings[ostate]);
				state_handlers[ostate].handler(old_state, state_mode_t::leave, nimrun);
			}
			catch(std::exception& e)
			{
				log_error("Caught exception during LEAVE transition: %s\n", e.what());
				state = state_handlers[istate].interrupt_state;
			}

			/* Stop at the first state without a handler. */
			if(state_handlers[istate].handler == nullptr)
				break;

			try
			{
				log_debug(log_level_state, "ENTER %s\n", state_strings[istate]);
				state_handlers[istate].handler(state, state_mode_t::enter, nimrun);
			}
			catch(std::exception& e)
			{
				log_error("Caught exception during ENTER transition: %s\n", e.what());
				state = state_handlers[istate].interrupt_state;
			}
		}

		old_state = state;
		if(nimrun.interrupt)
		{
			nimrun.interrupt = false;
			state = state_handlers[istate].interrupt_state;
		}
		else
		{
			try
			{
				log_debug(log_level_state, "RUN   %s\n", state_strings[istate]);
				state = state_handlers[istate].handler(state, state_mode_t::run, nimrun);
			}
			catch(std::exception& e)
			{
				log_error("Caught exception during RUN: %s\n", e.what());
				state = state_handlers[istate].interrupt_state;
			}
		}
		//sleep(1);
		usleep(500000);
	}

	return 0;
}

static state_t handler_none(state_t state, state_mode_t mode, nimrun_state& nimrun)
{
	return state_t::qpid_wait;
}

static state_t handler_qpid_wait(state_t state, state_mode_t mode, nimrun_state& nimrun)
{
	if(mode == state_mode_t::enter)
		return state;

	if(mode == state_mode_t::leave)
		return state;

	if(nimrun.qpid < 0)
	{
		/* QPID's terminated before it even began. */
		return state_t::stopped;
	}

	std::vector<uint16_t> ports = get_listening_ports(nimrun.qpid);
	std::remove(ports.begin(), ports.end(), nimrun.args.qpid_management_port);
	if(ports.empty())
		return state;

	log_debug(log_level_debug, "Detected QPID listening on port %hu\n", ports[0]);
	nimrun.qpid_port = ports[0];
	return state_t::nimrod_createfiles;
}

static state_t handler_nimrod_createfiles(state_t state, state_mode_t mode, nimrun_state& nimrun)
{
	if(mode == state_mode_t::enter)
		return state;

	if(mode == state_mode_t::leave)
		return state;

	/* Can't do this until QPID's up. */
	fs::create_directory(nimrun.sysinfo.nimrod_work);
	write_file(nimrun.sysinfo.nimrod_ini, build_nimrod_ini(nimrun.sysinfo.nimrod_dbpath));
	write_file(nimrun.sysinfo.nimrod_setupini, build_nimrod_setupini(
		nimrun.sysinfo.nimrod_home,
		nimrun.sysinfo.nimrod_work,
		nimrun.sysinfo.username.c_str(),
		nimrun.sysinfo.password.c_str(),
		nimrun.sysinfo.simple_hostname.c_str(),
		nimrun.qpid_port,
		nimrun.sysinfo.pem_cert
	));

	nimrun.nimrod_pid = 0;
	return state_t::nimrod_init;
}

static state_t handler_nimrod_common_resource(state_t state, state_mode_t mode, nimrun_state& nimrun)
{
	if(mode == state_mode_t::enter)
	{
		nimrun.resit = nimrun.sysinfo.nimrod_resources.begin();
		return state;
	}

	if(mode == state_mode_t::leave)
	{
		nimrun.resit = nimrun.sysinfo.nimrod_resources.end();
		return state;
	}

	/* See if QPID's died before us. */
	if(nimrun.qpid < 0)
		return state_t::nimrod_cleanup;

	if(!nimrun.resloop_started)
	{
		nimrun.resloop_started = true;
		if(state == state_t::nimrod_addresource)
		{
			if(nimrun.resit->local)
			{
				nimrun.nimrod_pid = nimrun.cli->add_local_resource(
					nimrun.resit->name.c_str(),
					static_cast<uint32_t>(nimrun.resit->num_agents)
				);
			}
			else
			{
				nimrun.nimrod_pid = nimrun.cli->add_remote_resource(
					nimrun.resit->name.c_str(),
					nimrun.resit->uri.c_str(),
					static_cast<uint32_t>(nimrun.resit->num_agents)
				);
			}
		}
		else
		{
			nimrun.nimrod_pid = nimrun.cli->assign_resource(nimrun.resit->name.c_str(), "localexp");
		}

		++nimrun.resit;
		return state;
	}

	if(nimrun.nimrod_pid < 0)
	{
		if(nimrun.nimrod_ret != 0)
			return state_t::nimrod_cleanup;

		nimrun.resloop_started = false;
		if(nimrun.resit == nimrun.sysinfo.nimrod_resources.end())
			return static_cast<state_t>(static_cast<std::underlying_type_t<state_t>>(state) + 1);
	}

	return state;
}

static state_t handler_nimrod_common(state_t state, state_mode_t mode, nimrun_state& nimrun)
{
	if(mode == state_mode_t::enter)
	{
		switch(state)
		{
			case state_t::nimrod_init:
				nimrun.nimrod_pid = nimrun.cli->setup_init(nimrun.sysinfo.nimrod_setupini);
				break;
			case state_t::nimrod_addexp:
				nimrun.nimrod_pid = nimrun.cli->add_experiment("localexp", nimrun.args.planfile);
				break;
			case state_t::nimrod_master:
				nimrun.nimrod_pid = nimrun.cli->master("localexp", 500);
				break;
			default:
				nimrun.nimrod_pid = -1;
				break;
		}
		return state;
	}

	if(mode == state_mode_t::leave)
		return state;

	/* See if QPID's died before us. */
	if(nimrun.qpid < 0)
		return state_t::nimrod_cleanup;

	if(nimrun.nimrod_pid < 0)
	{
		if(nimrun.nimrod_ret != 0)
			return state_t::nimrod_cleanup;

		state = static_cast<state_t>(static_cast<std::underlying_type_t<state_t>>(state) + 1);
	}

	return state;
}

static state_t handler_nimrod_cleanup(state_t state, state_mode_t mode, nimrun_state& nimrun) noexcept
{
	if(mode == state_mode_t::enter)
	{
		if(nimrun.nimrod_pid > 0)
		{
			/* If QPID's still alive, send a SIGTERM, otherwise SIGKILL. */
			kill(nimrun.nimrod_pid, nimrun.qpid >= 0 ? SIGTERM : SIGKILL);
		}

		return state;
	}

	if(mode == state_mode_t::leave)
		return state;

	if(nimrun.nimrod_pid < 0)
		return state_t::qpid_cleanup;

	return state;
}

static state_t handler_qpid_cleanup(state_t state, state_mode_t mode, nimrun_state& nimrun) noexcept
{
	if(mode == state_mode_t::enter)
	{
		if(nimrun.qpid >= 0)
			kill(nimrun.qpid, SIGTERM);
	}

	if(mode == state_mode_t::leave)
		return state;

	if(nimrun.qpid < 0)
		return state_t::stopped;

	return state;
}
