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
#include <algorithm>
#include <atomic>
#include <unistd.h>
#include <pwd.h>
#include <sys/wait.h>
#include <sys/utsname.h>
#include <config.h>
#include <iomanip>
#include <fstream>
#include <iostream>
#include "config.h"
#include "nimrun.hpp"

/* These must match above. */
static batch_info_proc_t cluster_info_procs[] = {
	get_batch_info_pbs,		/* generic_pbs */
	get_batch_info_slurm,	/* generic_slurm */
	get_batch_info_lsf,		/* generic_lsf */
	nullptr					/* unknown */
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

	resource_vector_type nimrod_resources;

	std::optional<fs::path> openssh;

	fs::path nimrod_home;
	fs::path tmpdir;

	fs::path outdir;
	fs::path outdir_stats;

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
	fs::path stdout_path;
	fs::path stderr_path;

	fs::path stdout_path_rel;
	fs::path stderr_path_rel;

	std::vector<std::string> interfaces;
	std::string password;
};

static struct nimrun_state
{
	nimrun_args args;
	nimrun_system_info sysinfo;
	fs::path planfile;
	fs::path generated_script;
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

std::ostream& log_error() noexcept
{
	return std::cerr;
}

std::ostream& log_debug(uint32_t level) noexcept
{
	static std::ostream s(nullptr);

	if(nimrun.args.debug >= level)
		return std::cout;

	return s;
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

		log_debug(log_level_signal) << "SIGNAL: Caught SIGCHLD for PID " << corpse << std::endl;

		int ret;
		if(WIFEXITED(status))
			ret = WEXITSTATUS(status);
		else if(WIFSIGNALED(status))
			ret = 128 + WTERMSIG(status);
		else
			ret = -1;

		if(nimrun.qpid >= 1 && corpse == nimrun.qpid)
		{
			log_debug(log_level_signal) << "SIGNAL: PID " << corpse << " is QPID!" << std::endl;
			nimrun.qpid = -1;
			nimrun.qpid_ret = ret;
		}
		
		if(nimrun.nimrod_pid >= 1 && corpse == nimrun.nimrod_pid)
		{
			log_debug(log_level_signal) << "SIGNAL: PID " << corpse << " is Nimrod!" << std::endl;
			nimrun.nimrod_pid = -1;
			nimrun.nimrod_ret = ret;
		}
	}
}

static int install_signal_handlers()
{
	struct sigaction new_action{};
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

static std::optional<fs::path> locate_openssh()
{
	using namespace std::literals;
	constexpr std::string_view paths[] = {
		"/usr/bin/ssh"sv,
		"/bin/ssh"sv,
		"/sbin/ssh"sv
	};

	constexpr fs::perms execperms = fs::perms::owner_exec | fs::perms::group_exec | fs::perms::others_exec;

	fs::path path;
	for(std::string_view sv : paths)
	{
		path.clear();
		path.append(sv);

		fs::file_status status = fs::status(path);
		if(is_regular_file(status) && (status.permissions() & execperms) != fs::perms::none)
			return path;
	}

	return std::optional<fs::path>();
}

#include "json.hpp"

NLOHMANN_JSON_SERIALIZE_ENUM(cluster_t, {
	{cluster_t::unknown,		"unknown"},
	{cluster_t::generic_pbs,	"generic_pbs"},
	{cluster_t::generic_slurm,	"generic_slurm"},
	{cluster_t::generic_lsf,	"generic_lsf"}
});

NLOHMANN_JSON_SERIALIZE_ENUM(exec_mode_t, {
	{exec_mode_t::nimrun,		"nimrun"},
	{exec_mode_t::nimexec,		"nimexec"}
});

static std::string get_username()
{
	const char *user;
	struct passwd *passwd;

	errno = 0;
	if((passwd = getpwuid(geteuid())) == nullptr) {
		/* Happens on NIS systems. */
		log_error() << "OS: getpwuid() failed, falling back to $USER" << std::endl;
		log_error() << "OS:   errno   = " << errno                    << std::endl;
		log_error() << "OS:   message = " << strerror(errno)          << std::endl;
	} else if(passwd->pw_name == nullptr || passwd->pw_name[0] == '\0') {
		log_error() << "OS: getpwuid() returned NULL or empty user, falling back to $USER" << std::endl;
	} else {
		return passwd->pw_name;
	}

	user = getenv("USER");
	if(user && user[0])
		return user;

	throw std::runtime_error("Unable to determine user name, please fix your system");
}

static void gather_system_info(nimrun_system_info& sysinfo, const nimrun_args& args, cluster_t cluster)
{
	sysinfo.cluster = cluster;

	memset(&sysinfo.uname, 0, sizeof(sysinfo.uname));
	if(uname(&sysinfo.uname) < 0)
	{
		log_error() << "OS: uname() failed" << std::endl;
		log_error() << "OS:   errno   = "   << errno << std::endl;
		log_error() << "OS:   message = "   << strerror(errno) << std::endl;
		throw make_posix_exception(errno);
	}

	fs::path cwd = fs::current_path();

	sysinfo.username = get_username();
	sysinfo.hostname = sysinfo.uname.nodename;
	sysinfo.simple_hostname = sysinfo.hostname.substr(0, sysinfo.hostname.find_first_of('.'));
	sysinfo.batch_info.job_id = "";
	sysinfo.batch_info.outdir = cwd.c_str();
	sysinfo.batch_info.ompthreads = 1;

	batch_info_proc_t infoproc = cluster_info_procs[static_cast<size_t>(cluster)];
	assert(infoproc != nullptr);

	sysinfo.batch_info = infoproc();

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

	std::sort(sysinfo.nimrod_resources.begin(), sysinfo.nimrod_resources.end(), [](const auto& a, const auto& b){
		return a.name < b.name;
	});

	std::string statsname = std::string("nimrod-") + sysinfo.batch_info.job_id;

	sysinfo.openssh			= locate_openssh();
	sysinfo.nimrod_home		= args.nimrod_home;
	sysinfo.tmpdir			= args.tmpdir;
	sysinfo.outdir			= args.outdir ? args.outdir : sysinfo.batch_info.outdir;
	sysinfo.outdir_stats	= sysinfo.outdir / statsname;
	sysinfo.java_home		= args.java_home;
	sysinfo.java			= sysinfo.java_home / "bin" / "java";
	sysinfo.qpid_home		= args.qpid_home;
	sysinfo.qpid_work		= sysinfo.tmpdir / "qpid-work";
	sysinfo.qpid_cfg		= sysinfo.outdir_stats / "qpid-initial-config.json";
	sysinfo.nimrod_work		= sysinfo.tmpdir / "nimrod-work";
	sysinfo.nimrod_dbpath	= sysinfo.nimrod_work / "nimrod.db";
	sysinfo.nimrod_ini		= sysinfo.outdir_stats / "nimrod.ini";
	sysinfo.nimrod_setupini	= sysinfo.outdir_stats / "nimrod-setup.ini";
	sysinfo.pem_cert		= sysinfo.outdir_stats / "cert.pem";
	sysinfo.pem_key			= sysinfo.outdir_stats / "key.pem";
	sysinfo.pkcs12_cert		= sysinfo.outdir_stats / "cert.p12";
	sysinfo.stdout_path		= sysinfo.outdir_stats / "out";
	sysinfo.stderr_path		= sysinfo.outdir_stats / "err";

	/* Can't use these, needs to compile with GCC 7.2 */
	//sysinfo.stdout_path_rel	= fs::relative(sysinfo.stdout_path, sysinfo.outdir);
	//sysinfo.stderr_path_rel	= fs::relative(sysinfo.stderr_path, sysinfo.outdir);
	sysinfo.stdout_path_rel	= fs::path(statsname) / "out";
	sysinfo.stderr_path_rel	= fs::path(statsname) / "err";
	sysinfo.password		= generate_random_password(32);

	if(get_ip_addrs(sysinfo.interfaces) < 0)
		throw make_posix_exception(errno);
}

static nlohmann::json dump_system_info_json(const nimrun_args& args, const nimrun_system_info& si)
{
	nlohmann::json ips = nlohmann::json::array();
	for(const auto& it : si.interfaces)
		ips.push_back(it);

	nlohmann::json res = nlohmann::json::array();
	for(const auto& it : si.nimrod_resources)
	{
		res.push_back({
			{"name", it.name},
			{"uri", it.uri},
			{"num_agents", it.num_agents},
			{"local", it.local}
		});
	}

	nlohmann::json nodes = nlohmann::json::object();
	for(const auto& it : si.batch_info.nodes)
		nodes[it.first] = it.second;

	nlohmann::json jargv = nlohmann::json::array();
	for(int i = 0; i < args.argc; ++i)
		jargv.push_back(args.argv[i]);

	nlohmann::json jfwdenv = nlohmann::json::array();
	for(const std::string& s : si.batch_info.fwdenv)
		jfwdenv.push_back(s);

	nlohmann::json env;
	for(size_t i = 0; environ[i] != nullptr; ++i)
		env[i] = environ[i];

	return {
		{"argv", jargv},
		{"environment", env},
		{"cluster", si.cluster},
		{"execmode", args.mode},
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
		{"batch_info", {
			{"ompthreads", si.batch_info.ompthreads},
			{"nodes", nodes},
			{"job_id", si.batch_info.job_id},
			{"outdir", si.batch_info.outdir},
			{"fwdenv", jfwdenv}
		}},
		{"outdir", si.outdir},
		{"outdir_stats", si.outdir_stats},
		{"nimrod_resources", res},
		{"openssh", si.openssh.value_or("")},
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
		{"stdout_path", si.stdout_path},
		{"stderr_path", si.stderr_path},
		{"stdout_path_rel", si.stdout_path_rel},
		{"stderr_path_rel", si.stderr_path_rel},
		{"password", si.password},
		{"interfaces", ips},
		{"compile_info", {
			{"revision", g_compile_info.revision},
			{"version", {
				{"nimrun", g_compile_info.version.nimrun},
				{"openssl", g_compile_info.version.openssl},
			}},
		}}
	};
}

static cluster_t detect_cluster(const char *cluster)
{
	/* Used for autodetection. */
	struct env_t
	{
		const char	*name;
		cluster_t	cluster;
	} envs[] = {
		{"PBS_JOBID",			cluster_t::generic_pbs},
		{"PBS_O_WORKDIR",		cluster_t::generic_pbs},

		{"SLURM_CLUSTER_NAME",	cluster_t::generic_slurm},
		{"SLURM_JOB_ID",		cluster_t::generic_slurm},
		{"SLURM_SUBMIT_DIR",	cluster_t::generic_slurm},
		{"SLURM_JOB_NODELIST",	cluster_t::generic_slurm},
		{"SLURM_NODELIST",		cluster_t::generic_slurm},

		{"LSB_JOBID",			cluster_t::generic_lsf},
		{"LS_SUBCWD",			cluster_t::generic_lsf},
		{"LSB_MCPU_HOSTS",		cluster_t::generic_lsf},
	};

	if(cluster != nullptr)
		return nlohmann::json(cluster).get<cluster_t>();

	/*
	 * This is very rudimentary detection code. It just checks for existence
	 * of known environment variables.
	 */
	for(const env_t& e : envs)
	{
		if(const char *val = getenv(e.name); val != nullptr && val[0] != '\0')
			return e.cluster;
	}

	return cluster_t::unknown;
}

static void mkdir(const fs::path& p)
{
    std::error_code ec;

    log_debug(log_level_debug) << "IO: fs::create_directories(" << p << ")" << std::endl;

    fs::create_directories(p, ec);
    if(ec)
    {
        log_error() << "IO: Unable to create directory"   << std::endl;
        log_error() << "IO:   path    = " << p            << std::endl;
        log_error() << "IO:   code    = " << ec.value()   << std::endl;
        log_error() << "IO:   message = " << ec.message() << std::endl;
        throw std::system_error(ec);
    }
}

int main(int argc, char **argv)
{
	nimrun_args& args = nimrun.args;
	int status = parse_arguments(argc, argv, stdout, stderr, &args);
	if(status != 0)
		return status;

	if(args.version)
		return 0;

	cluster_t cluster = detect_cluster(args.cluster);
	if(cluster == cluster_t::unknown)
	{
		log_error() << "Unknown cluster, please contact your system administrator..." << std::endl;
		return 1;
	}

	gather_system_info(nimrun.sysinfo, args, cluster);
	const nimrun_system_info& sysinfo = nimrun.sysinfo;

	nlohmann::json jcfg = dump_system_info_json(args, sysinfo);
	if(args.debug >= log_level_debug)
		log_debug(log_level_debug) << std::setw(4) << jcfg << std::setw(0) << std::endl;

	/* It is expected that this directory is accessible from any node. */
	mkdir(sysinfo.outdir_stats);
	{
		std::ofstream os(open_write_file(sysinfo.outdir_stats / "nimrun-config.json"));
		os << std::setw(4) << jcfg << std::endl;
	}

	mkdir(sysinfo.stdout_path);
	mkdir(sysinfo.stderr_path);

	if(args.mode == exec_mode_t::nimexec)
	{
		nimrun.planfile = sysinfo.outdir_stats / "planfile.pln";
		nimrun.generated_script = sysinfo.outdir_stats / "generated";
		process_shellfile(
			args.planfile,
			nimrun.planfile, nimrun.generated_script,
			sysinfo.stdout_path_rel, sysinfo.stderr_path_rel,
			argc - 1, argv + 1
		);
	}
	else
	{
		nimrun.planfile = args.planfile;
		fs::copy(nimrun.planfile, sysinfo.outdir_stats / "planfile.pln", fs::copy_options::overwrite_existing);
	}

	if(!sysinfo.openssh)
	{
		log_error() << "Unable to locate OpenSSH. Exiting..." << std::endl;
		return 1;
	}

	if(!fs::is_regular_file(sysinfo.java))
	{
		log_error() << "Unable to locate Java. Exiting..." << std::endl;
		return 1;
	}

	if(sysinfo.cluster == cluster_t::unknown)
	{
		log_error() << "Unknown cluster, please contact your system administrator..." << std::endl;
		return 1;
	}

	init_openssl();
	auto sslcrap = make_protector(deinit_openssl);

	evp_pkey_ptr key = create_pkey(4096);
	if(!key)
		return dump_openssl_errors(stderr), 1;

	std::vector<std::string_view> certnames;
	certnames.reserve(sysinfo.interfaces.size() + 1);
	certnames.emplace_back(sysinfo.simple_hostname);
	for(const std::string& i : sysinfo.interfaces)
		certnames.emplace_back(i);

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
	{
		std::ofstream os(open_write_file(sysinfo.qpid_cfg));
		generate_qpid_json(os,
			sysinfo.qpid_work,
			sysinfo.username,
			sysinfo.password,
			sysinfo.pkcs12_cert,
			sysinfo.password,
			0,
			args.qpid_management_port
		);
	}

	/* Create nimrod.ini. nimrod-setup.ini can't be done until later. */
	mkdir(nimrun.sysinfo.nimrod_work);
	{
		std::ofstream os(open_write_file(nimrun.sysinfo.nimrod_ini));
		build_nimrod_ini(os, nimrun.sysinfo.nimrod_dbpath);
	}

	if(install_signal_handlers() < 0)
		throw make_posix_exception(errno);

	nimcli nimrod(sysinfo.java, sysinfo.openssh.value(), sysinfo.tmpdir, sysinfo.nimrod_home, "x86_64-pc-linux-musl", sysinfo.nimrod_ini, sysinfo.outdir, args.debug >= log_level_nimrod_debug);

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
				log_debug(log_level_state) << "LEAVE " << state_strings[ostate] << std::endl;
				state_handlers[ostate].handler(old_state, state_mode_t::leave, nimrun);
			}
			catch(std::exception& e)
			{
				log_error() << "Caught exception during LEAVE transition: " << e.what() << std::endl;
				state = state_handlers[istate].interrupt_state;
			}

			/* Stop at the first state without a handler. */
			if(state_handlers[istate].handler == nullptr)
				break;

			try
			{
				log_debug(log_level_state) << "ENTER " << state_strings[istate] << std::endl;
				state_handlers[istate].handler(state, state_mode_t::enter, nimrun);
			}
			catch(std::exception& e)
			{
				log_error() << "Caught exception during ENTER transition: " << e.what() << std::endl;
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
				log_debug(log_level_state) << "RUN   " << state_strings[istate] << std::endl;
				state = state_handlers[istate].handler(state, state_mode_t::run, nimrun);
			}
			catch(std::exception& e)
			{
				log_error() << "Caught exception during RUN: " << e.what() << std::endl;
				state = state_handlers[istate].interrupt_state;
			}
		}
		//sleep(1);
		usleep(500000);
	}

	/* Copy things for later investigation. */

	if(fs::exists(sysinfo.nimrod_dbpath))
		fs::copy(sysinfo.nimrod_dbpath, sysinfo.outdir_stats, fs::copy_options::overwrite_existing);
	return 0;
}

static state_t handler_none(state_t state, state_mode_t mode, nimrun_state& nimrun)
{
	(void)state;
	(void)mode;
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
	if(auto it = std::find(ports.begin(), ports.end(), nimrun.args.qpid_management_port); it != ports.end())
		ports.erase(it);

	if(ports.empty())
		return state;

	log_debug(log_level_debug) << "Detected QPID listening on port " << ports[0] << std::endl;
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
	{
		std::ofstream os(open_write_file(nimrun.sysinfo.nimrod_setupini));
		build_nimrod_setupini(
			os,
			nimrun.sysinfo.nimrod_home,
			nimrun.sysinfo.nimrod_work,
			nimrun.sysinfo.username.c_str(),
			nimrun.sysinfo.password.c_str(),
			nimrun.sysinfo.simple_hostname.c_str(),
			nimrun.qpid_port,
			nimrun.sysinfo.pem_cert
		);
	}

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
					static_cast<uint32_t>(nimrun.resit->num_agents),
					nimrun.sysinfo.batch_info.fwdenv
				);
			}
		}
		else if(state == state_t::nimrod_assign)
		{
			nimrun.nimrod_pid = nimrun.cli->assign_resource(nimrun.resit->name.c_str(), "localexp");
		}
		else
		{
			/* invalid */
			return state_t::nimrod_cleanup;
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
		{
			switch(state)
			{
				case state_t::nimrod_addresource:
					state = state_t::nimrod_assign;
					break;
				case state_t::nimrod_assign:
					state = state_t::nimrod_master;
					break;
				default:
					/* invalid */
					state = state_t::nimrod_cleanup;
					break;
			}
		}
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
				nimrun.nimrod_pid = nimrun.cli->add_experiment("localexp", nimrun.planfile.c_str());
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

		switch(state)
		{
			case state_t::nimrod_init:
				state = state_t::nimrod_addexp;
				break;
			case state_t::nimrod_addexp:
				state = state_t::nimrod_addresource;
				break;
			case state_t::nimrod_master:
				/* valid */
			default:
				/* invalid */
				state = state_t::nimrod_cleanup;
				break;
		}
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
