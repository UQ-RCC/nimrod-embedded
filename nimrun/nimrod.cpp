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
#include <sstream>
#include <unistd.h>
#include <fcntl.h>
#include "nimrun.hpp"

std::ostream& build_nimrod_ini(std::ostream& os, const fs::path& dbpath)
{
	os << "[config]" << std::endl;
	os << "factory=au.edu.uq.rcc.nimrodg.impl.sqlite3.SQLite3APIFactory" << std::endl;
	os << std::endl;
	os << "[sqlite3]" << std::endl;
	os << "driver=org.sqlite.JDBC" << std::endl;
	os << "url=jdbc:sqlite:" << dbpath.u8string() << std::endl;
	return os;
}

std::ostream& build_nimrod_setupini(
	std::ostream& os,
	const fs::path& nimrod_home,
	const fs::path& nimrod_work,
	std::string_view user,
	std::string_view pass,
	std::string_view hostname,
	uint16_t port,
	const fs::path& cert_path
)
{
	os << "[config]" << std::endl;
	os << "workdir=" << nimrod_work.u8string() << fs::path::preferred_separator << std::endl;
	os << "storedir=${workdir}/experiments" << fs::path::preferred_separator << std::endl;
	os << std::endl;
	os << "[amqp]" << std::endl;
	os << "uri=amqps://" << user << ":" << pass << "@" << hostname << ":" << port << "/default" << std::endl;
	os << "routing_key=iamthemaster" << std::endl;
	os << "cert=" << cert_path.u8string() << std::endl;
	os << "no_verify_peer=false" << std::endl;
	os << "no_verify_host=false" << std::endl;
	os << std::endl;
	os << "[transfer]" << std::endl;
	os << "uri=file://${config/storedir}" << fs::path::preferred_separator << std::endl;
	os << "cert=" << std::endl;
	os << "no_verify_peer=false" << std::endl;
	os << "no_verify_host=false" << std::endl;
	os << std::endl;
	os << "[agents]" << std::endl;
	os << "x86_64-pc-linux-musl=" << (nimrod_home / "agents" / "agent-x86_64-pc-linux-musl").u8string() << std::endl;
	os << std::endl;
	os << "[agentmap]" << std::endl;
	os << "Linux,x86_64=x86_64-pc-linux-musl" << std::endl;
	os << std::endl;
	os << "[resource_types]" << std::endl;
	os << "local=au.edu.uq.rcc.nimrodg.resource.LocalResourceType" << std::endl;
	os << "remote=au.edu.uq.rcc.nimrodg.resource.RemoteResourceType" << std::endl;
	os << std::endl;
	os << "[properties]" << std::endl;
	os << "nimrod.sched.default.launch_penalty=-10" << std::endl;
	os << "nimrod.sched.default.spawn_cap=2147483647" << std::endl;
	os << "nimrod.sched.default.job_buf_size=10000" << std::endl;
	os << "nimrod.sched.default.job_buf_refill_threshold=1000" << std::endl;
	os << "nimrod.master.run_rescan_interval=60" << std::endl;
	os << "nimrod.master.heart.expiry_retry_interval=5" << std::endl;
	os << "nimrod.master.heart.expiry_retry_count=5" << std::endl;
	os << "# Disable heartbeats for now because they're broken." << std::endl;
	os << "nimrod.master.heart.interval=0" << std::endl;
	os << "nimrod.master.heart.missed_threshold=5" << std::endl;
	return os;
}

nimcli::nimcli(const fs::path& java, const fs::path& openssh, const fs::path& tmpdir, const fs::path& nimrod_home, const std::string& platform, const fs::path& ini, const fs::path& fsroot, bool debug) :
	m_java(java),
	m_openssh(openssh),
	m_tmpdir(tmpdir),
	m_nimrod_home(nimrod_home),
	m_platform(platform),
	m_ini(ini),
	m_rooturi("file://"),
	m_classpath(m_nimrod_home / "lib/*"),
	m_devnull(open("/dev/null", O_RDWR))
{
	m_rooturi.append(fsroot.c_str());

	m_tmparg = "-Djava.io.tmpdir=";
	m_tmparg.append(tmpdir);

	m_args.push_back(m_java.c_str());
	m_args.push_back("-server");
	m_args.push_back(m_tmparg.c_str());
	m_args.push_back("-cp");
	m_args.push_back(m_classpath.c_str());
	m_args.push_back("au.edu.uq.rcc.nimrodg.cli.NimrodCLI");
	m_args.push_back("-c");
	m_args.push_back(ini.c_str());

	if(debug)
		m_args.push_back("-d");

	m_basecount = m_args.size();

	if(!m_devnull)
		throw make_posix_exception(errno);
}

pid_t nimcli::setup_init(const fs::path& setupini)
{
	m_args.resize(m_basecount);
	m_args.push_back("setup");
	m_args.push_back("init");
	m_args.push_back("--skip-system");
	m_args.push_back(setupini.c_str());
	m_args.push_back(nullptr);
	return fork_and_reset();
}

pid_t nimcli::add_local_resource(const char *name, uint32_t parallelism)
{
	m_args.resize(m_basecount);
	char nas[16];
	sprintf(nas, "%u", parallelism);
	m_args.push_back("resource");
	m_args.push_back("add");
	m_args.push_back(name);
	m_args.push_back("local");
	m_args.push_back("--");
	m_args.push_back("--parallelism");
	m_args.push_back(nas);
	m_args.push_back("--platform");
	m_args.push_back(m_platform.c_str());
	m_args.push_back("--capture-output");
	m_args.push_back("copy");
	m_args.push_back(nullptr);
	return fork_and_reset();
}

pid_t nimcli::add_remote_resource(const char *name, const char *uri, uint32_t limit, const std::vector<std::string>& fwdenv)
{
	m_args.resize(m_basecount);

	char nas[16];
	sprintf(nas, "%u", limit);

	m_args.push_back("resource");
	m_args.push_back("add");
	m_args.push_back(name);
	m_args.push_back("remote");
	m_args.push_back("--");
	m_args.push_back("--uri");
	m_args.push_back(uri);
	m_args.push_back("--limit");
	m_args.push_back(nas);
	m_args.push_back("--platform");
	m_args.push_back(m_platform.c_str());
	m_args.push_back("--transport");
	m_args.push_back("openssh");
	m_args.push_back("--openssh-executable");
	m_args.push_back(m_openssh.c_str());
	m_args.push_back("--tmpdir");
	m_args.push_back(m_tmpdir.c_str());

	for(const std::string& e : fwdenv)
	{
		m_args.push_back("--forward-env");
		m_args.push_back(e.c_str());
	}

	m_args.push_back(nullptr);
	return fork_and_reset();
}

pid_t nimcli::add_experiment(const char *name, const char *planfile)
{
	m_args.resize(m_basecount);
	m_args.push_back("addexp");
	m_args.push_back(name);
	m_args.push_back(nullptr);

	int fd = open(planfile, O_RDONLY);
	if(fd < 0)
		throw make_posix_exception(errno);

	return fork_and_reset(fd);
}

pid_t nimcli::assign_resource(const char *resource, const char *exp)
{
	m_args.resize(m_basecount);
	m_args.push_back("resource");
	m_args.push_back("assign");
	m_args.push_back(resource);
	m_args.push_back(exp);
	m_args.push_back("--tx-uri");
	m_args.push_back(m_rooturi.c_str());
	m_args.push_back(nullptr);
	return fork_and_reset();
}

pid_t nimcli::master(const char *exp, uint32_t tick_rate)
{
	m_args.resize(m_basecount);
	m_args.push_back("master");

	char buf[16];
	if(tick_rate > 0)
	{
		m_args.push_back("--tick-rate");
		sprintf(buf, "%u", tick_rate);
		m_args.push_back(buf);
	}
	m_args.push_back(exp);
	m_args.push_back(nullptr);
	return fork_and_reset();
}

pid_t nimcli::fork_and_reset() noexcept
{
	return fork_and_reset(m_devnull.get());
}

pid_t nimcli::fork_and_reset(int fdin) noexcept
{
	pid_t pid = spawn_process(m_args[0], const_cast<char * const *>(m_args.data()), fdin);

	m_args.resize(m_basecount);

	if(fdin != m_devnull.get())
		close(fdin);

	return pid;
}
