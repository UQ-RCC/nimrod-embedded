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
#include "json.hpp"
#include "nimrun.hpp"

using json = nlohmann::json;

std::string build_nimrod_ini(const fs::path& dbpath)
{
	std::string s =
		"[config]\n"
		"factory=au.edu.uq.rcc.nimrodg.impl.sqlite3.SQLite3APIFactory\n"
		"\n"
		"[sqlite3]\n"
		"driver=org.sqlite.JDBC\n"
		"url=jdbc:sqlite:"
	;

	s.append(dbpath);
	s.append("\n");
	return s;
}

std::string build_nimrod_setupini(const fs::path& nimrod_home, const fs::path& nimrod_work, const char *user, const char *pass, const char *hostname, uint16_t port, const fs::path& cert_path)
{
	fs::path agent = nimrod_home / "agents" / "agent-x86_64-pc-linux-musl";

	std::ostringstream ss;

	ss	<< "[config]\n"
		<< "workdir=" << nimrod_work.u8string() << "/\n"
		   "storedir=${workdir}/experiments\n"
		   "\n"
		   "[amqp]\n"
		<< "uri=amqps://" << user << ":" << pass << "@" << hostname << ":" << port << "/default" << "\n"
		<< "routing_key=iamthemaster\n"
		<< "cert=" << cert_path.u8string() << "\n"
		<< "no_verify_peer=false\n"
		   "no_verify_host=false\n"
		   "\n"
		   "[transfer]\n"
		<< "uri=file://${config/storedir}\n"
		<< "cert=\n"
		<< "no_verify_peer=false\n"
		   "no_verify_host=false\n"
		   "\n"
		   "[agents]\n"
		<< "x86_64-pc-linux-musl=" << agent.u8string() << "\n"
		   "\n"
		   "[agentmap]\n"
		"Linux,x86_64=x86_64-pc-linux-musl\n"
		"\n"
		"[resource_types]\n"
		"local=au.edu.uq.rcc.nimrodg.resource.LocalResourceType\n"
		"remote=au.edu.uq.rcc.nimrodg.resource.RemoteResourceType\n"
		"\n"
		"[properties]\n"
		"nimrod.sched.default.launch_penalty=-10\n"
		"nimrod.sched.default.spawn_cap=10\n"
		"nimrod.sched.default.job_buf_size=1000\n"
		"nimrod.sched.default.job_buf_refill_threshold=100\n"
		"nimrod.master.run_rescan_interval=60\n"
		"nimrod.master.heart.expiry_retry_interval=5\n"
		"nimrod.master.heart.expiry_retry_count=5\n"
		"# Disable heartbeats for now because they're broken.\n"
		"nimrod.master.heart.interval=0\n"
		"nimrod.master.heart.missed_threshold=5\n"
	;

	return ss.str();
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

pid_t nimcli::add_remote_resource(const char *name, const char *uri, uint32_t limit)
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
