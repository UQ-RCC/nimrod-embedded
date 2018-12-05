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
#include <cstdint>
#include "json.hpp"
#include "nimrun.hpp"
#include <cstdio>

using json = nlohmann::json;

std::string generate_qpid_json(const fs::path& qpid_work, const char *user, const char *pass, const fs::path& cert_path, const char *cert_pass, uint16_t amqpPort, uint16_t managementPort)
{
	fs::path log_file = qpid_work / "log" / "qpid.log";
    json j = {
		{"name", "${broker.name}"},
		{"modelVersion", "7.0"},
		{"authenticationproviders", {
			{
				{"name", "nimrod_local"},
				{"type", "Plain"},
				{"users", {
					{
						{"name", user},
						{"type", "managed"},
						{"password", pass}
					}
				}}
			}
		}},
		{"brokerloggers", {
			{"name", "logfile"},
			{"type", "File"},
			{"fileName", log_file},
			{"brokerloginclusionrules", {
				{
					{"name", "Root"},
					{"type", "NameAndLevel"},
					{"level", "WARN"},
					{"loggerName", "ROOT"}
				},
				{
					{"name", "Qpid"},
					{"type", "NameAndLevel"},
					{"level", "INFO"},
					{"loggerName", "org.apache.qpid.*"}
				},
				{
					{"name", "Operational"},
					{"type", "NameAndLevel"},
					{"level", "INFO"},
					{"loggerName", "qpid.message.*"}
				},
				{
					{"name", "Statistics"},
					{"type", "NameAndLevel"},
					{"level", "INFO"},
					{"loggerName", "qpid.statistics.*"}
				}
			}}
		}},
		{"keystores", {
			{
				{"name", "nimrod_local"},
				{"type", "FileKeyStore"},
				{"password", cert_pass},
				{"storeUrl", cert_path}
			}
		}},
		{"ports", {
			{
				{"name", "nimrod_local"},
				{"type", "AMQP"},
				{"authenticationProvider", "nimrod_local"},
				{"keyStore", "nimrod_local"},
				{"needClientAuth", false},
				{"port", amqpPort},
				{"protocols", {
					"AMQP_0_9_1"
				}},
				{"transports", {
					"SSL"
				}},
				{"wantClientAuth", false},
				{"virtualhostaliases", {
					{
						{"name", "defaultAlias"},
						{"type", "defaultAlias"}
					},
					{
						{"name", "hostnameAlias"},
						{"type", "hostnameAlias"}
					},
					{
						{"name", "nameAlias"},
						{"type", "nameAlias"}
					}
				}}
			}
		}},
		{"virtualhostnodes", {
			{
				{"name", "default"},
				{"type", "JSON"},
				{"defaultVirtualHostNode", "true"},
				{"virtualHostInitialConfiguration", "${qpid.initial_config_virtualhost_config}"}
			}
		}},
		{"plugins", json::array()}
	};

	if(managementPort > 0)
	{
		j["plugins"].push_back({{"type", "MANAGEMENT-HTTP"}, {"name", "httpManagement"}});
		j["ports"].push_back({
			{"name", "HTTP"},
			{"port", managementPort},
			{"authenticationProvider", "nimrod_local"},
			{"protocols", {"HTTP"}}
		});
	}
	
	return j.dump(4, ' ');
}

#include <unistd.h>
#include <vector>
#include <string>

pid_t launch_qpid(const fs::path& java, const fs::path& qpid_home, const fs::path& qpid_work, const fs::path& icp)
{
	/* c_str() is suitable for use with OS APIs */
	std::string qhome = "-DQPID_HOME=";
	qhome.append(qpid_home.c_str());

	std::string qwork = "-DQPID_WORK=";
	qwork.append(qpid_work.c_str());

	/* Abuse this to handle escaping */
	fs::path cp_lib = qpid_home / "lib/*";
	fs::path cp_plugins = qpid_home / "lib/plugins/*";
	fs::path cp_opt = qpid_home / "lib/opt/*";

	std::string classpath = cp_lib.c_str();
	classpath.append(":");
	classpath.append(cp_plugins);
	classpath.append(":");
	classpath.append(cp_opt);

	const char *argv[] = {
		java.c_str(), "-server",
		"-cp", classpath.c_str(),
		"-XX:+HeapDumpOnOutOfMemoryError",
		"-Xmx512m", "-XX:MaxDirectMemorySize=1536m",
		"--add-modules", "java.xml.bind",
		qhome.c_str(),
		qwork.c_str(),
		"-Dderby.stream.error.file=/dev/null",
		"org.apache.qpid.server.Main",
		"--store-type", "Memory",
		"--initial-config-path", icp.c_str(),
		nullptr
	};

	pid_t pid = fork();
	if(pid == 0)
	{
		/* Force us into a new process group so Bash can't SIGINT us. */
		setpgid(0, 0);
		execvp(argv[0], const_cast<char * const *>(argv));
		_exit(1);
	}

	return pid;
}