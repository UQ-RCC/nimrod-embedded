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
		qhome.c_str(),
		qwork.c_str(),
		"-Dderby.stream.error.file=/dev/null",
		"org.apache.qpid.server.Main",
		"--store-type", "Memory",
		"--initial-config-path", icp.c_str(),
		nullptr
	};

	return spawn_process(argv[0], const_cast<char * const *>(argv), -1);
}
