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
#include <vector>
#include <string>
#include <cstring>
#include <fstream>
#include <algorithm>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include "nimrun.hpp"

int get_ip_addrs(std::vector<std::string>& addrs)
{
	/* If you have more than 32 interfaces then seek help. */
	constexpr size_t num_reqs = 32;
	struct ifreq reqs[num_reqs];
	struct ifconf conf;

	memset(reqs, 0, sizeof(reqs));
	memset(&conf, 0, sizeof(ifconf));
	conf.ifc_req = reqs;
	conf.ifc_len = sizeof(reqs);

	fd_ptr s(socket(AF_UNIX, SOCK_STREAM, 0));
	if(!s)
		return -1;

	if(ioctl(s.get(), SIOCGIFCONF, &conf) < 0)
		return -1;

	size_t naddr = conf.ifc_len / sizeof(struct ifreq);

	;
	for(size_t i = 0; i < naddr; ++i)
		addrs.emplace_back(inet_ntoa(reinterpret_cast<struct sockaddr_in *>(&reqs[i].ifr_addr)->sin_addr));

	return static_cast<int>(naddr);
}

struct tcp_entry
{
	uint16_t sl;
	uint32_t local_address;
	uint16_t local_port;
	uint32_t remote_address;
	uint16_t remote_port;
	uint8_t st;
	uint32_t tx_queue;
	uint32_t rx_queue;
	uint8_t tr;
	uint32_t tm_when;
	uint32_t retrnsmt;
	uint32_t uid;
	uint32_t timeout;
	uint32_t inode;
	/* There's other stuff afterwards I don't care about. */
};

static tcp_entry *parse_tcp(const char *s, tcp_entry *e) noexcept
{
	int ret = sscanf(s, " %hu: %x:%hx %u:%hx %hhx %x:%x %hhx:%x %x %u %u %u",
		&e->sl,
		&e->local_address, &e->local_port,
		&e->remote_address, &e->remote_port,
		&e->st,
		&e->tx_queue, &e->rx_queue,
		&e->tr, &e->tm_when,
		&e->retrnsmt,
		&e->uid,
		&e->timeout,
		&e->inode
	);
	if(ret != 14)
		return nullptr;

	return e;
}

static std::vector<tcp_entry> read_tcp_entries()
{
	std::vector<tcp_entry> tcp;

	std::ifstream f;
	f.open("/proc/net/tcp", std::ios::binary);
	std::string entry;
	std::getline(f, entry);
	while(std::getline(f, entry))
	{
		tcp_entry e;
		if(parse_tcp(entry.c_str(), &e) == nullptr)
			continue;

		tcp.push_back(e);
	}

	return tcp;
}

std::vector<uint16_t> get_listening_ports(pid_t pid)
{
	char _fdpath[32]; /* Enough to fit "/proc/<anypid>/fd" */
	sprintf(_fdpath, "/proc/%d/fd", static_cast<int>(pid));

	std::vector<uint16_t> ports;
	std::vector<tcp_entry> tcp = read_tcp_entries();

	for(auto& de : fs::directory_iterator(_fdpath))
	{
		if(!de.is_symlink())
			continue;

		fs::path link = fs::read_symlink(de);

		uint32_t inode;
		if(sscanf(link.c_str(), "socket:[%u]", &inode) != 1)
			continue;

		auto it = std::find_if(tcp.begin(), tcp.end(), [inode](const tcp_entry& e){
			return e.inode == inode;
		});

		if(it == tcp.end())
			continue;

		ports.push_back(it->local_port);
	}

	return ports;
}
