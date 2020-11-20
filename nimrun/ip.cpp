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
#include <fstream>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include "nimrun.hpp"

struct ifa_deleter
{
	void operator()(struct ifaddrs *ifap) noexcept { freeifaddrs(ifap); }
};
using ifa_ptr = std::unique_ptr<struct ifaddrs, ifa_deleter>;

int get_ip_addrs(std::vector<std::string>& addrs)
{
	struct ifaddrs *_ifap = nullptr;
	if(getifaddrs(&_ifap) < 0)
		return -1;

	ifa_ptr ifap(_ifap);

	char buf[std::max(INET_ADDRSTRLEN, INET6_ADDRSTRLEN)];

	for(struct ifaddrs *ifa = ifap.get(); ifa != nullptr; ifa = ifa->ifa_next)
	{
		if(ifa->ifa_addr == nullptr)
			continue;

		const void *addr = nullptr;
		if(ifa->ifa_addr->sa_family == AF_INET)
			addr = &reinterpret_cast<struct sockaddr_in*>(ifa->ifa_addr)->sin_addr;
		else if(ifa->ifa_addr->sa_family == AF_INET6)
			addr = &reinterpret_cast<struct sockaddr_in6*>(ifa->ifa_addr)->sin6_addr;

		if(addr == nullptr)
			continue;

		inet_ntop(ifa->ifa_addr->sa_family, addr, buf, sizeof(buf));
		addrs.emplace_back(buf);
	}

	return 0;
}

struct tcp_entry
{
	int					family;
	uint16_t			sl;
	union
	{
		struct in_addr	sin_addr;
		struct in6_addr	sin6_addr;
	}					local_address;
	uint16_t			local_port;
	union
	{
		struct in_addr	sin_addr;
		struct in6_addr	sin6_addr;
	}					remote_address;
	uint16_t			remote_port;
	uint8_t				st;
	uint32_t			tx_queue;
	uint32_t			rx_queue;
	uint8_t				tr;
	uint32_t			tm_when;
	uint32_t			retrnsmt;
	uint32_t			uid;
	uint32_t			timeout;
	uint32_t			inode;
	/* There's other stuff afterwards I don't care about. */
};

static void convert(struct in_addr *addr, const char *s)
{
	/* Convert into dot-notation so inet_pton can handle it. */
	uint8_t b[4];
	sscanf(s, "%2hhx%2hhx%2hhx%2hhx", b + 3, b + 2, b + 1, b + 0);

	char buf[16];
	sprintf(buf, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);

	inet_pton(AF_INET, buf, addr);
}

static void convert(struct in6_addr *addr, const char *s)
{
	/* 00000000000000000000000001000000 */
	/* 4 32-bit numbers, stored as LE. */

	/* "B80D01200000000067452301EFCDAB89" == 2001:0DB8:0000:0000:0123:4567:89AB:CDEF" */
	char buf[40];
	sprintf(buf, "%.2s%.2s:%.2s%.2s:%.2s%.2s:%.2s%.2s:%.2s%.2s:%.2s%.2s:%.2s%.2s:%.2s%.2s",
		s +  6, s +  4,
		s +  2, s +  0,
		s + 14, s + 12,
		s + 10, s +  8,
		s + 22, s + 20,
		s + 18, s + 16,
		s + 30, s + 28,
		s + 26, s + 24
	);

	inet_pton(AF_INET6, buf, addr);
}


static tcp_entry *parse_tcp4(const char *s, tcp_entry *e) noexcept
{
	char l8[9];
	char r8[9];
	int ret = sscanf(s, " %hu: %8s:%hx %8s:%hx %hhx %x:%x %hhx:%x %x %u %u %u",
		&e->sl,
		l8, &e->local_port,
		r8, &e->remote_port,
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

	e->family = AF_INET;
	convert(&e->local_address.sin_addr, l8);
	convert(&e->remote_address.sin_addr, r8);

	return e;
}

static tcp_entry *parse_tcp6(const char *s, tcp_entry *e) noexcept
{
	char l32[33];
	char r32[33];
	int ret = sscanf(s, " %hu: %32s:%hx %32s:%hx %hhx %x:%x %hhx:%x %x %u %u %u",
		&e->sl,
		l32, &e->local_port,
		r32, &e->remote_port,
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

	e->family = AF_INET6;
	convert(&e->local_address.sin6_addr, l32);
	convert(&e->remote_address.sin6_addr, r32);
	return e;
}

static std::vector<tcp_entry> read_tcp_entries()
{
	std::vector<tcp_entry> tcp;

	std::string entry;

	std::ifstream f;
	f.open("/proc/net/tcp", std::ios::binary);
	std::getline(f, entry);
	while(std::getline(f, entry))
	{
		tcp_entry e{};
		if(parse_tcp4(entry.c_str(), &e) == nullptr)
			continue;

		tcp.push_back(e);
	}
	f.close();
	f.open("/proc/net/tcp6", std::ios::binary);
	std::getline(f, entry);
	while(std::getline(f, entry))
	{
		tcp_entry e{};
		if(parse_tcp6(entry.c_str(), &e) == nullptr)
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
		if(!fs::is_symlink(de))
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
