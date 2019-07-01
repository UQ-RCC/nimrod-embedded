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
#include <cstdio>
#include <fstream>
#include "nimrun.hpp"

void write_file(const fs::path& path, const char *s)
{
	std::ofstream f;
	f.exceptions(std::ifstream::failbit | std::ifstream::badbit);
	f.open(path, std::ios::binary);
	f.write(s, strlen(s));
}

void write_file(const fs::path& path, const std::string& s)
{
	std::ofstream f;
	f.exceptions(std::ifstream::failbit | std::ifstream::badbit);
	f.open(path, std::ios::binary);
	f.write(s.c_str(), s.size());
}

std::unique_ptr<char[]> read_file(const fs::path& path, size_t& size)
{
	std::ifstream f(path, std::ios::binary);
	if(!f)
		return nullptr;

	if(!f.seekg(0, std::ios::end))
		return nullptr;

	size_t _size = static_cast<size_t>(f.tellg());
	if(!f.seekg(0, std::ios::beg))
		return nullptr;

	std::unique_ptr<char[]> buf = std::make_unique<char[]>(_size);
	if(!f.read(buf.get(), _size))
		return nullptr;

	size = _size;
	return buf;
}

std::string generate_random_password(size_t length)
{
	/* NB: Keeping this alphanumeric deliberately. */
	constexpr static const char s_character_set[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";

	std::string s(length, '\0');
	file_ptr f(fopen("/dev/urandom", "rb"));

	if(!f)
		throw std::runtime_error("Can't open /dev/urandom");

	fread(&s[0], s.length(), 1, f.get());
	for(size_t i = 0; i < s.length(); ++i)
		s[i] = s_character_set[s[i] % (sizeof(s_character_set) - 1)];

	return s;
}

std::system_error make_posix_exception(int err)
{
	return std::system_error(err, std::generic_category());
}

pid_t spawn_process(const char *path, char * const *argv, int fdin) noexcept
{
	pid_t pid = fork();
	if(pid != 0)
		return pid;

	/* Force us into a new process group so Bash can't SIGINT us. */
	setpgid(0, 0);

	if(fdin >= 0)
	{
		dup2(fdin, STDIN_FILENO);
		close(fdin);
	}

	execvp(path, argv);
	_exit(1);
}
