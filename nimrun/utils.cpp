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

fs::path getenv_path(const char *name)
{
	const char *c = getenv(name);
	if(c == nullptr)
		return fs::path();
	
	return fs::path(c);
}

std::system_error make_posix_exception(int err)
{
	return std::system_error(err, std::generic_category());
}
