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
#ifndef _NIMRUN_HPP
#define _NIMRUN_HPP

#include <memory>
#include <filesystem>
#include <unordered_map>
#include <cstdio>
#include <unistd.h>
#include <dlfcn.h>

namespace fs = std::filesystem;

struct file_desc
{
	file_desc(void) : _desc(-1) {}
	file_desc(int fd) : _desc(fd) {}
	file_desc(std::nullptr_t) : _desc(-1) {}

	operator int() { return _desc; }

	bool operator==(const file_desc &other) const { return _desc == other._desc; }
	bool operator!=(const file_desc &other) const { return _desc != other._desc; }
	bool operator==(std::nullptr_t) const { return _desc < 0; }
	bool operator!=(std::nullptr_t) const { return _desc >= 0; }

	int _desc;
};

struct fd_deleter
{
	using pointer = file_desc;
	void operator()(pointer p) { close(p); }
};

using fd_ptr = std::unique_ptr<int, fd_deleter>;

struct dl_deleter
{
	using pointer = void*;
	void operator()(pointer p) noexcept { dlclose(p); }
};
using dl_ptr = std::unique_ptr<void, dl_deleter>;

struct stdio_deleter
{
	using pointer = FILE*;
	void operator()(pointer p) { fclose(p); }
};

using stdio_ptr = std::unique_ptr<FILE, stdio_deleter>;
using file_ptr = stdio_ptr;

template <typename D>
auto make_protector(D& deleter)
{
	using ptr_type = std::unique_ptr<D, void(*)(D*)>;
	return ptr_type(&deleter, [](D* d) { (*d)(); });
}

/* args.cpp */

enum class exec_mode_t
{
	/* Legacy mode, accepts arguments, runs a planfile. */
	nimrun,
	/* New mode, no arguments, processes #NIM file. */
	nimexec
};

struct nimrun_args
{
	nimrun_args() noexcept;

	uint32_t	version;
	uint32_t	debug;
	const char	*planfile;
	const char	*tmpdir;
	const char	*outdir;
	uint16_t	qpid_management_port;
	const char	*qpid_home;
	const char	*java_home;
	const char	*nimrod_home;
};

int parse_arguments(int argc, char **argv, FILE *out, FILE *err, exec_mode_t mode, nimrun_args *args);

using node_map_type = std::unordered_map<std::string, size_t>;
struct batch_info_t
{
	const char *job_id;
	const char *outdir;
	size_t ompthreads;
	node_map_type nodes;
};

using batch_info_proc_t = batch_info_t(*)();

/* rcc.cpp */
batch_info_t get_batch_info_rcc();

/* wiener.cpp */
batch_info_t get_batch_info_wiener(const nimrun_args& args);

/* bsc.cpp */
batch_info_t get_batch_info_bsc();

/* ip.cpp */
int get_ip_addrs(std::vector<std::string>& addrs);
std::vector<uint16_t> get_listening_ports(pid_t pid);

/* ssl.cpp */
#include <openssl/ossl_typ.h>

struct deleter_x509 { void operator()(X509 *ptr) const noexcept; };
using x509_ptr = std::unique_ptr<X509, deleter_x509>;

struct deleter_evp_pkey { void operator()(EVP_PKEY *ptr) const noexcept; };
using evp_pkey_ptr = std::unique_ptr<EVP_PKEY, deleter_evp_pkey>;

struct deleter_rsa { void operator()(RSA *ptr) const noexcept; };
using rsa_ptr = std::unique_ptr<RSA, deleter_rsa>;

struct deleter_bn { void operator()(BIGNUM *bn) const noexcept; };
using bn_ptr = std::unique_ptr<BIGNUM, deleter_bn>;

void init_openssl();
void deinit_openssl();
void dump_openssl_errors(FILE *fp) noexcept;

evp_pkey_ptr create_pkey(size_t bits) noexcept;
x509_ptr create_cert(EVP_PKEY *pkey, long serial, size_t days, const std::string_view& cn, const std::vector<std::string_view>& altnames) noexcept;

int write_pem_key(EVP_PKEY *pkey, FILE *fp) noexcept;
int write_pem_cert(X509 *cert, FILE *fp) noexcept;
int write_pkcs12(EVP_PKEY *pkey, X509 *cert, const char *name, const char *pass, FILE *fp) noexcept;

/* shell.cpp */
void process_shellfile(const fs::path& file, const fs::path& planpath, const fs::path& scriptpath, int argc, char **argv);

/* qpid.cpp */
std::string generate_qpid_json(const fs::path& qpid_work, const char *user, const char *pass, const fs::path& cert_path, const char *cert_pass, uint16_t amqpPort, uint16_t managementPort);
pid_t launch_qpid(const fs::path& java, const fs::path& qpid_home, const fs::path& qpid_work, const fs::path& icp);

/* nimrod.cpp */
std::string build_nimrod_ini(const fs::path& dbpath);
std::string build_nimrod_setupini(const fs::path& nimrod_home, const fs::path& nimrod_work, const char *user, const char *pass, const char *hostname, uint16_t port, const fs::path& cert_path);

class nimcli
{
public:
	nimcli(const fs::path& java, const fs::path& openssh, const fs::path& tmpdir, const fs::path& nimrod_home, const std::string& platform, const fs::path& ini, const fs::path& fsroot, bool debug);

	pid_t setup_init(const fs::path& setupini);
	pid_t add_local_resource(const char *name, uint32_t parallelism);
	pid_t add_remote_resource(const char *name, const char *uri, uint32_t limit);
	pid_t add_experiment(const char *name, const char *planfile);
	pid_t assign_resource(const char *resource, const char *exp);
	pid_t master(const char *exp, uint32_t tick_rate);
private:
	pid_t fork_and_reset() noexcept;
	pid_t fork_and_reset(int fdin) noexcept;

	const fs::path& m_java;
	const fs::path& m_openssh;
	const fs::path& m_tmpdir;
	const fs::path& m_nimrod_home;
	const std::string m_platform;
	const fs::path& m_ini;
	std::string m_rooturi;
	fs::path m_classpath;
	std::string m_tmparg;
	std::vector<const char*> m_args;
	size_t m_basecount;
	fd_ptr m_devnull;
};

/* utils.cpp */
void write_file(const fs::path& path, const char *s);
void write_file(const fs::path& path, const std::string& s);
std::unique_ptr<char[]> read_file(const fs::path& path, size_t& size);

std::string generate_random_password(size_t length);
std::system_error make_posix_exception(int err);
pid_t spawn_process(const char *path, char * const *argv, int fdin) noexcept;

#endif /* _NIMRUN_HPP */
