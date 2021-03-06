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
#include <memory>
#include <vector>
#include <string>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/pkcs12.h>
#include "nimrun.hpp"

struct deleter_pkcs12 { void operator()(PKCS12 *p) const noexcept { PKCS12_free(p); } };
using pkcs12_ptr = std::unique_ptr<PKCS12, deleter_pkcs12>;

struct deleter_general_names { void operator()(GENERAL_NAMES* n) const noexcept { sk_GENERAL_NAME_free(n); } };
using general_names_ptr = std::unique_ptr<GENERAL_NAMES, deleter_general_names>;

struct deleter_general_name { void operator()(GENERAL_NAME* n) const noexcept { GENERAL_NAME_free(n); } };
using general_name_ptr = std::unique_ptr<GENERAL_NAME, deleter_general_name>;

struct deleter_asn1_ia5string { void operator()(ASN1_IA5STRING* s) const noexcept { ASN1_IA5STRING_free(s); } };
using asn1_ia5string_ptr = std::unique_ptr<ASN1_IA5STRING, deleter_asn1_ia5string>;

void init_openssl()
{
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();
	RAND_load_file("/dev/urandom", 32);
}

void deinit_openssl()
{
	ERR_free_strings();
	EVP_cleanup();

	CRYPTO_cleanup_all_ex_data();
}

void deleter_x509::operator()(X509 *ptr) const noexcept
{
	X509_free(ptr);
}

void deleter_evp_pkey::operator()(EVP_PKEY *ptr) const noexcept
{
	EVP_PKEY_free(ptr);
}

void deleter_rsa::operator()(RSA *ptr) const noexcept
{
	RSA_free(ptr);
}

void deleter_bn::operator()(BIGNUM *ptr) const noexcept
{
	BN_free(ptr);
}

void dump_openssl_errors(FILE *fp) noexcept
{
	if(fp)
		ERR_print_errors_fp(fp);
	else
		ERR_clear_error();
}

evp_pkey_ptr create_pkey(size_t bits) noexcept
{
	ERR_clear_error();

	evp_pkey_ptr pkey(EVP_PKEY_new());
	if(!pkey)
		return nullptr;

	bn_ptr bn(BN_new());
	if(!bn)
		return nullptr;

	if(BN_set_word(bn.get(), RSA_F4) != 1)
		return nullptr;

	rsa_ptr rsa(RSA_new());
	if(!rsa)
		return nullptr;

	if(RSA_generate_key_ex(rsa.get(), bits, bn.get(), nullptr) != 1)
		return nullptr;

	if(EVP_PKEY_assign_RSA(pkey.get(), rsa.get()) != 1)
		return nullptr;
	
	(void)rsa.release(); /* NB: Doesn't leak. */

	return pkey;
}

x509_ptr create_cert(EVP_PKEY *pkey, long serial, size_t days, const std::string_view& cn, const std::vector<std::string_view>& altnames) noexcept
{
	ERR_clear_error();

	if(!pkey)
		return nullptr;
	
	x509_ptr cert(X509_new());
	if(!cert)
		return nullptr;

	if(X509_set_version(cert.get(), 2) != 1)
		return nullptr;

	if(ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), serial) != 1)
		return nullptr;

	if(X509_gmtime_adj(X509_get_notBefore(cert.get()), 0) == nullptr)
		return nullptr;

	if(X509_gmtime_adj(X509_get_notAfter(cert.get()), static_cast<long>(60*60*24*days)) == nullptr)
		return nullptr;

	if(X509_set_pubkey(cert.get(), pkey) != 1)
		return nullptr;

	X509_NAME *name = X509_get_subject_name(cert.get());
	{
		unsigned char *_name = reinterpret_cast<unsigned char *>(const_cast<char*>(cn.data()));
		if(X509_NAME_add_entry_by_NID(name, NID_commonName, MBSTRING_ASC, _name, static_cast<int>(cn.size()), -1, 0) != 1)
			return nullptr;
	}

	{
		general_names_ptr gens(sk_GENERAL_NAME_new_null());
		if(!gens)
			return nullptr;

		for(const std::string_view& s : altnames)
		{
			unsigned char *_name = reinterpret_cast<unsigned char *>(const_cast<char*>(s.data()));

			general_name_ptr gen(GENERAL_NAME_new());
			if(!gen)
				return nullptr;

			asn1_ia5string_ptr ia5(ASN1_IA5STRING_new());
			if(!ia5)
				return nullptr;

			if(!ASN1_STRING_set(ia5.get(), _name, static_cast<int>(s.size())))
				return nullptr;

			GENERAL_NAME_set0_value(gen.get(), GEN_DNS, ia5.get());

			if(!sk_GENERAL_NAME_push(gens.get(), gen.get()))
				return nullptr;

			(void)gen.release();
			(void)ia5.release();
		}

		if(!X509_add1_ext_i2d(cert.get(), NID_subject_alt_name, gens.get(), 0, 0))
			return nullptr;
	}

	/* Self-signed */
	if(X509_set_issuer_name(cert.get(), name) != 1)
		return nullptr;

	if(X509_sign(cert.get(), pkey, EVP_sha256()) == 0)
		return nullptr;

	return cert;
}

int write_pem_key(EVP_PKEY *pkey, FILE *fp) noexcept
{
	ERR_clear_error();
	if(PEM_write_PrivateKey(fp, pkey, nullptr, nullptr, 0, nullptr, nullptr) != 1)
		return -1;
	return 0;
}

int write_pem_cert(X509 *cert, FILE *fp) noexcept
{
	ERR_clear_error();
	if(PEM_write_X509(fp, cert) != 1)
		return -1;
	return 0;
}

int write_pkcs12(EVP_PKEY *pkey, X509 *cert, const char *name, const char *pass, FILE *fp) noexcept
{
	pkcs12_ptr p12(PKCS12_create(const_cast<char*>(pass), const_cast<char*>(name), pkey, cert, nullptr, 0, 0, 0, 0, 0));
	if(!p12)
		return -1;

	if(i2d_PKCS12_fp(fp, p12.get()) != 1)
		return -1;

	return 0;
}
