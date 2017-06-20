#ifndef OpenSSLPack_H_
#define OpenSSLPack_H_

#include <string.h>
#include <assert.h>

#include <iostream>
#include <string>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>


class OpenSSLPack
{
	private:
	const int key_bits = 1024;
	const unsigned long private_exp = RSA_F4;
	const int padding_method = RSA_PKCS1_PADDING;

	public:
	void CreateKey();

	std::string Public_Encrypt(const std::string,const std::string);
	std::string Private_Encrypt(const std::string,const std::string);

	std::string Public_Decrypt(const std::string,const std::string);
	std::string Private_Decrypt(const std::string,const std::string);
};


void OpenSSLPack::CreateKey()
{
	RSA * rsa = RSA_generate_key(this->key_bits,private_exp,nullptr,nullptr);

	BIO *bp;
	bp = BIO_new_file("public.pem","w");
	PEM_write_bio_RSAPublicKey(bp,rsa);
	BIO_free_all(bp);

	bp = BIO_new_file("private.pem","w");
	PEM_write_bio_RSAPrivateKey(bp, rsa, nullptr, nullptr, 0 ,nullptr,nullptr);


	BIO_free_all(bp);

	RSA_free(rsa);
}

std::string OpenSSLPack::Public_Encrypt(const std::string content,const std::string pub_key_path)
{
	OpenSSL_add_all_algorithms();

	BIO * bp = BIO_new( BIO_s_file() );
	BIO_read_filename(bp,pub_key_path.c_str());

	RSA* rsak = PEM_read_bio_RSAPublicKey(bp,nullptr,nullptr,nullptr);
	if( nullptr == rsak){
		return "";
	}

	assert( nullptr != rsak);

	int nlen = RSA_size(rsak);

	unsigned char *pEncode = new unsigned char[nlen + 1];

	int ret = RSA_public_encrypt(content.length(),(unsigned char *)(content.c_str()),
			pEncode,rsak,this->padding_method);

	
	std::string Encode_str;
	if(ret > 0){
		Encode_str = std::string((char *)pEncode,ret);
	}
	delete [] pEncode;

	CRYPTO_cleanup_all_ex_data();
	BIO_free_all( bp );
	RSA_free(rsak);

	return Encode_str;
}
std::string OpenSSLPack::Private_Encrypt(const std::string content,const std::string pri_key_path)
{
	OpenSSL_add_all_algorithms();

	BIO * bp = BIO_new( BIO_s_file() );
	BIO_read_filename(bp,pri_key_path.c_str());

	assert(nullptr != bp);

	RSA* rsak = PEM_read_bio_RSAPrivateKey(bp,nullptr,nullptr,nullptr);

	if( nullptr == rsak){
		
		return "";
	}

	assert( nullptr != rsak);

	int nlen = RSA_size(rsak);

	unsigned char *pEncode = new unsigned char[nlen + 1];

	int ret = RSA_private_encrypt(content.length(),(unsigned char *)(content.c_str()),
			pEncode,rsak,this->padding_method);

	
	std::string Encode_str;
	if(ret > 0){
		Encode_str = std::string((char *)pEncode,ret);
	}
	delete [] pEncode;

	CRYPTO_cleanup_all_ex_data();
	BIO_free_all( bp );
	RSA_free(rsak);

	return Encode_str;
}

std::string OpenSSLPack::Public_Decrypt(const std::string content,const std::string pub_key_path)
{
	OpenSSL_add_all_algorithms();

	BIO *bp = BIO_new( BIO_s_file() );

	BIO_read_filename( bp, pub_key_path.c_str() );

	RSA * rsak = PEM_read_bio_RSAPublicKey(bp,nullptr,nullptr,nullptr);

	if( nullptr == rsak){
		std::cerr << __FUNCTION__ << " " << __LINE__ << "  " << pub_key_path << std::endl;
		return "";
	}

	assert(nullptr != rsak);

	int nlen = RSA_size(rsak);

	unsigned char *pEncode = new unsigned char[nlen + 1];

	int ret = RSA_public_decrypt(content.length(),(unsigned char *)content.c_str(),
			pEncode,rsak,this->padding_method);

	std::string Encode_str;

	if(ret > 0){
		Encode_str = std::string( (char *)pEncode, ret );
	}

	delete[] pEncode;

	CRYPTO_cleanup_all_ex_data();
	BIO_free_all( bp );
	RSA_free(rsak);

	return Encode_str;
}
std::string OpenSSLPack::Private_Decrypt(const std::string content,const std::string pri_key_path)
{
	OpenSSL_add_all_algorithms();

	BIO *bp = BIO_new( BIO_s_file() );

	BIO_read_filename( bp, pri_key_path.c_str() );

	assert(nullptr != bp);


	RSA * rsak = PEM_read_bio_RSAPrivateKey(bp,nullptr,nullptr,nullptr);

	if( nullptr == rsak){

		std::cerr << __FUNCTION__ << " " << __LINE__ << "  " << pri_key_path << std::endl;
		return "";
	}

	assert(nullptr != rsak);

	int nlen = RSA_size(rsak);

	unsigned char *pEncode = new unsigned char[nlen + 1];

	int ret = RSA_private_decrypt(content.length(),(unsigned char *)content.c_str(),
			pEncode,rsak,this->padding_method);


	std::string Encode_str;

	if(ret > 0){
		Encode_str = std::string( (char *)pEncode, ret );
	}

	delete[] pEncode;

	CRYPTO_cleanup_all_ex_data();
	BIO_free_all( bp );
	RSA_free(rsak);

	return Encode_str;
}

#endif
