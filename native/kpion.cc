#include <iostream>
#include <node.h>
#include <node_buffer.h>
#include <v8.h>

#include <cryptopp/modes.h>
#include <cryptopp/aes.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>

#define AES_KEY_LENGTH 32
#define ROUND_UP_TO_MULTIPLE(numberToRound, multiple) ((numberToRound + multiple - 1) & ~(multiple - 1))

v8::Handle<v8::Value> transform_key(const v8::Arguments& args) {
    v8::HandleScope scope;

    // Check if the correct number of arguments was given
    if(args.Length() != 3) {
        v8::ThrowException(v8::Exception::TypeError(v8::String::New("Wrong number of arguments given.")));
        return scope.Close(v8::Undefined());
    }

    // Check if all the given arguments have their expected type
    if(!node::Buffer::HasInstance(args[0]) || !node::Buffer::HasInstance(args[1]) || !args[2]->IsNumber()) {
        v8::ThrowException(v8::Exception::TypeError(v8::String::New("Wrong arguments given.")));
        return scope.Close(v8::Undefined());
    }

    // Store given arguments in some variables
    int key_transformation_rounds = args[2]->NumberValue();
    int untransformed_data_len = node::Buffer::Length(args[0]->ToObject());
    char *untransformed_data = node::Buffer::Data(args[0]->ToObject());
    char *unpadded_aes_key = node::Buffer::Data(args[1]->ToObject());

    // Pad AES key and create CryptoPP cipher
    char padded_aes_key[AES_KEY_LENGTH];
    memset(padded_aes_key, 0, AES_KEY_LENGTH);
    memcpy(padded_aes_key, unpadded_aes_key, AES_KEY_LENGTH);
    CryptoPP::AES::Encryption cpp_aes_encryption((const byte *) padded_aes_key, AES_KEY_LENGTH);
    CryptoPP::ECB_Mode_ExternalCipher::Encryption cpp_ebc_aes_encryptor(cpp_aes_encryption);

    // Create buffer for data transformation
    int transformed_data_len = ROUND_UP_TO_MULTIPLE(untransformed_data_len, CryptoPP::AES::BLOCKSIZE);
    char *transformed_data = (char *) malloc(transformed_data_len);
    memset(transformed_data, 0, transformed_data_len);
    memcpy(transformed_data, untransformed_data, untransformed_data_len);

    // Transform the data as many times as specified
    // Because ECB is a block cipher, the data must be processed in chunks
    // of the appropriate block size.
    for(int round = 0; round < key_transformation_rounds; round++) {
        for(int block_offset = 0; block_offset < transformed_data_len; block_offset += CryptoPP::AES::BLOCKSIZE) {
            cpp_ebc_aes_encryptor.ProcessData(
                (byte *) (transformed_data + block_offset),
                (const byte *) (transformed_data + block_offset),
                CryptoPP::AES::BLOCKSIZE
            );
        }
    }

    // Create SHA256 hash of transformed data
    CryptoPP::SHA256 sha256_hasher;
    byte sha256_digest[CryptoPP::SHA256::DIGESTSIZE];
    sha256_hasher.CalculateDigest(sha256_digest, (const byte *) transformed_data, untransformed_data_len);

    // Convert SHA256 digest to hex encoding
    CryptoPP::HexEncoder hex_encoder(NULL, false);
    std::string hex_encoded_sha256_hash;
    hex_encoder.Attach(new CryptoPP::StringSink(hex_encoded_sha256_hash));
    hex_encoder.Put(sha256_digest, sizeof(sha256_digest));
    hex_encoder.MessageEnd();

    return scope.Close(v8::String::New(hex_encoded_sha256_hash.c_str(), hex_encoded_sha256_hash.length()));
}

void init(v8::Handle<v8::Object> exports) {
	exports->Set(
		v8::String::NewSymbol("transformKey"),
		v8::FunctionTemplate::New(transform_key)->GetFunction()
	);
}

void Initialize(v8::Handle<v8::Object> exports);
NODE_MODULE(kpion, init)