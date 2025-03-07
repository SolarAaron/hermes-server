#include <chrono>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <random>
#include <ranges>
#include <vector>

#include "cryptopp/rsa.h"
#include "cryptopp/osrng.h"
#include "grpcpp/grpcpp.h"

#include "Args.hpp"
#include "chat_service.hpp"
#include "chat_service.hpp"
#include "slr.crypto.hpp"
#include "src/protobuf/messages.pb.h"

#define BLOCK_SIZE 128
#define HASH_DEF 4

#define ADDR_ENV "ADDR_ENV"
#define PORT_ENV "PORT_ENV"
#define CONN_ENV "CONN_ENV"
#define DBNM_ENV "DBNM_ENV"
#define SSL_KP_ENV "SSL_KP_ENV"

bool sanity_check() {
    auto prevBlock = new char[BLOCK_SIZE], block = new char[BLOCK_SIZE];
    auto key_rng = std::independent_bits_engine<std::random_device, CHAR_BIT, uint8_t>();
    auto crypt_rng = CryptoPP::AutoSeededRandomPool();
    auto header = std::unique_ptr<slr::hermes::chat_header>(new slr::hermes::chat_header);
    auto message = std::unique_ptr<slr::hermes::chat_content_map>(new slr::hermes::chat_content_map);
    auto message_key = std::vector<uint8_t>(BLOCK_SIZE);
    CryptoPP::RSA::PrivateKey private_key;

    auto start_time = std::chrono::high_resolution_clock::now();
    std::cout << "Sanity check starting" << std::endl;
    std::generate(message_key.begin(), message_key.end(), std::ref(key_rng));
    std::generate_n(block, BLOCK_SIZE, std::ref(key_rng));

    // message building done for demo purposes; this procedure is done client side
    std::cout << "Generated message key at " << std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start_time).count() << std::endl;

    message->mutable_content()->try_emplace("text", slr::hermes::chat_content());
    message->mutable_content()->at("text").mutable_text()->set_text("hello world");

    auto message_bytes = message->SerializeAsString();
    header->set_message_length(message_bytes.size());

    std::cout << "Generated message bytes at " << std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start_time).count() << std::endl;

    for(size_t byte = 0; byte < message_bytes.size(); byte++) {
        if(byte % BLOCK_SIZE == 0) {
            std::cout << "Encrypting message block " << header->message_bytes_size() << " at " << std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start_time).count() << std::endl;
            auto crypted = slr::crypto::shuffleEncrypt<BLOCK_SIZE, HASH_DEF>(message_key.size(), (char*)message_key.data(), BLOCK_SIZE, prevBlock, BLOCK_SIZE,
                                                                       block, 1);
            header->add_message_bytes(crypted.data(), crypted.size());
            memcpy(prevBlock, crypted.data(), crypted.size());
        }

        block[byte % BLOCK_SIZE] = message_bytes[byte];
    }

    std::cout << "Encrypting final message block " << header->message_bytes_size() << " at " << std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start_time).count() << std::endl;
    auto crypted = slr::crypto::shuffleEncrypt<BLOCK_SIZE, HASH_DEF>(message_key.size(), (char*)message_key.data(), BLOCK_SIZE, prevBlock, BLOCK_SIZE,
                                                               block, 1);
    header->add_message_bytes(crypted.data(), crypted.size());

    std::cout << "Generating rsa keys at " << std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start_time).count() << std::endl;
    private_key.GenerateRandomWithKeySize(crypt_rng, 4096);
    auto public_key = CryptoPP::RSA::PublicKey(private_key); // for demo purposes; key used for sending is destination public

    std::cout << "Encrypting message key with public key at " << std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start_time).count() << std::endl;
    auto crypted_key = public_key.ApplyFunction(CryptoPP::Integer(message_key.data(), message_key.size()));
    std::string crypted_bytes;

    crypted_bytes.resize(crypted_key.MinEncodedSize());
    crypted_key.Encode((CryptoPP::byte*) crypted_bytes.data(), crypted_bytes.size());

    header->set_message_key(crypted_bytes);

    std::cout << "Signing message key with private key at " << std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start_time).count() << std::endl;
    auto signer = CryptoPP::RSASSA_PKCS1v15_SHA256_Signer(private_key);
    auto sec_byte_block = CryptoPP::SecByteBlock(signer.SignatureLength());

    signer.SignMessage(crypt_rng, message_key.data(), message_key.size(), sec_byte_block);
    header->set_key_signature(sec_byte_block.data(), sec_byte_block.size());

    auto header_bytes = header->SerializeAsString();

    std::cout << "Generated header bytes at " << std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start_time).count() << std::endl;

    auto recovered_header = std::unique_ptr<slr::hermes::chat_header>(new slr::hermes::chat_header);

    if(recovered_header->ParseFromString(header_bytes)) {
        std::cout << "Recovered header from wire format at " << std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start_time).count() << std::endl;
    } else {
        std::cout << "Failed to parse recovered header, terminating" << std::endl;
        return false;
    }

    std::string recovered_key_bytes;
    auto recovered_key = private_key.CalculateInverse(crypt_rng, CryptoPP::Integer((CryptoPP::byte*)recovered_header->message_key().data(), recovered_header->message_key().size()));
    recovered_key_bytes.resize(recovered_key.MinEncodedSize());
    recovered_key.Encode((CryptoPP::byte*)recovered_key_bytes.data(), recovered_key_bytes.size());

    std::cout << "Recovered message key at " << std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start_time).count() << std::endl;

    auto verifier = CryptoPP::RSASSA_PKCS1v15_SHA256_Verifier(public_key);

    if(verifier.VerifyMessage((CryptoPP::byte*)recovered_key_bytes.data(), recovered_key_bytes.size(), (CryptoPP::byte*)recovered_header->key_signature().data(), recovered_header->key_signature().size()))
        std::cout << "Verified message key at " << std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start_time).count() << std::endl;
    else {
        std::cout << "Recovered message key verification failed, terminating" << std::endl;
        return false;
    }

    memset(prevBlock, 0, BLOCK_SIZE);
    memset(block, 0, BLOCK_SIZE);

    auto decrypted =
                slr::crypto::shuffleDecrypt<BLOCK_SIZE, HASH_DEF>(recovered_key_bytes.size(), recovered_key_bytes.data(), BLOCK_SIZE, prevBlock, BLOCK_SIZE, recovered_header->message_bytes(0).data(),
                                                               1);
    memcpy(prevBlock, recovered_header->message_bytes(0).data(), BLOCK_SIZE);
    std::stringstream recovered_message_bytes;

    std::cout << "Decrypted message block 0 at " << std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start_time).count() << std::endl;

    for(size_t msg_block = 1; msg_block < recovered_header->message_bytes_size(); msg_block++) {
        decrypted =
                slr::crypto::shuffleDecrypt<BLOCK_SIZE, HASH_DEF>(recovered_key_bytes.size(), recovered_key_bytes.data(), BLOCK_SIZE, prevBlock, BLOCK_SIZE, recovered_header->message_bytes(msg_block).data(),
                                                               1);
        std::cout << "Decrypted message block " << msg_block << " at " << std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start_time).count() << std::endl;

        memcpy(prevBlock, recovered_header->message_bytes(msg_block).data(), BLOCK_SIZE);
        for(auto recovered_byte: decrypted) {
            if(recovered_message_bytes.str().size() < recovered_header->message_length()) {
                recovered_message_bytes << recovered_byte;
            } else break;
        }
    }

    auto recovered_message = std::unique_ptr<slr::hermes::chat_content_map>(new slr::hermes::chat_content_map);
    if(recovered_message->ParseFromString(recovered_message_bytes.str()))
        std::cout << "Recovered message object from wire format at " << std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start_time).count() << std::endl;
    else {
        std::cout << "Failed to parse recovered message, terminating" << std::endl;
        return false;
    }

    for(const auto &recovered_message_content: recovered_message->content()) {
        std::cout << "Decrypted message content " << '"' << recovered_message_content.first << '"' << " at " << std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start_time).count() << std::endl;
        if(recovered_message_content.second.has_text())
            std::cout << "It contains text: " << recovered_message_content.second.text().text() << std::endl;
        if(recovered_message_content.second.has_attachment())
            std::cout << "It contains attachment: " << recovered_message_content.second.attachment().file_name() << " of length " << recovered_message_content.second.attachment().file_size() << std::endl;
    }

    std::cout << "Sanity check complete at " << std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start_time).count() << "!" << std::endl;
    return true;
}

std::map<std::string, std::optional<std::string>>
load_env() {
    auto result = std::map<std::string, std::optional<std::string>>();

    const char * addr = getenv(ADDR_ENV);
    const char * port = getenv(PORT_ENV);
    const char * conn = getenv(CONN_ENV);
    const char * dbnm = getenv(DBNM_ENV);

    result[ADDR_ENV] = addr ? std::optional(std::string(addr)) : std::optional<std::string>(std::nullopt);
    result[PORT_ENV] = port ? std::optional(std::string(port)) : std::optional<std::string>(std::nullopt);
    result[CONN_ENV] = conn ? std::optional(std::string(conn)) : std::optional<std::string>(std::nullopt);
    result[DBNM_ENV] = dbnm ? std::optional(std::string(dbnm)) : std::optional<std::string>(std::nullopt);

    return result;
}

int
main(int argc, char** argv) {
    auto args = slr::hermes::Args().parse(argc, argv);
    if(args.check_sanity && !sanity_check()) return 1;

    auto builder = std::make_unique<grpc::ServerBuilder>();
    auto env_map = load_env();

    if(!(env_map[CONN_ENV].has_value() && env_map[DBNM_ENV].has_value())) {
        std::cerr << "No database server specified in environment: " << CONN_ENV << ": " << env_map[CONN_ENV].value_or("EMPTY") << "; " << DBNM_ENV << ": " << env_map[DBNM_ENV].value_or("EMPTY") << std::endl;
        return 1;
    }

    auto service = std::make_unique<slr::hermes::chat_service>(env_map[CONN_ENV].value(), env_map[DBNM_ENV].value());
    auto ssl_opts = grpc::SslServerCredentialsOptions();

    auto key_pairs = env_map[SSL_KP_ENV].value_or("")
                     | std::ranges::views::split(';')
                     | std::ranges::views::transform(
                                                     [](auto&& str) {
                                                         return std::string_view(&*str.begin(), std::ranges::distance(str));
                                                     }
                                                    );

    for(auto&& key_pair: key_pairs) {
        auto split_kc = key_pair
                        | std::ranges::views::split(',')
                        | std::ranges::views::transform(
                                                        [](auto&& str) {
                                                            return std::string_view(&*str.begin(), std::ranges::distance(str));
                                                        }
                                                       );

        std::vector<std::string> holder;
        for(auto&& item: split_kc) {
            std::string out;
            out = item;
            holder.push_back(out);
        }

        if(holder.size() != 2) {
            std::cerr << "Invalid key/cer pair configured: " << key_pair << std::endl;
            return 1;
        }

        ssl_opts.pem_key_cert_pairs.emplace_back(grpc::SslServerCredentialsOptions::PemKeyCertPair(holder[0], holder[1]));
    }

    builder->AddListeningPort(
                              env_map[ADDR_ENV].value_or("localhost") + ":" + env_map[PORT_ENV].value_or("40013"),
                              ssl_opts.pem_key_cert_pairs.empty() ? grpc::InsecureServerCredentials() : SslServerCredentials(ssl_opts)
                             );
    builder->RegisterService(service.get());

    auto server = builder->BuildAndStart();
    std::cout << "Server listening on " << env_map[ADDR_ENV].value_or("localhost") << ":" << env_map[PORT_ENV].value_or("40013") << std::endl;

    server->Wait();

    return 0;
}
