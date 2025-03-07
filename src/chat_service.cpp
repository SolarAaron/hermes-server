//
// Created by atorres on 3/7/25.
//

#include "chat_service.hpp"

#include <bits/fs_fwd.h>
#include <cryptopp/rsa.h>

#include "bsoncxx/oid.hpp"
#include "bsoncxx/builder/stream/array.hpp"
#include "bsoncxx/builder/stream/document.hpp"

#define USER_COLLECTION_NAME "user"
#define HEADER_COLLECTION_NAME "header"
#define GRIDFS_COLLECTION_NAME "fs.files"

namespace slr::hermes {
    chat_service::chat_service(const std::string& uri_str, const std::string& db_name): connection(mongocxx::uri(uri_str)),
                                                                                        database(connection.database(db_name)) {}

    bsoncxx::types::bson_value::view
    chat_service::store_file(const chat_attachment& file) {
        auto bucket = this->database.gridfs_bucket();
        auto upstream = bucket.open_upload_stream(file.file_name());
        size_t size = 0;
        for(size_t chunk = 0; chunk < file.file_size(); chunk++) {
            upstream.write((uint8_t*) file.blocks(chunk).data(), std::min(file.blocks(chunk).size(), file.file_size() - size));
            size += file.blocks(chunk).size();
        }
        return upstream.close().id();
    }

    std::optional<chat_attachment>
    chat_service::load_file(const bsoncxx::types::bson_value::view& file_id) {
        auto file = chat_attachment();

        std::stringstream file_bytes;
        auto bucket = database.gridfs_bucket();
        auto fs_files = database.collection(GRIDFS_COLLECTION_NAME);

        auto file_query = bsoncxx::builder::stream::document();
        file_query << "id" << file_id.get_oid();

        auto file_document = fs_files.find_one(file_query << bsoncxx::builder::stream::finalize);

        if(!file_document.has_value()) return std::optional<chat_attachment>(std::nullopt);

        bucket.download_to_stream(file_id, &file_bytes);
        file.set_file_name(file_document.value()["filename"].get_string());
        file.set_file_size(file_document.value()["length"].get_int64());
        file.add_blocks(file_bytes.str());

        return std::make_optional(file);
    }

    bsoncxx::document::value
    chat_service::transform_user(const chat_user* request) {
        auto user = bsoncxx::builder::stream::document();

        if(!(request->has_phone() || request->has_mail())) {
            user << "unidentified" << true;
        }

        if(request->has_phone()) {
            user << "phone" << request->phone();
        }

        if(request->has_mail()) {
            user << "mail" << request->mail();
        }

        if(request->has_nickname()) {
            user << "nickname" << request->nickname();
        }

        if(request->has_status()) {
            user << "status" << request->status();
        }

        if(request->has_pic_idx()) {
            user << "picture_index" << (int64_t) request->pic_idx();
        }

        auto keys = bsoncxx::builder::stream::array();

        for(int key = 0; key < request->public_keys_size(); key++) {
            bsoncxx::types::b_binary key_bson{
                    bsoncxx::binary_sub_type::k_binary,
                    (uint32_t) request->public_keys(key).size(),
                    (uint8_t*) request->public_keys(key).data()
            };
            keys << key_bson;
        }
        user << "public_keys" << (keys << bsoncxx::builder::stream::finalize);

        auto pics = bsoncxx::builder::stream::array();

        for(size_t pic_idx = 0; pic_idx < request->picture_size(); pic_idx++) {
            auto pic_id = store_file(request->picture(pic_idx));
            pics << pic_id.get_oid();
        }
        user << "pictures" << (pics << bsoncxx::builder::stream::finalize);

        return user << bsoncxx::builder::stream::finalize;
    }

    grpc::Status
    chat_service::register_user(grpc::ServerContext* context, const chat_user* request, operation_result* response) {
        auto users = database.collection(USER_COLLECTION_NAME);
        auto user_document = transform_user(request);

        if(user_document["unidentified"]) {
            return grpc::Status(grpc::INVALID_ARGUMENT, "user_reg_no_id");
        }

        auto result = users.insert_one(user_document.view());

        response->set_success(true);
        response->set_result(result.value().inserted_id().get_oid().value.bytes());

        return ::grpc::Status::OK;
    }

    std::map<std::string, bsoncxx::types::bson_value::view>
    chat_service::store_bytes(const chat_header* request) {
        auto bucket = this->database.gridfs_bucket();
        std::stringstream ss;

        ss << "preview_" << bsoncxx::oid(request->sender_id().data(), request->sender_id().size()).to_string() << '_' << bsoncxx::oid(
             request->recipient_id().data(),
             request->recipient_id().size()
            ).to_string() << '_' << request->timestamp();
        auto preview_upstream = bucket.open_upload_stream(ss.str());
        for(size_t block = 0; block < request->preview_bytes_size(); ++block) {
            preview_upstream.write((uint8_t*) request->preview_bytes(block).data(), request->preview_bytes(block).size());
        }

        ss.clear();
        ss << bsoncxx::oid(request->sender_id().data(), request->sender_id().size()).to_string() << '_' << bsoncxx::oid(
                                                                                                                        request->recipient_id().data(),
                                                                                                                        request->recipient_id().size()
                                                                                                                       ).to_string() << '_' << request->timestamp();
        auto message_upstream = bucket.open_upload_stream(ss.str());
        for(size_t block = 0; block < request->message_bytes_size(); ++block) {
            message_upstream.write((uint8_t*) request->message_bytes(block).data(), request->message_bytes(block).size());
        }

        return std::map<std::string, bsoncxx::types::bson_value::view>{{"message", message_upstream.close().id()}, {"preview", preview_upstream.close().id()}};
    }

    bsoncxx::document::value
    chat_service::transform_header(const std::unique_ptr<chat_header>& request) {
        auto header = bsoncxx::builder::stream::document();

        header << "sender" << bsoncxx::oid(request->sender_id().data(), request->sender_id().size());
        header << "recipient" << bsoncxx::oid(request->recipient_id().data(), request->recipient_id().size());
        header << "recipient_type" << request->recipient_type();
        header << "timestamp" << bsoncxx::types::b_date{std::chrono::milliseconds{request->timestamp()}};
        header << "status" << request->status();
        header << "key_index" << (int64_t) request->key_index();
        header << "block_size" << (int64_t) request->block_size();
        header << "strength" << request->strength();
        header << "message_key" << bsoncxx::types::b_binary{
                bsoncxx::binary_sub_type::k_binary,
                (uint32_t) request->message_key().size(),
                (uint8_t*) request->message_key().data()
        };
        header << "key_signature" << bsoncxx::types::b_binary{
                bsoncxx::binary_sub_type::k_binary,
                (uint32_t) request->key_signature().size(),
                (uint8_t*) request->key_signature().data()
        };
        header << "preview_length" << (int64_t) request->preview_length();
        header << "message_length" << (int64_t) request->message_length();

        auto content_ids = this->store_bytes(request.get());
        header << "preview_id" << content_ids["preview"];
        header << "message_id" << content_ids["message"];

        return header << bsoncxx::builder::stream::finalize;
    }

    chat_header
    chat_service::detransform_header(const bsoncxx::document::view& header_document) {
        auto result = chat_header();

        result.set_message_id(std::string(header_document["_id"].get_oid().value.bytes(), bsoncxx::oid::size()));
        result.set_sender_id(std::string(header_document["sender"].get_oid().value.bytes(), bsoncxx::oid::size()));
        result.set_recipient_id(std::string(header_document["recipient_id"].get_oid().value.bytes(), bsoncxx::oid::size()));
        result.set_recipient_type(recipient_type(header_document["recipient_type"].get_int64().value));
        result.set_timestamp(header_document["timestamp"].get_date().value.count());
        result.set_edit_timestamp(header_document["edit_timestamp"].get_date().value.count());
        result.set_status(delivered);
        result.set_key_index(header_document["key_index"].get_int64());
        result.set_block_size(header_document["block_size"].get_int64());
        result.set_strength(header_document["strength"].get_string());
        result.set_message_key(std::string((char*) header_document["message_key"].get_binary().bytes, header_document["message_key"].get_binary().size));
        result.set_key_signature(std::string((char*) header_document["key_signature"].get_binary().bytes, header_document["key_signature"].get_binary().size));
        result.set_preview_length(header_document["preview_length"].get_int64());
        result.set_message_length(header_document["message_length"].get_int64());

        return result;
    }

    chat_user
    chat_service::detransform_user(const bsoncxx::document::view& user_document) {
        auto result = chat_user();

        if(user_document["phone"]) result.set_phone(user_document["phone"].get_string());
        if(user_document["mail"]) result.set_mail(user_document["mail"].get_string());
        if(user_document["nickname"]) result.set_nickname(user_document["nickname"].get_string());
        if(user_document["status"]) result.set_status(user_document["status"].get_string());
        if(user_document["picture_index"]) result.set_pic_idx(user_document["picture_index"].get_int64());

        for(auto pic_id: user_document["pictures"].get_array().value) {
            if(auto picture = load_file(pic_id.get_value())) *result.add_picture() = picture.value();
        }

        for(auto pub_key: user_document["public_keys"].get_array().value) {
            result.add_public_keys(pub_key.get_binary().bytes, pub_key.get_binary().size);
        }

        return result;
    }

    grpc::Status
    chat_service::send_messages(grpc::ServerContext* context, grpc::ServerReaderWriter<operation_result, chat_header>* stream) {
        bool stop = false;

        do {
            auto message = std::make_unique<chat_header>();
            stop = !stream->Read(message.get());

            if(!stop) {
                auto headers = this->database.collection(HEADER_COLLECTION_NAME);

                auto header_document = transform_header(message);
                auto result = headers.insert_one(header_document.view());

                auto response = operation_result();
                response.set_success(true);
                response.set_result(result.value().inserted_id().get_oid().value.bytes());

                stream->Write(response);
            }
        } while(!stop);

        return ::grpc::Status::OK;
    }

    std::optional<bsoncxx::document::value>
    chat_service::authenticate_request(const authenticated_request& auth) {
        auto users = database.collection(USER_COLLECTION_NAME);
        auto user_query = bsoncxx::builder::stream::document();

        user_query << "_id" << bsoncxx::oid(auth.user_id().data(), auth.user_id().size());

        auto user_document_optional = users.find_one(user_query << bsoncxx::builder::stream::finalize);

        if(!user_document_optional.has_value()) {
            return std::optional<bsoncxx::document::value>(std::nullopt);
        }

        auto public_key = CryptoPP::RSA::PublicKey();
        auto byte_queue = CryptoPP::ByteQueue();
        auto pubkey_bytes = user_document_optional.value()["public_keys"].get_array().value[auth.key_index()].get_binary();

        byte_queue.PutMessageEnd(pubkey_bytes.bytes, pubkey_bytes.size);
        public_key.Load(byte_queue);

        auto verifier = CryptoPP::RSASSA_PKCS1v15_SHA256_Verifier(public_key);

        if(!verifier.VerifyMessage(
                                   (CryptoPP::byte*) auth.nonce().data(),
                                   auth.nonce().size(),
                                   (CryptoPP::byte*) auth.signature().data(),
                                   auth.signature().size()
                                  )) {
            grpc::Status(grpc::StatusCode::UNAUTHENTICATED, "request_not_verified");
            return std::optional<bsoncxx::document::value>(std::nullopt);
        }
        return user_document_optional;
    }

    grpc::Status
    chat_service::edit_message(grpc::ServerContext* context, const edit_message_request* request, operation_result* response) {
        auto headers = this->database.collection(HEADER_COLLECTION_NAME);
        if(!authenticate_request(request->user_auth())) return grpc::Status(grpc::StatusCode::UNAUTHENTICATED, "request_not_verified");

        auto header_query = bsoncxx::builder::stream::document();

        header_query << "_id" << bsoncxx::oid(request->user_auth().user_id().data(), request->user_auth().user_id().size());

        auto original_header_document = headers.find_one(header_query << bsoncxx::builder::stream::finalize);
        auto bucket = database.gridfs_bucket();

        auto new_content_ids = this->store_bytes(&request->new_header());

        auto set_document = bsoncxx::builder::stream::document();
        auto update_document = bsoncxx::builder::stream::document();

        update_document << "edit_timestamp" << bsoncxx::types::b_date{std::chrono::milliseconds{request->timestamp()}};
        update_document << "preview_id" << new_content_ids["preview"];
        update_document << "message_id" << new_content_ids["message"];
        set_document << "$set" << (update_document << bsoncxx::builder::stream::finalize);

        headers.update_one(header_query << bsoncxx::builder::stream::finalize, set_document << bsoncxx::builder::stream::finalize);

        bucket.delete_file(original_header_document.value()["message_id"].get_value());
        bucket.delete_file(original_header_document.value()["preview_id"].get_value());

        response->set_success(true);

        return grpc::Status::OK;
    }

    grpc::Status
    chat_service::get_user_data(grpc::ServerContext* context, const user_data_request* request, operation_result* response) {
        auto users = database.collection(USER_COLLECTION_NAME);
        auto user_query = bsoncxx::builder::stream::document();

        user_query << "_id" << bsoncxx::oid(request->target_user_id().data(), request->target_user_id().size());

        auto user_document_optional = users.find_one(user_query << bsoncxx::builder::stream::finalize);

        if(!user_document_optional.has_value()) {
            return grpc::Status(grpc::StatusCode::NOT_FOUND, "user_not_exist");
        }

        chat_user found_user = detransform_user(user_document_optional.value());

        response->set_success(true);
        response->set_result(found_user.SerializeAsString());

        return grpc::Status::OK;
    }

    grpc::Status
    chat_service::add_user_key(grpc::ServerContext* context, const add_key_request* request, operation_result* response) {
        auto users = database.collection(USER_COLLECTION_NAME);
        auto user_document_optional = authenticate_request(request->user_auth());

        if(!user_document_optional) return grpc::Status(grpc::StatusCode::UNAUTHENTICATED, "request_not_verified");

        auto user_query = bsoncxx::builder::stream::document();

        user_query << "_id" << bsoncxx::oid(request->user_auth().user_id().data(), request->user_auth().user_id().size());

        auto key_array = bsoncxx::builder::stream::array();
        auto update_document = bsoncxx::builder::stream::document();
        auto set_document = bsoncxx::builder::stream::document();

        for(auto key: user_document_optional.value()["public_keys"].get_array().value) {
            key_array << key.get_binary();
        }

        key_array << request->new_key();
        update_document << "public_keys" << (key_array << bsoncxx::builder::stream::finalize);
        set_document << "$set" << (update_document << bsoncxx::builder::stream::finalize);

        users.update_one(user_query << bsoncxx::builder::stream::finalize, set_document << bsoncxx::builder::stream::finalize);
        response->set_success(true);

        return grpc::Status::OK;
    }

    grpc::Status
    chat_service::add_user_media(grpc::ServerContext* context, const add_media_request* request, operation_result* response) {
        auto users = database.collection(USER_COLLECTION_NAME);

        auto user_document_optional = authenticate_request(request->user_auth());
        if(!user_document_optional) return grpc::Status(grpc::StatusCode::UNAUTHENTICATED, "request_not_verified");

        auto user_query = bsoncxx::builder::stream::document();

        user_query << "_id" << bsoncxx::oid(request->user_auth().user_id().data(), request->user_auth().user_id().size());

        auto pic_id_array = bsoncxx::builder::stream::array();
        auto update_document = bsoncxx::builder::stream::document();
        auto set_document = bsoncxx::builder::stream::document();

        for(auto pic_id: user_document_optional.value()["pictures"].get_array().value) {
            pic_id_array << pic_id.get_oid();
        }

        pic_id_array << store_file(request->media()).get_oid();
        update_document << "pictures" << (pic_id_array << bsoncxx::builder::stream::finalize);
        update_document << "picture_index" << (std::distance(pic_id_array.view().cbegin(), pic_id_array.view().cend()) - 1);
        set_document << "$set" << (update_document << bsoncxx::builder::stream::finalize);

        users.update_one(user_query << bsoncxx::builder::stream::finalize, set_document << bsoncxx::builder::stream::finalize);
        response->set_success(true);

        return grpc::Status::OK;
    }

    grpc::Status
    chat_service::delete_user_media(grpc::ServerContext* context, const delete_user_media_request* request, operation_result* response) {
        auto users = database.collection(USER_COLLECTION_NAME);

        auto user_document_optional = authenticate_request(request->user_auth());
        if(!user_document_optional) return grpc::Status(grpc::StatusCode::UNAUTHENTICATED, "request_not_verified");

        auto user_query = bsoncxx::builder::stream::document();

        user_query << "_id" << bsoncxx::oid(request->user_auth().user_id().data(), request->user_auth().user_id().size());

        auto pic_id_array = bsoncxx::builder::stream::array();
        auto update_document = bsoncxx::builder::stream::document();
        auto set_document = bsoncxx::builder::stream::document();

        for(size_t idx = 0; idx < std::distance(
                                                user_document_optional.value()["pictures"].get_array().value.cbegin(),
                                                user_document_optional.value()["pictures"].get_array().value.cend()
                                               ); idx++) {
            auto pic_id = user_document_optional.value()["pictures"].get_array().value[idx];
            if(idx == request->media_index()) {
                auto bucket = database.gridfs_bucket();
                bucket.delete_file(pic_id.get_value());
            } else pic_id_array << pic_id.get_oid();
        }

        update_document << "pictures" << (pic_id_array << bsoncxx::builder::stream::finalize);
        if((user_document_optional.value()["picture_index"]) && (request->media_index() >= user_document_optional.value()["picture_index"].
                                                                 get_int64()))
            update_document << "picture_index" << (
                user_document_optional.value()["picture_index"].get_int64() - 1);
        set_document << "$set" << (update_document << bsoncxx::builder::stream::finalize);

        users.update_one(user_query << bsoncxx::builder::stream::finalize, set_document << bsoncxx::builder::stream::finalize);
        response->set_success(true);

        return grpc::Status::OK;
    }

    grpc::Status
    chat_service::get_headers_after(grpc::ServerContext* context, const header_request* request, grpc::ServerWriter<operation_result>* writer) {
        auto users = database.collection(USER_COLLECTION_NAME);

        auto user_document_optional = authenticate_request(request->user_auth());
        if(!user_document_optional) return grpc::Status(grpc::StatusCode::UNAUTHENTICATED, "request_not_verified");

        auto user_query = bsoncxx::builder::stream::document();

        user_query << "_id" << bsoncxx::oid(request->user_auth().user_id().data(), request->user_auth().user_id().size());

        auto headers = this->database.collection(HEADER_COLLECTION_NAME);
        auto header_query = bsoncxx::builder::stream::document();
        auto gt_query = bsoncxx::builder::stream::document();
        header_query << "recipient" << bsoncxx::oid(request->user_auth().user_id().data(), request->user_auth().user_id().size());
        header_query << "recipient_type" << user;
        gt_query << "timestamp" << bsoncxx::types::b_date{std::chrono::milliseconds{request->timestamp()}};
        header_query << "$gt" << (gt_query << bsoncxx::builder::stream::finalize);

        auto found_headers = headers.find(header_query << bsoncxx::builder::stream::finalize);
        for(auto header_document: found_headers) {
            auto header = detransform_header(header_document);
            auto bucket = database.gridfs_bucket();

            auto downstream = bucket.open_download_stream(header_document["preview_id"].get_value());
            auto block = std::make_unique<uint8_t[]>(header.block_size());

            while(downstream.read(block.get(), header.block_size()) != 0) {
                header.add_preview_bytes(std::string((char*) block.get(), header.block_size()));
            }

            auto result = operation_result();
            result.set_success(true);
            result.set_result(header.SerializeAsString().data());
            writer->Write(result);

            auto update_query = bsoncxx::builder::stream::document();
            auto set_document = bsoncxx::builder::stream::document();
            auto update_document = bsoncxx::builder::stream::document();

            update_query << "_id" << header_document["_id"].get_oid();
            update_document << "status" << delivered;
            set_document << "$set" << (update_document << bsoncxx::builder::stream::finalize);

            headers.update_one(update_query << bsoncxx::builder::stream::finalize, set_document << bsoncxx::builder::stream::finalize);
        }

        return ::grpc::Status::OK;
    }

    grpc::Status
    chat_service::get_full_message(grpc::ServerContext* context, const full_message_request* request, operation_result* response) {
        auto users = database.collection(USER_COLLECTION_NAME);

        auto user_document_optional = authenticate_request(request->user_auth());
        if(!user_document_optional) return grpc::Status(grpc::StatusCode::UNAUTHENTICATED, "request_not_verified");

        auto user_query = bsoncxx::builder::stream::document();

        user_query << "_id" << bsoncxx::oid(request->user_auth().user_id().data(), request->user_auth().user_id().size());

        auto headers = this->database.collection(HEADER_COLLECTION_NAME);
        auto header_query = bsoncxx::builder::stream::document();

        header_query << "_id" << bsoncxx::oid(request->user_auth().user_id().data(), request->user_auth().user_id().size());

        auto header_document = headers.find_one(header_query << bsoncxx::builder::stream::finalize);
        auto header = detransform_header(header_document.value());
        auto bucket = database.gridfs_bucket();

        auto downstream = bucket.open_download_stream(header_document.value()["message_id"].get_value());
        auto block = std::make_unique<uint8_t[]>(header.block_size());

        while(downstream.read(block.get(), header.block_size()) != 0) {
            header.add_message_bytes(std::string((char*) block.get(), header.block_size()));
        }

        response->set_success(true);
        response->set_result(header.SerializeAsString().data());

        return ::grpc::Status::OK;
    }
}
