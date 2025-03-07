//
// Created by atorres on 3/7/25.
//

#ifndef SERVICE_HPP
#define SERVICE_HPP

#include <string>

#include "mongocxx/client.hpp"

#include "src/protobuf/services.grpc.pb.h"

namespace slr::hermes {
    class chat_service final: public prometheus_service::Service {
    private:
        mongocxx::client connection;
        mongocxx::database database;

        bsoncxx::types::bson_value::view
        store_file(const chat_attachment& file);

        std::optional<chat_attachment>
        load_file(const bsoncxx::types::bson_value::view& file);

        bsoncxx::document::value
        transform_user(const chat_user* request);

        std::map<std::string, bsoncxx::types::bson_value::view>
        store_bytes(const chat_header* request);

        bsoncxx::document::value
        transform_header(const std::unique_ptr<chat_header>& request);

        static chat_header
        detransform_header(const bsoncxx::document::view& header_document);

        chat_user
        detransform_user(const bsoncxx::document::view& user_document);

        std::optional<bsoncxx::document::value>
        authenticate_request(const authenticated_request& auth);

    public:
        chat_service(const std::string& uri_str, const std::string& db_name);

        grpc::Status
        register_user(grpc::ServerContext* context, const chat_user* request, operation_result* response) override;

        grpc::Status
        get_headers_after(grpc::ServerContext* context, const header_request* request, grpc::ServerWriter<operation_result>* writer) override;

        grpc::Status
        get_full_message(grpc::ServerContext* context, const full_message_request* request, operation_result* response) override;

        grpc::Status
        send_messages(grpc::ServerContext* context, grpc::ServerReaderWriter<operation_result, chat_header>* stream) override;

        grpc::Status
        edit_message(grpc::ServerContext* context, const edit_message_request* request, operation_result* response) override;

        grpc::Status
        get_user_data(grpc::ServerContext* context, const user_data_request* request, operation_result* response) override;

        grpc::Status
        add_user_key(grpc::ServerContext* context, const add_key_request* request, operation_result* response) override;

        grpc::Status
        add_user_media(grpc::ServerContext* context, const add_media_request* request, operation_result* response) override;

        grpc::Status
        delete_user_media(grpc::ServerContext* context, const delete_user_media_request* request, operation_result* response) override;
    };
}

#endif //SERVICE_HPP
