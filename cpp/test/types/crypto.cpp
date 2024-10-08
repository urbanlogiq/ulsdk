// Copyright (c), CommunityLogiq Software
// 
// THIS FILE IS AUTOGENERATED, DO NOT EDIT

#include "ulsdk/types/crypto.h"

#include "test.h"

bool
test_crypt_header() {
    ::ul::types::CryptHeader t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::CryptHeader deserialized = ::ul::types::CryptHeader(bytes);
    return true;
}

TypeTest test_crypt_header_obj(test_crypt_header, "CryptHeader");

bool
test_encrypted_object() {
    ::ul::types::EncryptedObject t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::EncryptedObject deserialized = ::ul::types::EncryptedObject(bytes);
    return true;
}

TypeTest test_encrypted_object_obj(test_encrypted_object, "EncryptedObject");

bool
test_sha_256() {
    ::ul::types::Sha256 t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::Sha256 deserialized = ::ul::types::Sha256(bytes);
    return true;
}

TypeTest test_sha_256_obj(test_sha_256, "Sha256");

bool
test_signature() {
    ::ul::types::Signature t;
    const std::vector<uint8_t> bytes = ::ul::types::to_bytes(t);
    ::ul::types::Signature deserialized = ::ul::types::Signature(bytes);
    return true;
}

TypeTest test_signature_obj(test_signature, "Signature");
