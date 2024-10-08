// Copyright (c), CommunityLogiq Software
// 
// THIS FILE IS AUTOGENERATED, DO NOT EDIT

#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <variant>
#include <vector>

#include "flatbuffers/flatbuffers.h"
#include "ulsdk/types/Schema.h"
#include "ulsdk/types/crypto.h"
#include "ulsdk/types/data.h"
#include "ulsdk/types/id.h"
#include "ulsdk/types/job.h"
#include "ulsdk/types/object.h"
#include "ulsdk/types/reflection.h"
#include "ulsdk/types/stream.h"
#include "ulsdk/types/value.h"
#include "ulsdk/types/worklog.h"
#include "ulsdk/types/generated/fs_generated.h"

namespace ul {
namespace types {

struct Attr;
struct Chunk;
struct Directory;
struct DirectoryEntry;
struct DirectoryList;
struct File;
struct ListDirectory;
struct ListFile;
struct ListObject;
struct ListSlot;
struct MoveRequest;
struct NewLink;
struct ObjectRef;
struct Slot;
struct TopLevelDirectory;

typedef std::variant<
    std::shared_ptr<File>,
    std::shared_ptr<Directory>,
    std::shared_ptr<ObjectRef>
> Entry;

using ::EntryTy;
typedef std::variant<
    std::shared_ptr<ListFile>,
    std::shared_ptr<ListDirectory>,
    std::shared_ptr<ListObject>,
    std::shared_ptr<TopLevelDirectory>
> ListEntry;

struct File {
    std::string account_;
    std::optional<GenericId> blob_;
    std::optional<std::vector<Chunk>> chunks_;
    std::optional<std::string> container_;
    std::optional<Digest> digest_;
    std::string mime_;
    uint64_t size_;
    std::optional<std::string> virus_;

    File();
    File(const ::File *root);
    File(const std::vector<uint8_t> &bytes);
};

///
/// This Directory table holds the entries in the actual directory
///
struct Directory {
    std::optional<std::vector<B2cId>> notifications_;
    std::vector<Slot> slots_;

    Directory();
    Directory(const ::Directory *root);
    Directory(const std::vector<uint8_t> &bytes);
};

struct ObjectRef {
    ObjectId id_;
    DataCatalogObjectTy ty_;

    ObjectRef();
    ObjectRef(const ::ObjectRef *root);
    ObjectRef(const std::vector<uint8_t> &bytes);
};

struct ListFile {
    std::string mime_;
    uint64_t size_;
    std::optional<std::string> virus_;

    ListFile();
    ListFile(const ::ListFile *root);
    ListFile(const std::vector<uint8_t> &bytes);
};

struct ListDirectory {

    ListDirectory();
    ListDirectory(const ::ListDirectory *root);
    ListDirectory(const std::vector<uint8_t> &bytes);
};

struct ListObject {
    ObjectId id_;
    uint64_t size_;
    DataCatalogObjectTy ty_;

    ListObject();
    ListObject(const ::ListObject *root);
    ListObject(const std::vector<uint8_t> &bytes);
};

struct TopLevelDirectory {
    B2cId b2c_entity_;

    TopLevelDirectory();
    TopLevelDirectory(const ::TopLevelDirectory *root);
    TopLevelDirectory(const std::vector<uint8_t> &bytes);
};

struct Attr {
    std::string key_;
    Value v_;

    Attr();
    Attr(const ::Attr *root);
    Attr(const std::vector<uint8_t> &bytes);
};

struct Chunk {
    GenericId blob_;
    Digest digest_;
    uint64_t size_;

    Chunk();
    Chunk(const ::Chunk *root);
    Chunk(const std::vector<uint8_t> &bytes);
};

struct DirectoryEntry {
    Entry entry_;
    ObjectId parent_;

    DirectoryEntry();
    DirectoryEntry(const ::DirectoryEntry *root);
    DirectoryEntry(const std::vector<uint8_t> &bytes);
};

struct DirectoryList {
    std::vector<ListSlot> slots_;

    DirectoryList();
    DirectoryList(const ::DirectoryList *root);
    DirectoryList(const std::vector<uint8_t> &bytes);
};

struct ListSlot {
    std::optional<std::vector<Attr>> attributes_;
    ListEntry entry_;
    ObjectId id_;
    std::optional<B2cId> last_modified_by_;
    std::string name_;
    uint64_t size_;
    uint64_t time_;
    uint32_t user_permissions_;

    ListSlot();
    ListSlot(const ::ListSlot *root);
    ListSlot(const std::vector<uint8_t> &bytes);
};

struct MoveRequest {
    std::optional<std::string> dest_name_;
    std::optional<ObjectId> dest_root_;
    ObjectId entry_;
    bool overwrite_;

    MoveRequest();
    MoveRequest(const ::MoveRequest *root);
    MoveRequest(const std::vector<uint8_t> &bytes);
};

///
/// Body parameter for PUT drive/<object>
///
struct NewLink {
    std::string name_;
    ObjectId obj_;

    NewLink();
    NewLink(const ::NewLink *root);
    NewLink(const std::vector<uint8_t> &bytes);
};

struct Slot {
    std::optional<std::vector<Attr>> attributes_;
    ObjectId id_;
    std::string name_;
    EntryTy ty_;

    Slot();
    Slot(const ::Slot *root);
    Slot(const std::vector<uint8_t> &bytes);
};

std::pair<::flatbuffers::Offset<void>, ::Entry>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const Entry &o);
std::pair<::flatbuffers::Offset<void>, ::ListEntry>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const ListEntry &o);
::flatbuffers::Offset<::File>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const File &);

::flatbuffers::Offset<::Directory>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const Directory &);

::flatbuffers::Offset<::ObjectRef>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const ObjectRef &);

::flatbuffers::Offset<::ListFile>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const ListFile &);

::flatbuffers::Offset<::ListDirectory>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const ListDirectory &);

::flatbuffers::Offset<::ListObject>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const ListObject &);

::flatbuffers::Offset<::TopLevelDirectory>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const TopLevelDirectory &);

::flatbuffers::Offset<::Attr>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const Attr &);

::flatbuffers::Offset<::Chunk>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const Chunk &);

::flatbuffers::Offset<::DirectoryEntry>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const DirectoryEntry &);

::flatbuffers::Offset<::DirectoryList>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const DirectoryList &);

::flatbuffers::Offset<::ListSlot>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const ListSlot &);

::flatbuffers::Offset<::MoveRequest>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const MoveRequest &);

::flatbuffers::Offset<::NewLink>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const NewLink &);

::flatbuffers::Offset<::Slot>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const Slot &);


std::vector<uint8_t>
to_bytes(const File &o);

std::vector<uint8_t>
to_bytes(const Directory &o);

std::vector<uint8_t>
to_bytes(const ObjectRef &o);

std::vector<uint8_t>
to_bytes(const ListFile &o);

std::vector<uint8_t>
to_bytes(const ListDirectory &o);

std::vector<uint8_t>
to_bytes(const ListObject &o);

std::vector<uint8_t>
to_bytes(const TopLevelDirectory &o);

std::vector<uint8_t>
to_bytes(const Attr &o);

std::vector<uint8_t>
to_bytes(const Chunk &o);

std::vector<uint8_t>
to_bytes(const DirectoryEntry &o);

std::vector<uint8_t>
to_bytes(const DirectoryList &o);

std::vector<uint8_t>
to_bytes(const ListSlot &o);

std::vector<uint8_t>
to_bytes(const MoveRequest &o);

std::vector<uint8_t>
to_bytes(const NewLink &o);

std::vector<uint8_t>
to_bytes(const Slot &o);


} // namespace types
} // namespace ul
