// Copyright (c), CommunityLogiq Software
// 
// THIS FILE IS AUTOGENERATED, DO NOT EDIT

#pragma once

#include <cstdint>

#include "ulsdk/request_context.h"
#include "ulsdk/types/fs.h"
#include "ulsdk/types/id.h"
#include "ulsdk/types/object.h"
#include "ulsdk/ulsdk.h"


namespace ul {
namespace api {
namespace drive {

/**
 * Retrieves a directory listing from a unix-style path rooted at `root`. `root` may be one of:
- `me` for the current user's drive
- `union` for the union of the current user's drive and all shared drives
- the UUID of any drive directory
Paths may include wildcards like `*`.
                
 * @param root The root directory to list files for, or one of "me" or "union".
 * @param tail The unix-style path specifier to use for the file listing.
 * @return The directory listing
 */
Result<::ul::types::DirectoryList>
ls(
    ul::RequestContext &ctx,
    const std::string &root,
    const std::string &tail
);

/**
 * Creates a new file or directory at a specified path rooted at `root`.
 * @param root The directory into which the new entry will be created
 * @param tail The name of the new entry
 * @param ty The type of entry to create: `file` or `directory`.
 * @param mime The mime type of the entry to create, if this is a new file entry.
 * @param chunks Number of chunks to expect, if this is a new file entry.
 * @return A summary of the object created
 */
Result<::ul::types::ObjectSummary>
create_entry(
    ul::RequestContext &ctx,
    const std::string &root,
    const std::string &tail,
    const std::string &ty,
    const std::string &mime,
    int64_t chunks
);

/**
 * Retrieves a list of the top-level drive root directories that the current user has access to.
 * @return A listing of all the directory roots.
 */
Result<::ul::types::DirectoryList>
get_roots(
    ul::RequestContext &ctx
);

/**
 * Creates a new file in the specified directory with the specified content. Please use the `put_file_chunk` endpoint to upload files larger than 1GB.
 * @param root The directory into which the file will be uploaded
 * @param force Whether to overwrite the file if it already exists.
 * @param files The files to upload as part of a multipart upload
 * @return An updated list of directory entries
 */
Result<::ul::types::DirectoryList>
post_file(
    ul::RequestContext &ctx,
    const std::string &root,
    bool force,
    const std::vector<ul::File> &files
);

/**
 * Removes the specified drive entry from its parent directory.
 * @param entry The ID of the entry to remove
 * @return An updated list of directory entries
 */
Result<::ul::types::DirectoryList>
unlink(
    ul::RequestContext &ctx,
    const std::string &entry
);

/**
 * Moves a file or directory to a new location.
 * @param move_request Details of the move operation.
 */
Result<Void>
move(
    ul::RequestContext &ctx,
    const ::ul::types::MoveRequest &move_request
);

/**
 * Copies a file or directory to a new location within the drive.
 * @param copy_request Details of the copy operation.
 */
Result<Void>
copy(
    ul::RequestContext &ctx,
    const ::ul::types::MoveRequest &copy_request
);

/**
 * Retrieves a file by id.
 * @param id The ID of the file to retrieve
 * @return The contents of the file referenced by the specified ID
 */
Result<std::vector<uint8_t>>
get_file(
    ul::RequestContext &ctx,
    const std::string &id
);

/**
 * Uploads a chunk of a file by file id and chunk index.
 * @param file_id The ID of the file to which to set a file chunk
 * @param idx The index of the file chunk to set
 * @param hash The hash of the chunk to upload.
 * @param chunk Binary file chunk data
 */
Result<Void>
put_file_chunk(
    ul::RequestContext &ctx,
    const std::string &file_id,
    int64_t idx,
    const std::string &hash,
    const std::vector<uint8_t> &chunk
);

/**
 * Retrieves the id of the drive root directory for the specified principal (user or group).
 * @param b_2cid The principal (user or group) ID to retrieve the drive root directory for.
 * @return Drive directory root ID
 */
Result<::ul::types::ObjectId>
get_root_id(
    ul::RequestContext &ctx,
    const std::string &b_2cid
);

} // namespace drive
} // namespace api
} // namespace ul
