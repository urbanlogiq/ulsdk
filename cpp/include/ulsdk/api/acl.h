// Copyright (c), CommunityLogiq Software
// 
// THIS FILE IS AUTOGENERATED, DO NOT EDIT

#pragma once

#include <cstdint>

#include "ulsdk/request_context.h"
#include "ulsdk/types/notification.h"
#include "ulsdk/types/object.h"
#include "ulsdk/ulsdk.h"


namespace ul {
namespace api {
namespace acl {

/**
 * Create a new access control list. This ACL will be created with the current user as the owner.
 * @return An object summary list containing a single entry with the new ACL.
 */
Result<::ul::types::ObjectSummaryList>
new_acl(
    ul::RequestContext &ctx
);

/**
 * Create a new access control list that inherits from an existing ACL
 * @param extends The ID of the access control list to inherit from
 * @return An object summary list containing a single entry with the new ACL.
 */
Result<::ul::types::ObjectSummaryList>
new_from(
    ul::RequestContext &ctx,
    std::optional<Uuid> extends
);

/**
 * Request access to an object
 * @param request The access request object containing details about the permissions desired
 */
Result<Void>
request(
    ul::RequestContext &ctx,
    const ::ul::types::AccessRequest &request
);

/**
 * Share an object to a specific access control list principal with specified permissions.
 * @param id The ID of the object that will be shared.
 * @param to The ID of the access control list that the object will be shared with.
 * @param permission_bits The permission bitset (see the PermissionTy enum for more information).
 */
Result<Void>
share(
    ul::RequestContext &ctx,
    const Uuid &id,
    const Uuid &to,
    int64_t permission_bits
);

/**
 * Share an object to a specific access control list principal with specified permissions.
 * @param id The ID of the object that will be shared.
 * @param to The ID of the access control list that the object will be shared with.
 * @param permission_bits The permission bitset (see the PermissionTy enum for more information).
 * @param share_details A ShareDetails object containing extra information for the sharing operation, including whether or not to notify the target of the operation, and to provide a message.
 */
Result<Void>
share_with_details(
    ul::RequestContext &ctx,
    const Uuid &id,
    const Uuid &to,
    int64_t permission_bits,
    const ::ul::types::ShareDetails &share_details
);

/**
 * Share an object to a specific access control list principal with all permissions.
 * @param id The ID of the object that will be shared.
 * @param to The ID of the access control list that the object will be shared with.
 */
Result<Void>
share_all(
    ul::RequestContext &ctx,
    const Uuid &id,
    const Uuid &to
);

/**
 * Share an object to a specific access control list principal with all permissions.
 * @param id The ID of the object that will be shared.
 * @param to The ID of the access control list that the object will be shared with.
 * @param share_details A ShareDetails object containing extra information for the sharing operation, including whether or not to notify the target of the operation, and to provide a message.
 */
Result<Void>
share_all_with_details(
    ul::RequestContext &ctx,
    const Uuid &id,
    const Uuid &to,
    const ::ul::types::ShareDetails &share_details
);

/**
 * Grant an object to a specific access control list principal with specified permissions. Unlike the share operation, grant operations will fail with a 403 if the user performing the operation does not have the appropriate access.
 * @param id The ID of the object to which access will be granted.
 * @param to The ID of the access control list that the object will be granted to.
 * @param permission_bits The permission bitset (see the PermissionTy enum for more information).
 */
Result<Void>
grant(
    ul::RequestContext &ctx,
    const Uuid &id,
    const Uuid &to,
    int64_t permission_bits
);

/**
 * Grant an object to a specific access control list principal with specified permissions. Unlike the share operation, grant operations will fail with a 403 if the user performing the operation does not have the appropriate access.
 * @param id The ID of the object to which access will be granted.
 * @param to The ID of the access control list that the object will be granted to.
 * @param permission_bits The permission bitset (see the PermissionTy enum for more information).
 * @param grant_details A ShareDetails object containing extra information for the sharing operation, including whether or not to notify the target of the operation, and to provide a message.
 */
Result<Void>
grant_with_details(
    ul::RequestContext &ctx,
    const Uuid &id,
    const Uuid &to,
    int64_t permission_bits,
    const ::ul::types::ShareDetails &grant_details
);

/**
 * Grant an object to a specific access control list principal with all permissions. Unlike the share operation, grant operations will fail with a 403 if the user performing the operation does not have the appropriate access.
 * @param id The ID of the object to which access will be granted.
 * @param to The ID of the access control list that the object will be granted to.
 */
Result<Void>
grant_all(
    ul::RequestContext &ctx,
    const Uuid &id,
    const Uuid &to
);

/**
 * Grant an object to a specific access control list principal with all permissions. Unlike the share operation, grant operations will fail with a 403 if the user performing the operation does not have the appropriate access.
 * @param id The ID of the object to which access will be granted.
 * @param to The ID of the access control list that the object will be granted to.
 * @param grant_details A ShareDetails object containing extra information for the sharing operation, including whether or not to notify the target of the operation, and to provide a message.
 */
Result<Void>
grant_all_with_details(
    ul::RequestContext &ctx,
    const Uuid &id,
    const Uuid &to,
    const ::ul::types::ShareDetails &grant_details
);

/**
 * Revoke all access from a specified ACL to an object.
 * @param id The ID of the object from which access will be revoked.
 * @param from The ID of the access control list that access to the object will be revoked from.
 */
Result<Void>
revoke(
    ul::RequestContext &ctx,
    const Uuid &id,
    const Uuid &from
);

/**
 * Get the permissions the caller has on the object with the given ID.
 * @param id The ID of the object which will be queried for permissions.
 */
Result<Void>
get_permissions(
    ul::RequestContext &ctx,
    const Uuid &id
);

/**
 * Forcibly set an object's ACL to another ACL object. Note that the target ACL needs to contain the exact same permissions as the current ACL otherwise this method will return 400 Bad Request. This is a safeguard to ensure the user cannot lock themselves out of an object.
 * @param id The ID of the object which will have its ACL set.
 * @param acl_id The ID of the ACL object which will be used as the object ACL.
 */
Result<Void>
set(
    ul::RequestContext &ctx,
    const Uuid &id,
    const Uuid &acl_id
);

} // namespace acl
} // namespace api
} // namespace ul
