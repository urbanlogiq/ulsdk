# Copyright (c), CommunityLogiq Software
# 
# THIS FILE IS AUTOGENERATED, DO NOT EDIT

from dataclasses import dataclass
from enum import Enum
from flatbuffers.table import Table
from flatbuffers.builder import Builder
from flatbuffers.util import RemoveSizePrefix
from typing import Union, List, Optional, Self, Tuple
from .id import (
    B2cId,
    ColumnGroupId,
    ContentId,
    DataStateId,
    GenericId,
    GraphNodeId,
    ObjectId,
    ObjectNamespace,
    StreamId,
)
from .generated.AccessControlList import AccessControlList as FbsAccessControlList
from .generated.B2cId import B2cId as FbsB2cId
from .generated.ColumnGroupId import ColumnGroupId as FbsColumnGroupId
from .generated.ContentId import ContentId as FbsContentId
from .generated.DataStateId import DataStateId as FbsDataStateId
from .generated.GenericId import GenericId as FbsGenericId
from .generated.GraphNodeId import GraphNodeId as FbsGraphNodeId
from .generated.ObjectId import ObjectId as FbsObjectId
from .generated.Role import Role as FbsRole
from .generated.StreamId import StreamId as FbsStreamId

class PermissionTy(Enum):
    PERM_BROWSE = 1
    PERM_READ = 2
    PERM_APPEND = 4
    PERM_MODIFY = 8


@dataclass
class AccessControlList:
    # The "extends" allows us to chain together ACLs without needing to copy
    # the whole thing. For example, if want to grant Alice access to a file,
    # we would create a new ACL for that file that has Alice in the permissions
    # list but extends the parent directory's ACL to retain all the existing
    # permissions. This can also be used to selectively revoke access (by
    # adding an ACL entry with empty permissions) to an object.
    extends: Optional["ObjectId"]

    roles: "List[Role]"

    @classmethod
    def from_fbs(cls, o: FbsAccessControlList) -> Self:
        extends = None
        extends_obj = o.Extends()
        if extends_obj is not None:
            extends = ObjectId.from_fbs(extends_obj)
        roles = list()
        if not o.RolesIsNone():
            for i in range(o.RolesLength()):
                roles_val = None
                roles_obj = o.Roles(i)
                if roles_obj is not None:
                    roles_val = Role.from_fbs(roles_obj)
                roles.append(roles_val)
        return cls(extends, roles)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsAccessControlList.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.AccessControlList import (
            Start,
            AddExtends,
            AddRoles,
            StartRolesVector,
            End,
        )
        extends_offset = None
        if self.extends is not None:
            extends_offset = self.extends.serialize_to(builder)
        roles_offsets = list()
        for value in self.roles:
            roles_offsets.append(value.serialize_to(builder))
        StartRolesVector(builder, len(self.roles))
        for i in reversed(range(len(self.roles))):
            builder.PrependUOffsetTRelative(roles_offsets[i])
        roles_offset = builder.EndVector()
        
        Start(builder)
        if extends_offset is not None:
            AddExtends(builder, extends_offset)
        AddRoles(builder, roles_offset)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        extends = ObjectId.make_default()
        roles = []
        return cls(extends, roles)

    def __eq__(self, other) -> bool:
        eq = True
        eq = eq and self.extends == other.extends
        if len(self.roles) != len(other.roles):
            return False
        for i in range(len(self.roles)):
            eq = eq and self.roles[i] == other.roles[i]

        return eq

@dataclass
class Role:
    permission: "int"

    principal: "B2cId"

    @classmethod
    def from_fbs(cls, o: FbsRole) -> Self:
        permission = o.Permission()
        principal_obj = o.Principal()
        if principal_obj is not None:
            principal = B2cId.from_fbs(principal_obj)
        else:
            raise ValueError("Principal is required")
        return cls(permission, principal)

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        deprefixed = RemoveSizePrefix(data, 0)
        o = FbsRole.GetRootAs(deprefixed[0], deprefixed[1])
        return cls.from_fbs(o)

    def serialize_to(self, builder: Builder) -> int:
        from .generated.Role import (
            Start,
            AddPermission,
            AddPrincipal,
            End,
        )
        principal_offset = self.principal.serialize_to(builder)
        
        Start(builder)
        AddPermission(builder, self.permission)
        AddPrincipal(builder, principal_offset)
        return End(builder)

    def to_bytes(self) -> bytes:
        builder = Builder(0)
        offset = self.serialize_to(builder)
        builder.FinishSizePrefixed(offset)
        return builder.Output()

    @classmethod
    def make_default(cls) -> Self:
        permission = 0
        principal = B2cId.make_default()
        return cls(permission, principal)

    def __eq__(self, other) -> bool:
        eq = True
        eq = eq and self.permission == other.permission
        eq = eq and self.principal == other.principal

        return eq