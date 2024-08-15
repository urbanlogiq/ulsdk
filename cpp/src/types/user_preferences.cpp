// Copyright (c), CommunityLogiq Software
// 
// THIS FILE IS AUTOGENERATED, DO NOT EDIT

#include <stdexcept>

#include "ulsdk/types/user_preferences.h"

namespace ul {
namespace types {

::flatbuffers::Offset<::UserPreferences>
serialize_to(::flatbuffers::FlatBufferBuilder &builder, const UserPreferences &o) {
    std::optional<::flatbuffers::Offset<::Point>> center_offset = std::nullopt;
    if (o.center_.has_value()) {
        const ::flatbuffers::Offset<::Point> center_offset_val = serialize_to(builder, o.center_.value());
        center_offset = std::make_optional(center_offset_val);
    }
    std::optional<::flatbuffers::Offset<::ObjectId>> defaultAreaReportTemplate_offset = std::nullopt;
    if (o.defaultAreaReportTemplate_.has_value()) {
        const ::flatbuffers::Offset<::ObjectId> defaultAreaReportTemplate_offset_val = serialize_to(builder, o.defaultAreaReportTemplate_.value());
        defaultAreaReportTemplate_offset = std::make_optional(defaultAreaReportTemplate_offset_val);
    }
    std::optional<::flatbuffers::Offset<::ObjectId>> homepage_usecase_id_offset = std::nullopt;
    if (o.homepage_usecase_id_.has_value()) {
        const ::flatbuffers::Offset<::ObjectId> homepage_usecase_id_offset_val = serialize_to(builder, o.homepage_usecase_id_.value());
        homepage_usecase_id_offset = std::make_optional(homepage_usecase_id_offset_val);
    }
    std::optional<::flatbuffers::Offset<::flatbuffers::String>> timezone_offset = std::nullopt;
    if (o.timezone_.has_value()) {
        const ::flatbuffers::Offset<::flatbuffers::String> timezone_offset_val = builder.CreateString(o.timezone_.value());
        timezone_offset = std::make_optional(timezone_offset_val);
    }

    ::UserPreferencesBuilder instance_builder = ::UserPreferencesBuilder(builder);
    if (center_offset.has_value()) {
        instance_builder.add_center(center_offset.value());
    }
    if (defaultAreaReportTemplate_offset.has_value()) {
        instance_builder.add_defaultAreaReportTemplate(defaultAreaReportTemplate_offset.value());
    }
    if (homepage_usecase_id_offset.has_value()) {
        instance_builder.add_homepage_usecase_id(homepage_usecase_id_offset.value());
    }
    if (timezone_offset.has_value()) {
        instance_builder.add_timezone(timezone_offset.value());
    }
    instance_builder.add_units(o.units_);
    instance_builder.add_zoom(o.zoom_);
    return instance_builder.Finish();
}

std::vector<uint8_t> to_bytes(const UserPreferences &o) {
    ::flatbuffers::FlatBufferBuilder builder;
    const auto offset = serialize_to(builder, o);
    builder.FinishSizePrefixed(offset);
    const auto span = builder.GetBufferSpan();
    return std::vector<uint8_t>(span.begin(), span.end());
}

UserPreferences::UserPreferences()
    : center_(std::nullopt)
    , defaultAreaReportTemplate_(std::nullopt)
    , homepage_usecase_id_(std::nullopt)
    , timezone_(std::nullopt)
    , units_(Units(0))
    , zoom_(0) {
}

UserPreferences::UserPreferences(const std::vector<uint8_t> &bytes)
    : UserPreferences(::flatbuffers::GetSizePrefixedRoot<::UserPreferences>(bytes.data())) {
}

UserPreferences::UserPreferences(const ::UserPreferences *root) 
    : center_(std::nullopt)
    , defaultAreaReportTemplate_(std::nullopt)
    , homepage_usecase_id_(std::nullopt)
    , timezone_(std::nullopt)
    , units_(Units(0))
    , zoom_(0) {
    if (root == nullptr) {
        throw std::runtime_error("cannot deserialize flatbuffer type");
    }

    if (root->center() != nullptr) {
        center_ = decltype(center_)(root->center());
    }
    if (root->defaultAreaReportTemplate() != nullptr) {
        defaultAreaReportTemplate_ = decltype(defaultAreaReportTemplate_)(root->defaultAreaReportTemplate());
    }
    if (root->homepage_usecase_id() != nullptr) {
        homepage_usecase_id_ = decltype(homepage_usecase_id_)(root->homepage_usecase_id());
    }
    if (root->timezone() != nullptr) {
        timezone_ = std::string(*root->timezone()->begin(), *root->timezone()->end());
    }
    units_ = root->units();
    zoom_ = root->zoom();
}

} // namespace types
} // namespace ul
