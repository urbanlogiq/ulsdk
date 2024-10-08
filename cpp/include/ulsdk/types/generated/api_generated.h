// automatically generated by the FlatBuffers compiler, do not modify


#ifndef FLATBUFFERS_GENERATED_API_H_
#define FLATBUFFERS_GENERATED_API_H_

#include "flatbuffers/flatbuffers.h"

// Ensure the included flatbuffers.h is the same version as when this file was
// generated, otherwise it may not be compatible.
static_assert(FLATBUFFERS_VERSION_MAJOR == 23 &&
              FLATBUFFERS_VERSION_MINOR == 5 &&
              FLATBUFFERS_VERSION_REVISION == 26,
             "Non-compatible flatbuffers version included");

/// These constants are used to populate the `OrderByOp` struct's `order` field.
enum class SortOrder : uint32_t {
  ASC = 0,
  DESC = 1,
  MIN = ASC,
  MAX = DESC
};

inline const SortOrder (&EnumValuesSortOrder())[2] {
  static const SortOrder values[] = {
    SortOrder::ASC,
    SortOrder::DESC
  };
  return values;
}

inline const char * const *EnumNamesSortOrder() {
  static const char * const names[3] = {
    "ASC",
    "DESC",
    nullptr
  };
  return names;
}

inline const char *EnumNameSortOrder(SortOrder e) {
  if (::flatbuffers::IsOutRange(e, SortOrder::ASC, SortOrder::DESC)) return "";
  const size_t index = static_cast<size_t>(e);
  return EnumNamesSortOrder()[index];
}

#endif  // FLATBUFFERS_GENERATED_API_H_
