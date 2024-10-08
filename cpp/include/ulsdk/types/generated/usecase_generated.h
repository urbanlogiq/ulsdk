// automatically generated by the FlatBuffers compiler, do not modify


#ifndef FLATBUFFERS_GENERATED_USECASE_H_
#define FLATBUFFERS_GENERATED_USECASE_H_

#include "flatbuffers/flatbuffers.h"

// Ensure the included flatbuffers.h is the same version as when this file was
// generated, otherwise it may not be compatible.
static_assert(FLATBUFFERS_VERSION_MAJOR == 23 &&
              FLATBUFFERS_VERSION_MINOR == 5 &&
              FLATBUFFERS_VERSION_REVISION == 26,
             "Non-compatible flatbuffers version included");

#include "Schema_generated.h"
#include "id_generated.h"
#include "query_generated.h"
#include "value_generated.h"

struct UseCaseInputPair;
struct UseCaseInputPairBuilder;

struct UseCase;
struct UseCaseBuilder;

enum class UseCaseTy : uint32_t {
  Invalid = 0,
  OriginDestination = 1,
  TrafficImpact = 2,
  TxDotFreight = 3,
  TravelTime = 4,
  RoadVolume = 5,
  IntersectionCounts = 6,
  CrashBoard = 7,
  TxDotCrash = 8,
  HendersonDelay = 9,
  PedestrianVolume = 10,
  ActiveTransportation = 11,
  KPIDashboard = 12,
  HendersonTrafficImpact = 13,
  AreaReportBulkExport = 14,
  Fireboard = 15,
  GenericDashboard = 16,
  MetricsDashboard = 17,
  FreightAnalysis = 18,
  CorridorAnalysis = 19,
  Ethica = 20,
  MIN = Invalid,
  MAX = Ethica
};

inline const UseCaseTy (&EnumValuesUseCaseTy())[21] {
  static const UseCaseTy values[] = {
    UseCaseTy::Invalid,
    UseCaseTy::OriginDestination,
    UseCaseTy::TrafficImpact,
    UseCaseTy::TxDotFreight,
    UseCaseTy::TravelTime,
    UseCaseTy::RoadVolume,
    UseCaseTy::IntersectionCounts,
    UseCaseTy::CrashBoard,
    UseCaseTy::TxDotCrash,
    UseCaseTy::HendersonDelay,
    UseCaseTy::PedestrianVolume,
    UseCaseTy::ActiveTransportation,
    UseCaseTy::KPIDashboard,
    UseCaseTy::HendersonTrafficImpact,
    UseCaseTy::AreaReportBulkExport,
    UseCaseTy::Fireboard,
    UseCaseTy::GenericDashboard,
    UseCaseTy::MetricsDashboard,
    UseCaseTy::FreightAnalysis,
    UseCaseTy::CorridorAnalysis,
    UseCaseTy::Ethica
  };
  return values;
}

inline const char * const *EnumNamesUseCaseTy() {
  static const char * const names[22] = {
    "Invalid",
    "OriginDestination",
    "TrafficImpact",
    "TxDotFreight",
    "TravelTime",
    "RoadVolume",
    "IntersectionCounts",
    "CrashBoard",
    "TxDotCrash",
    "HendersonDelay",
    "PedestrianVolume",
    "ActiveTransportation",
    "KPIDashboard",
    "HendersonTrafficImpact",
    "AreaReportBulkExport",
    "Fireboard",
    "GenericDashboard",
    "MetricsDashboard",
    "FreightAnalysis",
    "CorridorAnalysis",
    "Ethica",
    nullptr
  };
  return names;
}

inline const char *EnumNameUseCaseTy(UseCaseTy e) {
  if (::flatbuffers::IsOutRange(e, UseCaseTy::Invalid, UseCaseTy::Ethica)) return "";
  const size_t index = static_cast<size_t>(e);
  return EnumNamesUseCaseTy()[index];
}

enum class UseCaseModule : uint32_t {
  None = 0,
  Traffic = 1,
  EconomicDevelopment = 2,
  Planning = 3,
  MIN = None,
  MAX = Planning
};

inline const UseCaseModule (&EnumValuesUseCaseModule())[4] {
  static const UseCaseModule values[] = {
    UseCaseModule::None,
    UseCaseModule::Traffic,
    UseCaseModule::EconomicDevelopment,
    UseCaseModule::Planning
  };
  return values;
}

inline const char * const *EnumNamesUseCaseModule() {
  static const char * const names[5] = {
    "None",
    "Traffic",
    "EconomicDevelopment",
    "Planning",
    nullptr
  };
  return names;
}

inline const char *EnumNameUseCaseModule(UseCaseModule e) {
  if (::flatbuffers::IsOutRange(e, UseCaseModule::None, UseCaseModule::Planning)) return "";
  const size_t index = static_cast<size_t>(e);
  return EnumNamesUseCaseModule()[index];
}

enum class UseCaseInput : uint8_t {
  NONE = 0,
  ObjectId = 1,
  Schema = 2,
  ParameterizedQuery = 3,
  ValueInstance = 4,
  MIN = NONE,
  MAX = ValueInstance
};

inline const UseCaseInput (&EnumValuesUseCaseInput())[5] {
  static const UseCaseInput values[] = {
    UseCaseInput::NONE,
    UseCaseInput::ObjectId,
    UseCaseInput::Schema,
    UseCaseInput::ParameterizedQuery,
    UseCaseInput::ValueInstance
  };
  return values;
}

inline const char * const *EnumNamesUseCaseInput() {
  static const char * const names[6] = {
    "NONE",
    "ObjectId",
    "Schema",
    "ParameterizedQuery",
    "ValueInstance",
    nullptr
  };
  return names;
}

inline const char *EnumNameUseCaseInput(UseCaseInput e) {
  if (::flatbuffers::IsOutRange(e, UseCaseInput::NONE, UseCaseInput::ValueInstance)) return "";
  const size_t index = static_cast<size_t>(e);
  return EnumNamesUseCaseInput()[index];
}

template<typename T> struct UseCaseInputTraits {
  static const UseCaseInput enum_value = UseCaseInput::NONE;
};

template<> struct UseCaseInputTraits<ObjectId> {
  static const UseCaseInput enum_value = UseCaseInput::ObjectId;
};

template<> struct UseCaseInputTraits<Schema> {
  static const UseCaseInput enum_value = UseCaseInput::Schema;
};

template<> struct UseCaseInputTraits<ParameterizedQuery> {
  static const UseCaseInput enum_value = UseCaseInput::ParameterizedQuery;
};

template<> struct UseCaseInputTraits<ValueInstance> {
  static const UseCaseInput enum_value = UseCaseInput::ValueInstance;
};

bool VerifyUseCaseInput(::flatbuffers::Verifier &verifier, const void *obj, UseCaseInput type);
bool VerifyUseCaseInputVector(::flatbuffers::Verifier &verifier, const ::flatbuffers::Vector<::flatbuffers::Offset<void>> *values, const ::flatbuffers::Vector<UseCaseInput> *types);

struct UseCaseInputPair FLATBUFFERS_FINAL_CLASS : private ::flatbuffers::Table {
  typedef UseCaseInputPairBuilder Builder;
  struct Traits;
  enum FlatBuffersVTableOffset FLATBUFFERS_VTABLE_UNDERLYING_TYPE {
    VT_NAME = 4,
    VT_INPUT_TYPE = 6,
    VT_INPUT = 8
  };
  const ::flatbuffers::String *name() const {
    return GetPointer<const ::flatbuffers::String *>(VT_NAME);
  }
  UseCaseInput input_type() const {
    return static_cast<UseCaseInput>(GetField<uint8_t>(VT_INPUT_TYPE, 0));
  }
  const void *input() const {
    return GetPointer<const void *>(VT_INPUT);
  }
  template<typename T> const T *input_as() const;
  const ObjectId *input_as_ObjectId() const {
    return input_type() == UseCaseInput::ObjectId ? static_cast<const ObjectId *>(input()) : nullptr;
  }
  const Schema *input_as_Schema() const {
    return input_type() == UseCaseInput::Schema ? static_cast<const Schema *>(input()) : nullptr;
  }
  const ParameterizedQuery *input_as_ParameterizedQuery() const {
    return input_type() == UseCaseInput::ParameterizedQuery ? static_cast<const ParameterizedQuery *>(input()) : nullptr;
  }
  const ValueInstance *input_as_ValueInstance() const {
    return input_type() == UseCaseInput::ValueInstance ? static_cast<const ValueInstance *>(input()) : nullptr;
  }
  bool Verify(::flatbuffers::Verifier &verifier) const {
    return VerifyTableStart(verifier) &&
           VerifyOffsetRequired(verifier, VT_NAME) &&
           verifier.VerifyString(name()) &&
           VerifyField<uint8_t>(verifier, VT_INPUT_TYPE, 1) &&
           VerifyOffset(verifier, VT_INPUT) &&
           VerifyUseCaseInput(verifier, input(), input_type()) &&
           verifier.EndTable();
  }
};

template<> inline const ObjectId *UseCaseInputPair::input_as<ObjectId>() const {
  return input_as_ObjectId();
}

template<> inline const Schema *UseCaseInputPair::input_as<Schema>() const {
  return input_as_Schema();
}

template<> inline const ParameterizedQuery *UseCaseInputPair::input_as<ParameterizedQuery>() const {
  return input_as_ParameterizedQuery();
}

template<> inline const ValueInstance *UseCaseInputPair::input_as<ValueInstance>() const {
  return input_as_ValueInstance();
}

struct UseCaseInputPairBuilder {
  typedef UseCaseInputPair Table;
  ::flatbuffers::FlatBufferBuilder &fbb_;
  ::flatbuffers::uoffset_t start_;
  void add_name(::flatbuffers::Offset<::flatbuffers::String> name) {
    fbb_.AddOffset(UseCaseInputPair::VT_NAME, name);
  }
  void add_input_type(UseCaseInput input_type) {
    fbb_.AddElement<uint8_t>(UseCaseInputPair::VT_INPUT_TYPE, static_cast<uint8_t>(input_type), 0);
  }
  void add_input(::flatbuffers::Offset<void> input) {
    fbb_.AddOffset(UseCaseInputPair::VT_INPUT, input);
  }
  explicit UseCaseInputPairBuilder(::flatbuffers::FlatBufferBuilder &_fbb)
        : fbb_(_fbb) {
    start_ = fbb_.StartTable();
  }
  ::flatbuffers::Offset<UseCaseInputPair> Finish() {
    const auto end = fbb_.EndTable(start_);
    auto o = ::flatbuffers::Offset<UseCaseInputPair>(end);
    fbb_.Required(o, UseCaseInputPair::VT_NAME);
    return o;
  }
};

inline ::flatbuffers::Offset<UseCaseInputPair> CreateUseCaseInputPair(
    ::flatbuffers::FlatBufferBuilder &_fbb,
    ::flatbuffers::Offset<::flatbuffers::String> name = 0,
    UseCaseInput input_type = UseCaseInput::NONE,
    ::flatbuffers::Offset<void> input = 0) {
  UseCaseInputPairBuilder builder_(_fbb);
  builder_.add_input(input);
  builder_.add_name(name);
  builder_.add_input_type(input_type);
  return builder_.Finish();
}

struct UseCaseInputPair::Traits {
  using type = UseCaseInputPair;
  static auto constexpr Create = CreateUseCaseInputPair;
};

inline ::flatbuffers::Offset<UseCaseInputPair> CreateUseCaseInputPairDirect(
    ::flatbuffers::FlatBufferBuilder &_fbb,
    const char *name = nullptr,
    UseCaseInput input_type = UseCaseInput::NONE,
    ::flatbuffers::Offset<void> input = 0) {
  auto name__ = name ? _fbb.CreateString(name) : 0;
  return CreateUseCaseInputPair(
      _fbb,
      name__,
      input_type,
      input);
}

struct UseCase FLATBUFFERS_FINAL_CLASS : private ::flatbuffers::Table {
  typedef UseCaseBuilder Builder;
  struct Traits;
  enum FlatBuffersVTableOffset FLATBUFFERS_VTABLE_UNDERLYING_TYPE {
    VT_TY = 4,
    VT_MODULE_ = 6,
    VT_INPUTS = 8,
    VT_NAME = 10,
    VT_DESCRIPTION = 12,
    VT_SUBTITLE = 14,
    VT_ABBREVIATION = 16,
    VT_EXTENDED_TITLE = 18,
    VT_EXTENDED_DESCRIPTION = 20
  };
  UseCaseTy ty() const {
    return static_cast<UseCaseTy>(GetField<uint32_t>(VT_TY, 0));
  }
  UseCaseModule module_() const {
    return static_cast<UseCaseModule>(GetField<uint32_t>(VT_MODULE_, 0));
  }
  const ::flatbuffers::Vector<::flatbuffers::Offset<UseCaseInputPair>> *inputs() const {
    return GetPointer<const ::flatbuffers::Vector<::flatbuffers::Offset<UseCaseInputPair>> *>(VT_INPUTS);
  }
  const ::flatbuffers::String *name() const {
    return GetPointer<const ::flatbuffers::String *>(VT_NAME);
  }
  const ::flatbuffers::String *description() const {
    return GetPointer<const ::flatbuffers::String *>(VT_DESCRIPTION);
  }
  const ::flatbuffers::String *subtitle() const {
    return GetPointer<const ::flatbuffers::String *>(VT_SUBTITLE);
  }
  const ::flatbuffers::String *abbreviation() const {
    return GetPointer<const ::flatbuffers::String *>(VT_ABBREVIATION);
  }
  const ::flatbuffers::String *extended_title() const {
    return GetPointer<const ::flatbuffers::String *>(VT_EXTENDED_TITLE);
  }
  const ::flatbuffers::String *extended_description() const {
    return GetPointer<const ::flatbuffers::String *>(VT_EXTENDED_DESCRIPTION);
  }
  bool Verify(::flatbuffers::Verifier &verifier) const {
    return VerifyTableStart(verifier) &&
           VerifyField<uint32_t>(verifier, VT_TY, 4) &&
           VerifyField<uint32_t>(verifier, VT_MODULE_, 4) &&
           VerifyOffsetRequired(verifier, VT_INPUTS) &&
           verifier.VerifyVector(inputs()) &&
           verifier.VerifyVectorOfTables(inputs()) &&
           VerifyOffsetRequired(verifier, VT_NAME) &&
           verifier.VerifyString(name()) &&
           VerifyOffset(verifier, VT_DESCRIPTION) &&
           verifier.VerifyString(description()) &&
           VerifyOffset(verifier, VT_SUBTITLE) &&
           verifier.VerifyString(subtitle()) &&
           VerifyOffset(verifier, VT_ABBREVIATION) &&
           verifier.VerifyString(abbreviation()) &&
           VerifyOffset(verifier, VT_EXTENDED_TITLE) &&
           verifier.VerifyString(extended_title()) &&
           VerifyOffset(verifier, VT_EXTENDED_DESCRIPTION) &&
           verifier.VerifyString(extended_description()) &&
           verifier.EndTable();
  }
};

struct UseCaseBuilder {
  typedef UseCase Table;
  ::flatbuffers::FlatBufferBuilder &fbb_;
  ::flatbuffers::uoffset_t start_;
  void add_ty(UseCaseTy ty) {
    fbb_.AddElement<uint32_t>(UseCase::VT_TY, static_cast<uint32_t>(ty), 0);
  }
  void add_module_(UseCaseModule module_) {
    fbb_.AddElement<uint32_t>(UseCase::VT_MODULE_, static_cast<uint32_t>(module_), 0);
  }
  void add_inputs(::flatbuffers::Offset<::flatbuffers::Vector<::flatbuffers::Offset<UseCaseInputPair>>> inputs) {
    fbb_.AddOffset(UseCase::VT_INPUTS, inputs);
  }
  void add_name(::flatbuffers::Offset<::flatbuffers::String> name) {
    fbb_.AddOffset(UseCase::VT_NAME, name);
  }
  void add_description(::flatbuffers::Offset<::flatbuffers::String> description) {
    fbb_.AddOffset(UseCase::VT_DESCRIPTION, description);
  }
  void add_subtitle(::flatbuffers::Offset<::flatbuffers::String> subtitle) {
    fbb_.AddOffset(UseCase::VT_SUBTITLE, subtitle);
  }
  void add_abbreviation(::flatbuffers::Offset<::flatbuffers::String> abbreviation) {
    fbb_.AddOffset(UseCase::VT_ABBREVIATION, abbreviation);
  }
  void add_extended_title(::flatbuffers::Offset<::flatbuffers::String> extended_title) {
    fbb_.AddOffset(UseCase::VT_EXTENDED_TITLE, extended_title);
  }
  void add_extended_description(::flatbuffers::Offset<::flatbuffers::String> extended_description) {
    fbb_.AddOffset(UseCase::VT_EXTENDED_DESCRIPTION, extended_description);
  }
  explicit UseCaseBuilder(::flatbuffers::FlatBufferBuilder &_fbb)
        : fbb_(_fbb) {
    start_ = fbb_.StartTable();
  }
  ::flatbuffers::Offset<UseCase> Finish() {
    const auto end = fbb_.EndTable(start_);
    auto o = ::flatbuffers::Offset<UseCase>(end);
    fbb_.Required(o, UseCase::VT_INPUTS);
    fbb_.Required(o, UseCase::VT_NAME);
    return o;
  }
};

inline ::flatbuffers::Offset<UseCase> CreateUseCase(
    ::flatbuffers::FlatBufferBuilder &_fbb,
    UseCaseTy ty = UseCaseTy::Invalid,
    UseCaseModule module_ = UseCaseModule::None,
    ::flatbuffers::Offset<::flatbuffers::Vector<::flatbuffers::Offset<UseCaseInputPair>>> inputs = 0,
    ::flatbuffers::Offset<::flatbuffers::String> name = 0,
    ::flatbuffers::Offset<::flatbuffers::String> description = 0,
    ::flatbuffers::Offset<::flatbuffers::String> subtitle = 0,
    ::flatbuffers::Offset<::flatbuffers::String> abbreviation = 0,
    ::flatbuffers::Offset<::flatbuffers::String> extended_title = 0,
    ::flatbuffers::Offset<::flatbuffers::String> extended_description = 0) {
  UseCaseBuilder builder_(_fbb);
  builder_.add_extended_description(extended_description);
  builder_.add_extended_title(extended_title);
  builder_.add_abbreviation(abbreviation);
  builder_.add_subtitle(subtitle);
  builder_.add_description(description);
  builder_.add_name(name);
  builder_.add_inputs(inputs);
  builder_.add_module_(module_);
  builder_.add_ty(ty);
  return builder_.Finish();
}

struct UseCase::Traits {
  using type = UseCase;
  static auto constexpr Create = CreateUseCase;
};

inline ::flatbuffers::Offset<UseCase> CreateUseCaseDirect(
    ::flatbuffers::FlatBufferBuilder &_fbb,
    UseCaseTy ty = UseCaseTy::Invalid,
    UseCaseModule module_ = UseCaseModule::None,
    const std::vector<::flatbuffers::Offset<UseCaseInputPair>> *inputs = nullptr,
    const char *name = nullptr,
    const char *description = nullptr,
    const char *subtitle = nullptr,
    const char *abbreviation = nullptr,
    const char *extended_title = nullptr,
    const char *extended_description = nullptr) {
  auto inputs__ = inputs ? _fbb.CreateVector<::flatbuffers::Offset<UseCaseInputPair>>(*inputs) : 0;
  auto name__ = name ? _fbb.CreateString(name) : 0;
  auto description__ = description ? _fbb.CreateString(description) : 0;
  auto subtitle__ = subtitle ? _fbb.CreateString(subtitle) : 0;
  auto abbreviation__ = abbreviation ? _fbb.CreateString(abbreviation) : 0;
  auto extended_title__ = extended_title ? _fbb.CreateString(extended_title) : 0;
  auto extended_description__ = extended_description ? _fbb.CreateString(extended_description) : 0;
  return CreateUseCase(
      _fbb,
      ty,
      module_,
      inputs__,
      name__,
      description__,
      subtitle__,
      abbreviation__,
      extended_title__,
      extended_description__);
}

inline bool VerifyUseCaseInput(::flatbuffers::Verifier &verifier, const void *obj, UseCaseInput type) {
  switch (type) {
    case UseCaseInput::NONE: {
      return true;
    }
    case UseCaseInput::ObjectId: {
      auto ptr = reinterpret_cast<const ObjectId *>(obj);
      return verifier.VerifyTable(ptr);
    }
    case UseCaseInput::Schema: {
      auto ptr = reinterpret_cast<const Schema *>(obj);
      return verifier.VerifyTable(ptr);
    }
    case UseCaseInput::ParameterizedQuery: {
      auto ptr = reinterpret_cast<const ParameterizedQuery *>(obj);
      return verifier.VerifyTable(ptr);
    }
    case UseCaseInput::ValueInstance: {
      auto ptr = reinterpret_cast<const ValueInstance *>(obj);
      return verifier.VerifyTable(ptr);
    }
    default: return true;
  }
}

inline bool VerifyUseCaseInputVector(::flatbuffers::Verifier &verifier, const ::flatbuffers::Vector<::flatbuffers::Offset<void>> *values, const ::flatbuffers::Vector<UseCaseInput> *types) {
  if (!values || !types) return !values && !types;
  if (values->size() != types->size()) return false;
  for (::flatbuffers::uoffset_t i = 0; i < values->size(); ++i) {
    if (!VerifyUseCaseInput(
        verifier,  values->Get(i), types->GetEnum<UseCaseInput>(i))) {
      return false;
    }
  }
  return true;
}

inline const UseCase *GetUseCase(const void *buf) {
  return ::flatbuffers::GetRoot<UseCase>(buf);
}

inline const UseCase *GetSizePrefixedUseCase(const void *buf) {
  return ::flatbuffers::GetSizePrefixedRoot<UseCase>(buf);
}

inline bool VerifyUseCaseBuffer(
    ::flatbuffers::Verifier &verifier) {
  return verifier.VerifyBuffer<UseCase>(nullptr);
}

inline bool VerifySizePrefixedUseCaseBuffer(
    ::flatbuffers::Verifier &verifier) {
  return verifier.VerifySizePrefixedBuffer<UseCase>(nullptr);
}

inline void FinishUseCaseBuffer(
    ::flatbuffers::FlatBufferBuilder &fbb,
    ::flatbuffers::Offset<UseCase> root) {
  fbb.Finish(root);
}

inline void FinishSizePrefixedUseCaseBuffer(
    ::flatbuffers::FlatBufferBuilder &fbb,
    ::flatbuffers::Offset<UseCase> root) {
  fbb.FinishSizePrefixed(root);
}

#endif  // FLATBUFFERS_GENERATED_USECASE_H_
