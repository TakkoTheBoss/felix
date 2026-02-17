#include <sqlite3.h>

// OpenSSL 3.x deprecates the low-level SHA256_* APIs.
// Use the EVP interface to avoid deprecation warnings.
#include <openssl/evp.h>

#include <unicode/unistr.h>
#include <unicode/normalizer2.h>
#include <unicode/errorcode.h>

// JSON dependency: nlohmann/json (header-only). Prefer system install, fall back to local json.hpp.
#if __has_include(<nlohmann/json.hpp>)
  #include <nlohmann/json.hpp>
#elif __has_include("json.hpp")
  #include "json.hpp"
#else
  #error "Missing dependency: nlohmann/json. Install it (provides <nlohmann/json.hpp>) or place json.hpp alongside this source."
#endif


#include <algorithm>
#include <array>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <exception>
#include <fstream>
#include <functional>
#include <iostream>
#include <limits>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
//#include <span>

using json = nlohmann::json;

// ------------------------------------------------------------
// Felix MVP (SQLite-backed) with:
// - Strict typing (no inference): key=type:value
// - NDJSON ingestion
// - Snapshot + time-window queries
// - ICU NFC canonicalization for text
// ------------------------------------------------------------

static inline std::string trim_copy(std::string_view sv) {
  size_t b = 0;
  while (b < sv.size() && std::isspace(static_cast<unsigned char>(sv[b]))) b++;
  size_t e = sv.size();
  while (e > b && std::isspace(static_cast<unsigned char>(sv[e - 1]))) e--;
  return std::string(sv.substr(b, e - b));
}

static inline void require_utf8(std::string_view s, const char* what) {
  icu::UnicodeString u = icu::UnicodeString::fromUTF8(icu::StringPiece(s.data(), (int)s.size()));
  std::string round;
  u.toUTF8String(round);
  if (round.size() != s.size() || round != std::string(s)) {
    throw std::runtime_error(std::string("invalid UTF-8 in ") + what);
  }
}

static inline std::vector<uint8_t> base64_decode_strict(const std::string& b64) {
  std::string s;
  s.reserve(b64.size());
  for (unsigned char c : b64) {
    if (c == ' ' || c == '\t' || c == '\r' || c == '\n') continue;
    s.push_back((char)c);
  }
  if (s.empty()) return {};

  std::vector<uint8_t> out((s.size() * 3) / 4 + 4);
  int n = EVP_DecodeBlock(out.data(),
                          reinterpret_cast<const unsigned char*>(s.data()),
                          (int)s.size());
  if (n < 0) throw std::runtime_error("invalid base64 for bytes");
  out.resize((size_t)n);

  size_t pad = 0;
  if (!s.empty() && s.back() == '=') pad++;
  if (s.size() >= 2 && s[s.size() - 2] == '=') pad++;
  if (pad) {
    if (out.size() < pad) throw std::runtime_error("invalid base64 padding for bytes");
    out.resize(out.size() - pad);
  }
  return out;
}

static inline std::string canonicalize_uuid(std::string_view in) {
  std::string s = trim_copy(in);
  if (s.size() != 36) throw std::runtime_error("invalid uuid length");
  auto is_hex = [](char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
  };
  for (size_t i = 0; i < s.size(); i++) {
    char c = s[i];
    if (i == 8 || i == 13 || i == 18 || i == 23) {
      if (c != '-') throw std::runtime_error("invalid uuid format");
      continue;
    }
    if (!is_hex(c)) throw std::runtime_error("invalid uuid format");
    s[i] = (char)std::tolower((unsigned char)c);
  }
  return s;
}

static inline std::string nfc_normalize_utf8(std::string_view utf8_in) {
  // ICU NFC normalization
  UErrorCode status = U_ZERO_ERROR;
  const icu::Normalizer2* norm = icu::Normalizer2::getNFCInstance(status);
  if (U_FAILURE(status) || norm == nullptr) {
    throw std::runtime_error("ICU: failed to get NFC normalizer");
  }

  icu::UnicodeString u = icu::UnicodeString::fromUTF8(icu::StringPiece(utf8_in.data(), (int)utf8_in.size()));
  icu::UnicodeString out;
  status = U_ZERO_ERROR;
  norm->normalize(u, out, status);
  if (U_FAILURE(status)) {
    throw std::runtime_error("ICU: NFC normalize failed");
  }

  std::string utf8_out;
  out.toUTF8String(utf8_out);
  return utf8_out;
}

static inline std::array<uint8_t, 32> sha256_bytes(const uint8_t* data, size_t len) {
  std::array<uint8_t, 32> out{};

  // EVP digest calculation
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (!ctx) throw std::runtime_error("OpenSSL: EVP_MD_CTX_new failed");

  unsigned int out_len = 0;
  if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1 ||
      EVP_DigestUpdate(ctx, data, len) != 1 ||
      EVP_DigestFinal_ex(ctx, out.data(), &out_len) != 1) {
    EVP_MD_CTX_free(ctx);
    throw std::runtime_error("OpenSSL: EVP sha256 digest failed");
  }

  EVP_MD_CTX_free(ctx);
  if (out_len != out.size()) {
    throw std::runtime_error("OpenSSL: unexpected SHA-256 digest length");
  }
  return out;
}

// Type tags and versioning for hashing/tag mapping.
// NOTE: These are declared here so helper functions can use them without requiring <span>.
enum class LogicalType : uint8_t {
  Null,
  Bool,
  Int,
  Float,
  Text,
  Bytes,
  Uuid,
  JsonReserved
};

enum class TagMapVersion : uint8_t { LegacyV02, FelixV03 };
enum class HashFormatVersion : uint8_t { LegacyNoSep, FelixV03Sep };

static inline uint8_t type_tag_byte(TagMapVersion v, LogicalType t);



static inline std::array<uint8_t, 32> sha256_typed(TagMapVersion tagmap,
                                                         HashFormatVersion hfmt,
                                                         LogicalType logical_type,
                                                         const uint8_t* canon_bytes,
                                                         size_t canon_len) {
  const uint8_t tag = type_tag_byte(tagmap, logical_type);
  std::vector<uint8_t> buf;
  buf.reserve(1 + (hfmt == HashFormatVersion::FelixV03Sep ? 1 : 0) + canon_len);
  buf.push_back(tag);
  if (hfmt == HashFormatVersion::FelixV03Sep) buf.push_back(0x00);
  buf.insert(buf.end(), canon_bytes, canon_bytes + canon_len);
  return sha256_bytes(buf.data(), buf.size());
}


static inline std::vector<uint8_t> bytes_of(std::string_view s) {
  return std::vector<uint8_t>(s.begin(), s.end());
}

// hex_of() removed (was unused in the MVP).


static inline uint8_t type_tag_byte(TagMapVersion v, LogicalType t) {
  if (v == TagMapVersion::LegacyV02) {
    // Legacy mapping used by early Felix MVP DBs.
    // Text=1, Int=2, Float=3, Bool=4, Null=5, Json=6
    switch (t) {
      case LogicalType::Text: return 1;
      case LogicalType::Int: return 2;
      case LogicalType::Float: return 3;
      case LogicalType::Bool: return 4;
      case LogicalType::Null: return 5;
      case LogicalType::JsonReserved: return 6;
      default: throw std::runtime_error("type not supported by legacy tag map");
    }
  }

  // Felix v0.3 normative mapping.
  switch (t) {
    case LogicalType::Null: return 0x00;
    case LogicalType::Bool: return 0x01;
    case LogicalType::Int: return 0x02;
    case LogicalType::Float: return 0x03;
    case LogicalType::Text: return 0x04;
    case LogicalType::Bytes: return 0x05;
    case LogicalType::Uuid: return 0x06;
    case LogicalType::JsonReserved: return 0x07;
  }
  return 0xFF;
}


static inline LogicalType logical_type_from_tag(TagMapVersion v, uint8_t tag) {
  if (v == TagMapVersion::LegacyV02) {
    switch (tag) {
      case 1: return LogicalType::Text;
      case 2: return LogicalType::Int;
      case 3: return LogicalType::Float;
      case 4: return LogicalType::Bool;
      case 5: return LogicalType::Null;
      case 6: return LogicalType::JsonReserved;
      default: throw std::runtime_error("unknown legacy type tag");
    }
  }
  switch (tag) {
    case 0x00: return LogicalType::Null;
    case 0x01: return LogicalType::Bool;
    case 0x02: return LogicalType::Int;
    case 0x03: return LogicalType::Float;
    case 0x04: return LogicalType::Text;
    case 0x05: return LogicalType::Bytes;
    case 0x06: return LogicalType::Uuid;
    case 0x07: return LogicalType::JsonReserved;
    default: throw std::runtime_error("unknown v0.3 type tag");
  }
}

static inline std::string type_name(LogicalType t) {
  switch (t) {
    case LogicalType::Null: return "null";
    case LogicalType::Bool: return "bool";
    case LogicalType::Int: return "int";
    case LogicalType::Float: return "float";
    case LogicalType::Text: return "text";
    case LogicalType::Bytes: return "bytes";
    case LogicalType::Uuid: return "uuid";
    case LogicalType::JsonReserved: return "json";
  }
  return "unknown";
}

static inline LogicalType logical_type_from_string(std::string_view s) {
  if (s == "null") return LogicalType::Null;
  if (s == "bool") return LogicalType::Bool;
  if (s == "int") return LogicalType::Int;
  if (s == "float") return LogicalType::Float;
  if (s == "text") return LogicalType::Text;
  if (s == "bytes") return LogicalType::Bytes;
  if (s == "uuid") return LogicalType::Uuid;
  if (s == "json") return LogicalType::JsonReserved;
  throw std::runtime_error("unknown type: " + std::string(s));
}


static inline std::string type_to_string(LogicalType t) {
  switch (t) {
    case LogicalType::Null: return "null";
    case LogicalType::Bool: return "bool";
    case LogicalType::Int: return "int";
    case LogicalType::Float: return "float";
    case LogicalType::Text: return "text";
    case LogicalType::Bytes: return "bytes";
    case LogicalType::Uuid: return "uuid";
    case LogicalType::JsonReserved: return "json";
  }
  return "unknown";
}

static inline LogicalType parse_type(std::string_view s) {
  LogicalType t = logical_type_from_string(trim_copy(s));
  if (t == LogicalType::JsonReserved) {
    throw std::runtime_error("type json is reserved in Felix v0.3 and is not accepted by this implementation");
  }
  return t;
}

struct CanonValue {
  LogicalType logical_type{};
  // Exactly one of canon_text or canon_blob is used depending on logical_type.
  std::string canon_text;                 // for text, int, float, bool, null, uuid
  std::vector<uint8_t> canon_blob;        // for bytes
  std::array<uint8_t, 32> hash{};         // computed at insertion time based on DB format
};


static inline std::string canonicalize_float64(double d) {
  if (std::isnan(d)) throw std::runtime_error("NaN is not allowed for float");
  if (std::isinf(d)) return std::signbit(d) ? "-inf" : "inf";
  if (d == 0.0) return "0"; // normalizes -0 to 0

  // Use nlohmann::detail::to_chars for broad libstdc++ compatibility.
  char buf[128];
  char* end = nlohmann::detail::to_chars(buf, buf + sizeof(buf), d);
  if (end == nullptr) throw std::runtime_error("float canonicalization failed");
  std::string s(buf, end);

  // Lowercase exponent marker if present.
  for (char& c : s) if (c == 'E') c = 'e';

  // Trim trailing zeros after decimal point in mantissa.
  auto epos = s.find('e');
  std::string mant = (epos == std::string::npos) ? s : s.substr(0, epos);
  std::string exp  = (epos == std::string::npos) ? "" : s.substr(epos);

  auto dot = mant.find('.');
  if (dot != std::string::npos) {
    while (!mant.empty() && mant.back() == '0') mant.pop_back();
    if (!mant.empty() && mant.back() == '.') mant.pop_back();
  }

  s = mant + exp;
  if (s == "-0") s = "0";
  return s;
}

static inline CanonValue canonicalize_typed_value(LogicalType t, const json& v) {
  CanonValue cv{};
  cv.logical_type = t;

  if (t == LogicalType::Null) {
    cv.canon_text = "null";
    return cv;
  }

  if (t == LogicalType::Bool) {
    if (!v.is_boolean()) throw std::runtime_error("bool value must be JSON boolean");
    cv.canon_text = v.get<bool>() ? "true" : "false";
    return cv;
  }

  if (t == LogicalType::Int) {
    if (!v.is_number_integer()) throw std::runtime_error("int value must be JSON integer");
    int64_t x = v.get<int64_t>();
    cv.canon_text = std::to_string(x);
    return cv;
  }

  if (t == LogicalType::Float) {
    if (!v.is_number()) throw std::runtime_error("float value must be JSON number");
    double d = v.get<double>();
    cv.canon_text = canonicalize_float64(d);
    return cv;
  }

  if (t == LogicalType::Text) {
    if (!v.is_string()) throw std::runtime_error("text value must be JSON string");
    std::string raw = v.get<std::string>();
    require_utf8(raw, "text");
    std::string s = trim_copy(raw);
    cv.canon_text = nfc_normalize_utf8(s);
    return cv;
  }

  if (t == LogicalType::Uuid) {
    if (!v.is_string()) throw std::runtime_error("uuid value must be JSON string");
    std::string raw = v.get<std::string>();
    require_utf8(raw, "uuid");
    cv.canon_text = canonicalize_uuid(raw);
    return cv;
  }

  if (t == LogicalType::Bytes) {
    if (!v.is_string()) throw std::runtime_error("bytes value must be base64 string");
    std::string b64 = v.get<std::string>();
    require_utf8(b64, "bytes-base64");
    cv.canon_blob = base64_decode_strict(b64);
    return cv;
  }

  if (t == LogicalType::JsonReserved) {
    throw std::runtime_error("type json is reserved in Felix v0.3");
  }

  throw std::runtime_error("unsupported type");
}

static inline CanonValue canonicalize_typed_value(LogicalType t, std::string_view raw_value_text) {
  CanonValue cv{};
  cv.logical_type = t;

  std::string raw = std::string(raw_value_text);

  if (t == LogicalType::Null) {
    cv.canon_text = "null";
    return cv;
  }

  if (t == LogicalType::Bool) {
    std::string s = trim_copy(raw);
    if (s != "true" && s != "false") throw std::runtime_error("bool must be true or false");
    cv.canon_text = s;
    return cv;
  }

  if (t == LogicalType::Int) {
    std::string s = trim_copy(raw);
    if (s.empty()) throw std::runtime_error("int cannot be empty");
    size_t idx = 0;
    long long vll = 0;
    try {
      vll = std::stoll(s, &idx, 10);
    } catch (...) {
      throw std::runtime_error("invalid int");
    }
    if (idx != s.size()) throw std::runtime_error("invalid int");
    cv.canon_text = std::to_string((int64_t)vll);
    return cv;
  }

  if (t == LogicalType::Float) {
    std::string s = trim_copy(raw);
    if (s == "inf" || s == "+inf") { cv.canon_text = "inf"; return cv; }
    if (s == "-inf") { cv.canon_text = "-inf"; return cv; }
    if (s == "nan" || s == "NaN" || s == "NAN") throw std::runtime_error("NaN is not allowed for float");
    char* endp = nullptr;
    errno = 0;
    double d = std::strtod(s.c_str(), &endp);
    if (endp == s.c_str() || *endp != '\0' || errno == ERANGE) throw std::runtime_error("invalid float");
    cv.canon_text = canonicalize_float64(d);
    return cv;
  }

  if (t == LogicalType::Text) {
    require_utf8(raw, "text");
    std::string s = trim_copy(raw);
    cv.canon_text = nfc_normalize_utf8(s);
    return cv;
  }

  if (t == LogicalType::Uuid) {
    require_utf8(raw, "uuid");
    cv.canon_text = canonicalize_uuid(raw);
    return cv;
  }

  if (t == LogicalType::Bytes) {
    require_utf8(raw, "bytes-base64");
    cv.canon_blob = base64_decode_strict(std::string(raw));
    return cv;
  }

  if (t == LogicalType::JsonReserved) {
    throw std::runtime_error("type json is reserved in Felix v0.3");
  }

  throw std::runtime_error("unsupported type");
}

static inline std::array<uint8_t, 32> canonicalize_field_hash(std::string_view field_name) {
  // fields: trim + NFC normalization, case-sensitive
  std::string canon = nfc_normalize_utf8(trim_copy(field_name));
  // Field hashing is implementation-internal; keep stable within this implementation.
  std::string prefix = "field\0";
  std::vector<uint8_t> buf(prefix.begin(), prefix.end());
  buf.insert(buf.end(), canon.begin(), canon.end());
  return sha256_bytes(reinterpret_cast<const uint8_t*>(buf.data()), buf.size());
}

// ------------------------------------------------------------
// SQLite helpers
// ------------------------------------------------------------

struct Stmt {
  sqlite3_stmt* s{nullptr};
  ~Stmt() { if (s) sqlite3_finalize(s); }
};

static inline void check_sql(int rc, sqlite3* db, const char* what) {
  if (rc != SQLITE_OK && rc != SQLITE_DONE && rc != SQLITE_ROW) {
    std::ostringstream oss;
    oss << what << " failed: " << sqlite3_errmsg(db) << " (rc=" << rc << ")";
    throw std::runtime_error(oss.str());
  }
}

static inline void exec_sql(sqlite3* db, const char* sql) {
  char* err = nullptr;
  int rc = sqlite3_exec(db, sql, nullptr, nullptr, &err);
  if (rc != SQLITE_OK) {
    std::string msg = err ? err : "unknown error";
    sqlite3_free(err);
    throw std::runtime_error("sqlite exec failed: " + msg);
  }
}

static inline void begin_tx(sqlite3* db) { exec_sql(db, "BEGIN IMMEDIATE;"); }
static inline void commit_tx(sqlite3* db){ exec_sql(db, "COMMIT;"); }
static inline void rollback_tx(sqlite3* db){ exec_sql(db, "ROLLBACK;"); }

// ------------------------------------------------------------
// Felix SQLite Store
// ------------------------------------------------------------

struct FactRow {
  uint64_t record_id{};
  uint32_t field_id{};
  uint64_t value_id{};
  int64_t ts_ms{};
};

struct FieldRow {
  uint32_t field_id{};
  std::string name_canon{};
};

struct ValueRow {
  uint64_t value_id{};
  LogicalType type{};
  std::string canon_text{};
};

class FelixSqlite {
public:
  explicit FelixSqlite(const std::string& path) {
    int rc = sqlite3_open(path.c_str(), &db_);
    if (rc != SQLITE_OK) throw std::runtime_error("failed to open sqlite db");

    exec_sql(db_, "PRAGMA foreign_keys = ON;");
    exec_sql(db_, "PRAGMA journal_mode = WAL;");
    exec_sql(db_, "PRAGMA synchronous = NORMAL;");
    ensure_meta_table();
    load_format_defaults();
  }

  ~FelixSqlite() {
    if (db_) sqlite3_close(db_);
  }

  void init_schema() {
    exec_sql(db_, R"SQL(
      CREATE TABLE IF NOT EXISTS fields (
        field_id    INTEGER PRIMARY KEY,
        name_canon  TEXT NOT NULL,
        hash        BLOB NOT NULL UNIQUE
      );

      CREATE TABLE IF NOT EXISTS f_values (
        value_id    INTEGER PRIMARY KEY,
        type_tag    INTEGER NOT NULL,
        canon_text  TEXT,
        canon_blob  BLOB,
        hash        BLOB NOT NULL UNIQUE
      );

      CREATE TABLE IF NOT EXISTS records (
        record_id   INTEGER PRIMARY KEY,
        created_ts  INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS facts (
        record_id  INTEGER NOT NULL,
        field_id   INTEGER NOT NULL,
        value_id   INTEGER NOT NULL,
        ts         INTEGER NOT NULL,
        PRIMARY KEY (record_id, field_id, ts),
        FOREIGN KEY (record_id) REFERENCES records(record_id),
        FOREIGN KEY (field_id)  REFERENCES fields(field_id),
        FOREIGN KEY (value_id)  REFERENCES f_values(value_id)
      );

      CREATE TABLE IF NOT EXISTS current_facts (
        record_id  INTEGER NOT NULL,
        field_id   INTEGER NOT NULL,
        value_id   INTEGER NOT NULL,
        ts         INTEGER NOT NULL,
        PRIMARY KEY (record_id, field_id),
        FOREIGN KEY (record_id) REFERENCES records(record_id),
        FOREIGN KEY (field_id)  REFERENCES fields(field_id),
        FOREIGN KEY (value_id)  REFERENCES f_values(value_id)
      );

      CREATE INDEX IF NOT EXISTS facts_by_value ON facts(value_id);
      CREATE INDEX IF NOT EXISTS facts_by_field_value ON facts(field_id, value_id);
      CREATE INDEX IF NOT EXISTS facts_by_record_field_ts ON facts(record_id, field_id, ts);
      CREATE INDEX IF NOT EXISTS current_by_field_value ON current_facts(field_id, value_id);
      CREATE INDEX IF NOT EXISTS facts_by_ts ON facts(ts);
    )SQL");

    // Declare this database as Felix v0.3 format for new DBs.
    meta_set("felix_spec", "0.3");
    meta_set("tag_map", "felix_v03");
    meta_set("hash_format", "felix_v03_sep");
    load_format_defaults();

    ensure_null_value();
  }

  void with_tx(const std::function<void()>& fn) {
    begin_tx(db_);
    try {
      fn();
      commit_tx(db_);
    } catch (...) {
      rollback_tx(db_);
      throw;
    }
  }

  void ensure_record(uint64_t record_id, int64_t created_ts_ms) {
    Stmt st;
    check_sql(sqlite3_prepare_v2(db_, "INSERT OR IGNORE INTO records(record_id, created_ts) VALUES(?,?);", -1, &st.s, nullptr),
              db_, "prepare ensure_record");
    sqlite3_bind_int64(st.s, 1, (sqlite3_int64)record_id);
    sqlite3_bind_int64(st.s, 2, (sqlite3_int64)created_ts_ms);
    check_sql(sqlite3_step(st.s), db_, "ensure_record step");
  }

  uint32_t get_or_create_field(std::string_view field_name) {
    if (field_name.size() > 256) throw std::runtime_error("field name exceeds 256 bytes");
    require_utf8(field_name, "field name");

    std::string canon = nfc_normalize_utf8(trim_copy(field_name));
    auto h = canonicalize_field_hash(canon);

    {
      Stmt st;
      check_sql(sqlite3_prepare_v2(db_, "INSERT OR IGNORE INTO fields(name_canon, hash) VALUES(?,?);", -1, &st.s, nullptr),
                db_, "prepare field insert");
      sqlite3_bind_text(st.s, 1, canon.c_str(), -1, SQLITE_TRANSIENT);
      sqlite3_bind_blob(st.s, 2, h.data(), (int)h.size(), SQLITE_TRANSIENT);
      check_sql(sqlite3_step(st.s), db_, "field insert step");
    }

    {
      Stmt st;
      check_sql(sqlite3_prepare_v2(db_, "SELECT field_id FROM fields WHERE hash=?;", -1, &st.s, nullptr),
                db_, "prepare field select");
      sqlite3_bind_blob(st.s, 1, h.data(), (int)h.size(), SQLITE_TRANSIENT);
      int rc = sqlite3_step(st.s);
      check_sql(rc, db_, "field select step");
      if (rc == SQLITE_ROW) return (uint32_t)sqlite3_column_int(st.s, 0);
    }

    throw std::runtime_error("field insert/select failed unexpectedly");
  }

  uint64_t get_or_create_value(const CanonValue& cv_in) {
    CanonValue cv = cv_in;

    // Resource limits (spec recommended defaults).
    if (cv.logical_type == LogicalType::Text && cv.canon_text.size() > (1u * 1024u * 1024u)) throw std::runtime_error("text value exceeds 1 MiB");
    if (cv.logical_type == LogicalType::Bytes && cv.canon_blob.size() > (4u * 1024u * 1024u)) throw std::runtime_error("bytes value exceeds 4 MiB");

    const uint8_t* canon_ptr = nullptr;
    size_t canon_len = 0;
    if (cv.logical_type == LogicalType::Bytes) {
      canon_ptr = cv.canon_blob.data();
      canon_len = cv.canon_blob.size();
    } else {
      canon_ptr = reinterpret_cast<const uint8_t*>(cv.canon_text.data());
      canon_len = cv.canon_text.size();
    }

    cv.hash = sha256_typed(tagmap_, hashfmt_, cv.logical_type, canon_ptr, canon_len);

    {
      Stmt st;
      check_sql(sqlite3_prepare_v2(db_,
                                  "INSERT OR IGNORE INTO f_values(type_tag, canon_text, canon_blob, hash) VALUES(?,?,?,?);",
                                  -1, &st.s, nullptr),
                db_, "prepare value insert");

      sqlite3_bind_int(st.s, 1, (int)type_tag_byte(tagmap_, cv.logical_type));

      if (cv.logical_type == LogicalType::Bytes) {
        sqlite3_bind_null(st.s, 2);
        sqlite3_bind_blob(st.s, 3,
                          cv.canon_blob.empty() ? "" : (const void*)cv.canon_blob.data(),
                          (int)cv.canon_blob.size(),
                          SQLITE_TRANSIENT);
      } else {
        sqlite3_bind_text(st.s, 2, cv.canon_text.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_null(st.s, 3);
      }

      sqlite3_bind_blob(st.s, 4, cv.hash.data(), (int)cv.hash.size(), SQLITE_TRANSIENT);
      check_sql(sqlite3_step(st.s), db_, "value insert step");
    }

    {
      Stmt st;
      check_sql(sqlite3_prepare_v2(db_, "SELECT value_id FROM f_values WHERE hash=?;", -1, &st.s, nullptr),
                db_, "prepare value select");
      sqlite3_bind_blob(st.s, 1, cv.hash.data(), (int)cv.hash.size(), SQLITE_TRANSIENT);
      int rc = sqlite3_step(st.s);
      check_sql(rc, db_, "value select step");
      if (rc == SQLITE_ROW) return (uint64_t)sqlite3_column_int64(st.s, 0);
    }

    throw std::runtime_error("value insert/select failed unexpectedly");
  }

  std::optional<std::pair<uint64_t, int64_t>> get_current(uint64_t record_id, uint32_t field_id) {
    Stmt st;
    check_sql(sqlite3_prepare_v2(db_, "SELECT value_id, ts FROM current_facts WHERE record_id=? AND field_id=?;",
                                 -1, &st.s, nullptr),
              db_, "prepare get_current");
    sqlite3_bind_int64(st.s, 1, (sqlite3_int64)record_id);
    sqlite3_bind_int(st.s, 2, (int)field_id);
    int rc = sqlite3_step(st.s);
    check_sql(rc, db_, "get_current step");
    if (rc == SQLITE_ROW) {
      uint64_t vid = (uint64_t)sqlite3_column_int64(st.s, 0);
      int64_t ts = (int64_t)sqlite3_column_int64(st.s, 1);
      return std::make_pair(vid, ts);
    }
    return std::nullopt;
  }

  void insert_fact(const FactRow& f) {
    Stmt st;
    check_sql(sqlite3_prepare_v2(db_, "INSERT INTO facts(record_id, field_id, value_id, ts) VALUES(?,?,?,?);",
                                 -1, &st.s, nullptr),
              db_, "prepare insert_fact");
    sqlite3_bind_int64(st.s, 1, (sqlite3_int64)f.record_id);
    sqlite3_bind_int(st.s, 2, (int)f.field_id);
    sqlite3_bind_int64(st.s, 3, (sqlite3_int64)f.value_id);
    sqlite3_bind_int64(st.s, 4, (sqlite3_int64)f.ts_ms);
    check_sql(sqlite3_step(st.s), db_, "insert_fact step");
  }

  void upsert_current_if_newer(const FactRow& f) {
    Stmt st;
    check_sql(sqlite3_prepare_v2(db_,
      "INSERT INTO current_facts(record_id, field_id, value_id, ts) "
      "VALUES(?,?,?,?) "
      "ON CONFLICT(record_id, field_id) DO UPDATE SET "
      "value_id=excluded.value_id, ts=excluded.ts "
      "WHERE excluded.ts >= current_facts.ts;",
      -1, &st.s, nullptr),
      db_, "prepare upsert_current_if_newer");

    sqlite3_bind_int64(st.s, 1, (sqlite3_int64)f.record_id);
    sqlite3_bind_int(st.s, 2, (int)f.field_id);
    sqlite3_bind_int64(st.s, 3, (sqlite3_int64)f.value_id);
    sqlite3_bind_int64(st.s, 4, (sqlite3_int64)f.ts_ms);
    check_sql(sqlite3_step(st.s), db_, "upsert_current_if_newer step");
  }

  std::vector<uint64_t> query_current_eq(uint32_t field_id, uint64_t value_id) {
    Stmt st;
    check_sql(sqlite3_prepare_v2(db_, "SELECT record_id FROM current_facts WHERE field_id=? AND value_id=?;",
                                 -1, &st.s, nullptr),
              db_, "prepare query_current_eq");
    sqlite3_bind_int(st.s, 1, (int)field_id);
    sqlite3_bind_int64(st.s, 2, (sqlite3_int64)value_id);

    std::vector<uint64_t> out;
    for (;;) {
      int rc = sqlite3_step(st.s);
      if (rc == SQLITE_DONE) break;
      check_sql(rc, db_, "query_current_eq step");
      out.push_back((uint64_t)sqlite3_column_int64(st.s, 0));
    }
    return out;
  }

  std::vector<uint64_t> query_ever_eq(uint32_t field_id, uint64_t value_id) {
    Stmt st;
    check_sql(sqlite3_prepare_v2(db_, "SELECT DISTINCT record_id FROM facts WHERE field_id=? AND value_id=?;",
                                 -1, &st.s, nullptr),
              db_, "prepare query_ever_eq");
    sqlite3_bind_int(st.s, 1, (int)field_id);
    sqlite3_bind_int64(st.s, 2, (sqlite3_int64)value_id);

    std::vector<uint64_t> out;
    for (;;) {
      int rc = sqlite3_step(st.s);
      if (rc == SQLITE_DONE) break;
      check_sql(rc, db_, "query_ever_eq step");
      out.push_back((uint64_t)sqlite3_column_int64(st.s, 0));
    }
    return out;
  }

  std::vector<FactRow> query_facts_window(int64_t t1, int64_t t2, std::optional<uint64_t> record_filter) {
    std::vector<FactRow> out;
    Stmt st;

    if (record_filter) {
      check_sql(sqlite3_prepare_v2(db_,
        "SELECT record_id, field_id, value_id, ts "
        "FROM facts WHERE ts BETWEEN ? AND ? AND record_id=? ORDER BY ts;",
        -1, &st.s, nullptr),
        db_, "prepare query_facts_window(record)");
      sqlite3_bind_int64(st.s, 1, (sqlite3_int64)t1);
      sqlite3_bind_int64(st.s, 2, (sqlite3_int64)t2);
      sqlite3_bind_int64(st.s, 3, (sqlite3_int64)*record_filter);
    } else {
      check_sql(sqlite3_prepare_v2(db_,
        "SELECT record_id, field_id, value_id, ts "
        "FROM facts WHERE ts BETWEEN ? AND ? ORDER BY ts;",
        -1, &st.s, nullptr),
        db_, "prepare query_facts_window");
      sqlite3_bind_int64(st.s, 1, (sqlite3_int64)t1);
      sqlite3_bind_int64(st.s, 2, (sqlite3_int64)t2);
    }

    for (;;) {
      int rc = sqlite3_step(st.s);
      if (rc == SQLITE_DONE) break;
      check_sql(rc, db_, "query_facts_window step");
      FactRow f{};
      f.record_id = (uint64_t)sqlite3_column_int64(st.s, 0);
      f.field_id  = (uint32_t)sqlite3_column_int(st.s, 1);
      f.value_id  = (uint64_t)sqlite3_column_int64(st.s, 2);
      f.ts_ms     = (int64_t)sqlite3_column_int64(st.s, 3);
      out.push_back(f);
    }
    return out;
  }

  std::vector<FactRow> snapshot_at(uint64_t record_id, int64_t t) {
    // Latest per field where ts <= t
    Stmt st;
    check_sql(sqlite3_prepare_v2(db_,
      "SELECT f.record_id, f.field_id, f.value_id, f.ts "
      "FROM facts f "
      "JOIN ("
      "  SELECT field_id, MAX(ts) AS max_ts "
      "  FROM facts "
      "  WHERE record_id=? AND ts <= ? "
      "  GROUP BY field_id"
      ") latest "
      "ON latest.field_id = f.field_id AND latest.max_ts = f.ts "
      "WHERE f.record_id=?;",
      -1, &st.s, nullptr),
      db_, "prepare snapshot_at");

    sqlite3_bind_int64(st.s, 1, (sqlite3_int64)record_id);
    sqlite3_bind_int64(st.s, 2, (sqlite3_int64)t);
    sqlite3_bind_int64(st.s, 3, (sqlite3_int64)record_id);

    std::vector<FactRow> out;
    for (;;) {
      int rc = sqlite3_step(st.s);
      if (rc == SQLITE_DONE) break;
      check_sql(rc, db_, "snapshot_at step");
      FactRow f{};
      f.record_id = (uint64_t)sqlite3_column_int64(st.s, 0);
      f.field_id  = (uint32_t)sqlite3_column_int(st.s, 1);
      f.value_id  = (uint64_t)sqlite3_column_int64(st.s, 2);
      f.ts_ms     = (int64_t)sqlite3_column_int64(st.s, 3);
      out.push_back(f);
    }
    return out;
  }

  FieldRow get_field(uint32_t field_id) {
    Stmt st;
    check_sql(sqlite3_prepare_v2(db_, "SELECT field_id, name_canon FROM fields WHERE field_id=?;", -1, &st.s, nullptr),
              db_, "prepare get_field");
    sqlite3_bind_int(st.s, 1, (int)field_id);
    int rc = sqlite3_step(st.s);
    check_sql(rc, db_, "get_field step");
    if (rc != SQLITE_ROW) throw std::runtime_error("unknown field_id");
    FieldRow fr{};
    fr.field_id = (uint32_t)sqlite3_column_int(st.s, 0);
    fr.name_canon = (const char*)sqlite3_column_text(st.s, 1);
    return fr;
  }

  ValueRow get_value(uint64_t value_id) {
    Stmt st;
    check_sql(sqlite3_prepare_v2(db_, "SELECT value_id, type_tag, canon_text FROM f_values WHERE value_id=?;", -1, &st.s, nullptr),
              db_, "prepare get_value");
    sqlite3_bind_int64(st.s, 1, (sqlite3_int64)value_id);
    int rc = sqlite3_step(st.s);
    check_sql(rc, db_, "get_value step");
    if (rc != SQLITE_ROW) throw std::runtime_error("unknown value_id");
    ValueRow vr{};
    vr.value_id = (uint64_t)sqlite3_column_int64(st.s, 0);
    uint8_t tag = (uint8_t)sqlite3_column_int(st.s, 1);
    vr.type = logical_type_from_tag(tagmap_, tag);
    const unsigned char* txt = sqlite3_column_text(st.s, 2);
    vr.canon_text = txt ? (const char*)txt : "";
    return vr;
  }

  void rebuild_current_facts() {
    exec_sql(db_, "DELETE FROM current_facts;");
    exec_sql(db_, R"SQL(
      INSERT INTO current_facts(record_id, field_id, value_id, ts)
      SELECT f.record_id, f.field_id, f.value_id, f.ts
      FROM facts f
      JOIN (
        SELECT record_id, field_id, MAX(ts) AS max_ts
        FROM facts
        GROUP BY record_id, field_id
      ) latest
      ON latest.record_id = f.record_id
      AND latest.field_id  = f.field_id
      AND latest.max_ts    = f.ts;
    )SQL");
  }

  uint64_t null_value_id() const { return null_value_id_; }

private:
  sqlite3* db_{nullptr};
  TagMapVersion tagmap_{TagMapVersion::LegacyV02};
  HashFormatVersion hashfmt_{HashFormatVersion::LegacyNoSep};
  uint64_t null_value_id_{0};

  void ensure_meta_table() {
    exec_sql(db_, "CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);");
  }

  std::optional<std::string> meta_get(std::string_view k) {
    Stmt st;
    check_sql(sqlite3_prepare_v2(db_, "SELECT v FROM meta WHERE k=?;", -1, &st.s, nullptr), db_, "prepare meta_get");
    sqlite3_bind_text(st.s, 1, std::string(k).c_str(), -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st.s);
    if (rc == SQLITE_ROW) {
      const unsigned char* t = sqlite3_column_text(st.s, 0);
      return t ? std::optional<std::string>((const char*)t) : std::optional<std::string>("");
    }
    check_sql(rc, db_, "meta_get step");
    return std::nullopt;
  }

  void meta_set(std::string_view k, std::string_view v) {
    Stmt st;
    check_sql(sqlite3_prepare_v2(db_,
                                "INSERT INTO meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v;",
                                -1, &st.s, nullptr),
              db_, "prepare meta_set");
    sqlite3_bind_text(st.s, 1, std::string(k).c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st.s, 2, std::string(v).c_str(), -1, SQLITE_TRANSIENT);
    check_sql(sqlite3_step(st.s), db_, "meta_set step");
  }

  void load_format_defaults() {
    auto hv = meta_get("hash_format");
    auto tv = meta_get("tag_map");
    if (!hv.has_value() || !tv.has_value()) {
      tagmap_ = TagMapVersion::LegacyV02;
      hashfmt_ = HashFormatVersion::LegacyNoSep;
      return;
    }
    tagmap_ = (*tv == "felix_v03") ? TagMapVersion::FelixV03 : TagMapVersion::LegacyV02;
    hashfmt_ = (*hv == "felix_v03_sep") ? HashFormatVersion::FelixV03Sep : HashFormatVersion::LegacyNoSep;
  }

  void ensure_null_value() {
    CanonValue cv{};
    cv.logical_type = LogicalType::Null;
    cv.canon_text = "null";
    null_value_id_ = get_or_create_value(cv);
  }
};

// ------------------------------------------------------------
// Engine: temporality policy + ingest
// ------------------------------------------------------------

enum class TemporalityMode { EventDriven, ObservationDriven };

static inline TemporalityMode parse_mode(std::string_view s) {
  if (s == "event") return TemporalityMode::EventDriven;
  if (s == "observe") return TemporalityMode::ObservationDriven;
  throw std::runtime_error("mode must be 'event' or 'observe'");
}

struct IngestItem {
  std::string field_name;
  CanonValue value;
};

static inline std::pair<std::string, std::string> split_once(std::string_view s, char c) {
  auto pos = s.find(c);
  if (pos == std::string_view::npos) return {std::string(s), ""};
  return {std::string(s.substr(0, pos)), std::string(s.substr(pos + 1))};
}

static inline IngestItem parse_typed_kv(std::string_view token) {
  // token: FieldName=type:value
  auto eq = token.find('=');
  if (eq == std::string_view::npos) throw std::runtime_error("expected Field=type:value");
  std::string field = trim_copy(token.substr(0, eq));
  std::string rhs = std::string(token.substr(eq + 1));

  auto [type_s, value_s] = split_once(rhs, ':');
  LogicalType t = parse_type(trim_copy(type_s));
  CanonValue cv = canonicalize_typed_value(t, std::string_view(value_s));
  return {field, cv};
}

static void ingest_items(FelixSqlite& store,
                         uint64_t record_id,
                         int64_t ts_ms,
                         TemporalityMode mode,
                         const std::vector<IngestItem>& items) {
  store.with_tx([&]{
    store.ensure_record(record_id, ts_ms);

    if (items.size() > 256) throw std::runtime_error("fields per ingest exceeds 256");
    for (const auto& it : items) {
      uint32_t fid = store.get_or_create_field(it.field_name);
      uint64_t vid = store.get_or_create_value(it.value);

      if (mode == TemporalityMode::EventDriven) {
        auto cur = store.get_current(record_id, fid);
        if (cur && cur->first == vid) continue; // unchanged => no fact
      }

      FactRow f{};
      f.record_id = record_id;
      f.field_id = fid;
      f.value_id = vid;
      f.ts_ms = ts_ms;

      store.insert_fact(f);
      store.upsert_current_if_newer(f);
    }
  });
}

// ------------------------------------------------------------
// NDJSON ingestion format (strictly typed)
// Each line is one record update:
// {
//   "record_id": 5001,
//   "ts_ms": 1739539200000,
//   "mode": "event",               // optional, default provided by CLI
//   "fields": {
//     "First Name": {"t":"text", "v":"Luke"},
//     "Age": {"t":"int", "v":6},
//     "Favorite Animal": {"t":"text", "v":"Sheep Dog"},
//     "DeletedField": {"t":"null"}
//   }
// }
// ------------------------------------------------------------

static IngestItem item_from_field_json(const std::string& field_name, const json& j) {
  if (!j.is_object()) throw std::runtime_error("fields.<name> must be an object {t, v}");
  if (!j.contains("t")) throw std::runtime_error("fields.<name>.t missing");
  LogicalType t = parse_type(j.at("t").get<std::string>());

  json v = json(nullptr);
  if (t != LogicalType::Null) {
    if (!j.contains("v")) throw std::runtime_error("fields.<name>.v missing for non-null");
    v = j.at("v");
  }

  CanonValue cv = canonicalize_typed_value(t, v);
  return {field_name, cv};
}

static void ingest_ndjson_file(FelixSqlite& store, const std::string& path, TemporalityMode default_mode) {
  std::ifstream in(path);
  if (!in) throw std::runtime_error("failed to open ndjson file: " + path);

  std::string line;
  uint64_t lineno = 0;

  while (std::getline(in, line)) {
    if (line.size() > (2u * 1024u * 1024u)) throw std::runtime_error("NDJSON line exceeds 2 MiB");
    lineno++;
    std::string trimmed = trim_copy(line);
    if (trimmed.empty()) continue;

    json j;
    try {
      j = json::parse(trimmed);
    } catch (const std::exception& e) {
      throw std::runtime_error("NDJSON parse error at line " + std::to_string(lineno) + ": " + e.what());
    }

    if (!j.contains("record_id") || !j.contains("ts_ms") || !j.contains("fields")) {
      throw std::runtime_error("NDJSON line " + std::to_string(lineno) + " must contain record_id, ts_ms, fields");
    }

    uint64_t record_id = j.at("record_id").get<uint64_t>();
    int64_t ts_ms = j.at("ts_ms").get<int64_t>();
    TemporalityMode mode = default_mode;
    if (j.contains("mode")) mode = parse_mode(j.at("mode").get<std::string>());

    const json& fields = j.at("fields");
    if (!fields.is_object()) throw std::runtime_error("fields must be an object at line " + std::to_string(lineno));

    std::vector<IngestItem> items;
    items.reserve(fields.size());
    for (auto it = fields.begin(); it != fields.end(); ++it) {
      items.push_back(item_from_field_json(it.key(), it.value()));
    }

    ingest_items(store, record_id, ts_ms, mode, items);
  }
}

// ------------------------------------------------------------
// Output helpers (NDJSON / JSON)
// ------------------------------------------------------------

static json fact_to_json(FelixSqlite& store, const FactRow& f) {
  FieldRow fr = store.get_field(f.field_id);
  ValueRow vr = store.get_value(f.value_id);
  return json{
    {"record_id", f.record_id},
    {"field_id", f.field_id},
    {"field_name", fr.name_canon},
    {"value_id", f.value_id},
    {"type", type_to_string(vr.type)},
    {"canon", vr.canon_text},
    {"ts_ms", f.ts_ms}
  };
}

static json snapshot_to_json(FelixSqlite& store, uint64_t record_id, int64_t t, const std::vector<FactRow>& rows) {
  json out;
  out["record_id"] = record_id;
  out["ts_ms"] = t;
  json fields = json::object();

  for (const auto& f : rows) {
    FieldRow fr = store.get_field(f.field_id);
    ValueRow vr = store.get_value(f.value_id);
    fields[fr.name_canon] = json{
      {"field_id", f.field_id},
      {"value_id", f.value_id},
      {"type", type_to_string(vr.type)},
      {"canon", vr.canon_text},
      {"fact_ts_ms", f.ts_ms}
    };
  }

  out["fields"] = fields;
  return out;
}

// ------------------------------------------------------------
// CLI
// ------------------------------------------------------------

static void usage() {
  std::cerr <<
    "felixctl <db.sqlite> <command> [args]\n\n"
    "Commands:\n"
    "  init\n"
    "  ingest <record_id> <ts_ms> <mode:event|observe> Field=type:value [Field=type:value ...]\n"
    "  ingest_ndjson <file.ndjson> [default_mode:event|observe]\n"
    "  current_eq <field_name> <type:value>\n"
    "  ever_eq <field_name> <type:value>\n"
    "  facts_window <t1_ms> <t2_ms> [record_id]\n"
    "  snapshot <record_id> <t_ms>\n"
    "  rebuild_current\n\n"
    "Strict typing:\n"
    "  - CLI values MUST be provided as type:value\n"
    "  - Types: text|int|float|bool|null|json\n\n"
    "NDJSON format (per line):\n"
    "  {\"record_id\":5001,\"ts_ms\":1739539200000,\"mode\":\"event\",\"fields\":{\n"
    "     \"Age\":{\"t\":\"int\",\"v\":6},\n"
    "     \"Last Name\":{\"t\":\"text\",\"v\":\"Cat\"},\n"
    "     \"DeletedField\":{\"t\":\"null\"}\n"
    "  }}\n";
}

static CanonValue parse_cli_type_value(std::string_view tv) {
  auto [type_s, value_s] = split_once(tv, ':');
  LogicalType t = parse_type(trim_copy(type_s));
  return canonicalize_typed_value(t, std::string_view(value_s));
}

namespace felix {

int run_felix(int argc, char** argv) {
  try {
    if (argc < 3) { usage(); return 2; }

    std::string dbpath = argv[1];
    std::string cmd = argv[2];

    FelixSqlite store(dbpath);

    if (cmd == "init") {
      store.init_schema();
      std::cout << "ok: initialized schema\n";
      return 0;
    }

    store.init_schema();

    if (cmd == "ingest") {
      if (argc < 7) { usage(); return 2; }
      uint64_t record_id = std::stoull(argv[3]);
      int64_t ts_ms = std::stoll(argv[4]);
      TemporalityMode mode = parse_mode(argv[5]);

      std::vector<IngestItem> items;
      for (int i = 6; i < argc; i++) {
        items.push_back(parse_typed_kv(argv[i]));
      }

      ingest_items(store, record_id, ts_ms, mode, items);
      std::cout << "ok: ingested record " << record_id << "\n";
      return 0;
    }

    if (cmd == "ingest_ndjson") {
      if (argc < 4) { usage(); return 2; }
      std::string file = argv[3];
      TemporalityMode def = TemporalityMode::EventDriven;
      if (argc >= 5) def = parse_mode(argv[4]);
      ingest_ndjson_file(store, file, def);
      std::cout << "ok: ingested ndjson " << file << "\n";
      return 0;
    }

    if (cmd == "current_eq" || cmd == "ever_eq") {
      if (argc < 5) { usage(); return 2; }
      std::string field = argv[3];
      std::string typed_value = argv[4];

      uint32_t fid = store.get_or_create_field(field);
      CanonValue cv = parse_cli_type_value(typed_value);
      uint64_t vid = store.get_or_create_value(cv);

      auto rows = (cmd == "current_eq")
        ? store.query_current_eq(fid, vid)
        : store.query_ever_eq(fid, vid);

      for (auto rid : rows) std::cout << rid << "\n";
      return 0;
    }

    if (cmd == "facts_window") {
      if (argc < 5) { usage(); return 2; }
      int64_t t1 = std::stoll(argv[3]);
      int64_t t2 = std::stoll(argv[4]);
      std::optional<uint64_t> rid{};
      if (argc >= 6) rid = std::stoull(argv[5]);

      auto facts = store.query_facts_window(t1, t2, rid);
      for (const auto& f : facts) {
        std::cout << fact_to_json(store, f).dump() << "\n";
      }
      return 0;
    }

    if (cmd == "snapshot") {
      if (argc < 5) { usage(); return 2; }
      uint64_t rid = std::stoull(argv[3]);
      int64_t t = std::stoll(argv[4]);
      auto rows = store.snapshot_at(rid, t);
      std::cout << snapshot_to_json(store, rid, t, rows).dump(2) << "\n";
      return 0;
    }

    if (cmd == "rebuild_current") {
      store.rebuild_current_facts();
      std::cout << "ok: rebuilt current_facts\n";
      return 0;
    }

    usage();
    return 2;

  } catch (const std::exception& e) {
    std::cerr << "error: " << e.what() << "\n";
    return 1;
  }
}
}
