#pragma once

#include "oracle_scanner/session.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace oracle_scanner {

// LOB_OP, the call a client makes to read a LOB it holds a locator for. A LOB
// column's row data carries no content at all — only the locator — so without
// this a LOB can be described and never read.
constexpr uint8_t TTC_FUNCTION_LOB_OP = 96;
constexpr uint8_t TTC_MESSAGE_LOB_DATA = 14;

// Operation codes. Only the two reads are used: the lifecycle operations
// (OPEN/CLOSE/IS_OPEN) exist for writing and for temporary LOBs, neither of
// which this client does.
constexpr uint32_t LOB_OP_GET_LENGTH = 0x0001;
constexpr uint32_t LOB_OP_READ = 0x0002;

struct TtcLobRequest {
    uint8_t sequence = 1;
    std::vector<uint8_t> locator;
    uint32_t operation = LOB_OP_READ;
    //! 1-based, in characters for a CLOB and bytes for a BLOB.
    uint64_t offset = 1;
    //! Zero means the request carries no amount, which is what GET_LENGTH does.
    uint64_t amount = 0;
};

std::vector<uint8_t> EncodeTtcLobRequest(const TtcLobRequest &request);

struct TtcLobResponse {
    //! The slice a READ returned; empty for GET_LENGTH.
    std::vector<uint8_t> data;
    //! What the server says it served, or the LOB's length for GET_LENGTH. In
    //! the same unit as the request's offset.
    uint64_t amount = 0;
    size_t bytes_consumed = 0;
};

// Decodes the LOB_DATA and return-parameter prefix of a LOB_OP response. The
// end-of-call that follows is left to the caller, which is the same division
// the execute and fetch paths use.
TtcLobResponse DecodeTtcLobResponse(const std::vector<uint8_t> &message, size_t locator_size);

// Converts a character LOB to the UTF-8 bytes used by the rest of the client.
// Ordinary CLOBs use the encoding selected by their locator, while NCLOBs are
// always UTF-16BE on this wire. The database character set does not by itself
// choose how a LOB read is encoded.
std::vector<uint8_t> DecodeTtcCharacterLobToUtf8(const std::vector<uint8_t> &content,
                                                 const std::vector<uint8_t> &locator,
                                                 uint8_t character_set_form);

std::vector<uint8_t> DecodeUtf16BeToUtf8(const std::vector<uint8_t> &utf16);

} // namespace oracle_scanner
