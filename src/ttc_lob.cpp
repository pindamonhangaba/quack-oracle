#include "oracle_scanner/ttc_lob.hpp"

#include "oracle_scanner/byte_buffer.hpp"
#include "oracle_scanner/protocol_error.hpp"
#include "oracle_scanner/ttc_auth.hpp"
#include "oracle_scanner/ttc_parameter.hpp"

namespace oracle_scanner {

namespace {

constexpr size_t MAX_LOCATOR_BYTES = 4096;
constexpr size_t MAX_LOB_CHUNK_BYTES = 16U << 20U;
constexpr size_t LOB_LOCATOR_ENCODING_OFFSET = 6;
constexpr size_t LOB_LOCATOR_FLAGS_OFFSET = 7;
constexpr uint8_t LOB_LOCATOR_UTF16_FLAG = 0x80;
constexpr uint8_t LOB_LOCATOR_UTF16_LE_FLAG = 0x40;

} // namespace

// The field order is the one a server has to read to recover the operation,
// locator, offset and amount; the pointer/length pairs in between are present
// even when null, because the layout is positional.
std::vector<uint8_t> EncodeTtcLobRequest(const TtcLobRequest &request) {
    if (request.locator.empty() || request.locator.size() > MAX_LOCATOR_BYTES) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "TTC LOB request has an invalid locator");
    }
    if (request.offset == 0) {
        // Oracle counts a LOB from 1. A zero offset is a caller's off-by-one,
        // and asking the server to reject it would cost a round trip.
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "TTC LOB offsets are 1-based");
    }
    if (request.amount > MAX_LOB_CHUNK_BYTES) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "TTC LOB request amount is too large");
    }
    ByteWriter writer;
    writer.WriteByte(TTC_MESSAGE_FUNCTION).WriteByte(TTC_FUNCTION_LOB_OP).WriteByte(request.sequence);
    writer.WriteByte(1).WriteUB4(static_cast<uint32_t>(request.locator.size())); // source locator
    writer.WriteByte(0).WriteUB4(0);                                            // destination locator
    writer.WriteUB4(0).WriteUB4(0);                                             // short source, short dest offset
    writer.WriteByte(0).WriteByte(0).WriteByte(0);                              // charset, short amount, null lob
    writer.WriteUB4(request.operation);
    writer.WriteByte(0).WriteByte(0);                                           // SCN array pointer and length
    writer.WriteUB8(request.offset).WriteUB8(0);                                // source and destination offset
    writer.WriteByte(1); // amount pointer
    writer.WriteUInt16BE(0).WriteUInt16BE(0).WriteUInt16BE(0);                  // array-LOB fields, unused
    writer.WriteRaw(request.locator);
    writer.WriteUB8(request.amount);
    return writer.Take();
}

TtcLobResponse DecodeTtcLobResponse(const std::vector<uint8_t> &message, size_t locator_size) {
    if (locator_size == 0 || locator_size > MAX_LOCATOR_BYTES) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "TTC LOB response decoder has an invalid locator size");
    }
    ByteReader reader(message);
    TtcLobResponse result;
    if (reader.Remaining() == 0) {
        throw ProtocolError(ProtocolErrorKind::TRUNCATED, "TTC LOB response is empty");
    }
    if (reader.PeekByte() == TTC_MESSAGE_LOB_DATA) {
        reader.ReadByte();
        const auto data = reader.ReadLengthPrefixed(MAX_LOB_CHUNK_BYTES);
        if (data) {
            result.data = *data;
        }
    }
    // The return parameter echoes the locator and then says how much the server
    // served. A read that returns nothing still carries it, which is how the
    // end of a LOB is recognised without asking for its length first.
    if (reader.Remaining() == 0) {
        throw ProtocolError(ProtocolErrorKind::TRUNCATED, "TTC LOB response has no return parameter");
    }
    if (reader.ReadByte() != TTC_MESSAGE_PARAMETER) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "expected a TTC return parameter after LOB data");
    }
    reader.Skip(locator_size);
    result.amount = reader.ReadUB8();
    result.bytes_consumed = reader.Position();
    return result;
}

std::vector<uint8_t> DecodeUtf16ToUtf8(const std::vector<uint8_t> &utf16, bool little_endian) {
    if (utf16.size() % 2 != 0) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "a CLOB read returned an odd number of UTF-16 bytes");
    }
    std::vector<uint8_t> result;
    result.reserve(utf16.size());
    const auto append = [&result](uint32_t code_point) {
        if (code_point < 0x80) {
            result.push_back(static_cast<uint8_t>(code_point));
        } else if (code_point < 0x800) {
            result.push_back(static_cast<uint8_t>(0xC0U | (code_point >> 6U)));
            result.push_back(static_cast<uint8_t>(0x80U | (code_point & 0x3FU)));
        } else if (code_point < 0x10000) {
            result.push_back(static_cast<uint8_t>(0xE0U | (code_point >> 12U)));
            result.push_back(static_cast<uint8_t>(0x80U | ((code_point >> 6U) & 0x3FU)));
            result.push_back(static_cast<uint8_t>(0x80U | (code_point & 0x3FU)));
        } else {
            result.push_back(static_cast<uint8_t>(0xF0U | (code_point >> 18U)));
            result.push_back(static_cast<uint8_t>(0x80U | ((code_point >> 12U) & 0x3FU)));
            result.push_back(static_cast<uint8_t>(0x80U | ((code_point >> 6U) & 0x3FU)));
            result.push_back(static_cast<uint8_t>(0x80U | (code_point & 0x3FU)));
        }
    };
    for (size_t index = 0; index + 1 < utf16.size(); index += 2) {
        const uint32_t unit = little_endian ? static_cast<uint32_t>(utf16[index]) |
                                                 (static_cast<uint32_t>(utf16[index + 1]) << 8U)
                                           : (static_cast<uint32_t>(utf16[index]) << 8U) | utf16[index + 1];
        if (unit >= 0xD800 && unit <= 0xDBFF) {
            // A high surrogate must be followed by its low half. An unpaired
            // one is not a character, and guessing a replacement would put
            // bytes in a column that the database does not hold.
            if (index + 3 >= utf16.size()) {
                throw ProtocolError(ProtocolErrorKind::MALFORMED, "a CLOB read ended on an unpaired UTF-16 surrogate");
            }
            const uint32_t low = little_endian ? static_cast<uint32_t>(utf16[index + 2]) |
                                       (static_cast<uint32_t>(utf16[index + 3]) << 8U)
                                   : (static_cast<uint32_t>(utf16[index + 2]) << 8U) | utf16[index + 3];
            if (low < 0xDC00 || low > 0xDFFF) {
                throw ProtocolError(ProtocolErrorKind::MALFORMED, "a CLOB read carried an unpaired UTF-16 surrogate");
            }
            append(0x10000U + ((unit - 0xD800U) << 10U) + (low - 0xDC00U));
            index += 2;
            continue;
        }
        if (unit >= 0xDC00 && unit <= 0xDFFF) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "a CLOB read carried a low UTF-16 surrogate first");
        }
        append(unit);
    }
    return result;
}

namespace {

void ValidateUtf8(const std::vector<uint8_t> &utf8) {
    for (size_t index = 0; index < utf8.size();) {
        const auto first = utf8[index];
        size_t continuation_count = 0;
        uint8_t second_minimum = 0x80;
        uint8_t second_maximum = 0xBF;
        if (first <= 0x7F) {
            index++;
            continue;
        } else if (first >= 0xC2 && first <= 0xDF) {
            continuation_count = 1;
        } else if (first == 0xE0) {
            continuation_count = 2;
            second_minimum = 0xA0;
        } else if (first >= 0xE1 && first <= 0xEC) {
            continuation_count = 2;
        } else if (first == 0xED) {
            continuation_count = 2;
            second_maximum = 0x9F;
        } else if (first >= 0xEE && first <= 0xEF) {
            continuation_count = 2;
        } else if (first == 0xF0) {
            continuation_count = 3;
            second_minimum = 0x90;
        } else if (first >= 0xF1 && first <= 0xF3) {
            continuation_count = 3;
        } else if (first == 0xF4) {
            continuation_count = 3;
            second_maximum = 0x8F;
        } else {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "a CLOB read returned invalid UTF-8");
        }
        if (index + continuation_count >= utf8.size() || utf8[index + 1] < second_minimum ||
            utf8[index + 1] > second_maximum) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "a CLOB read returned invalid UTF-8");
        }
        for (size_t offset = 2; offset <= continuation_count; offset++) {
            const auto byte = utf8[index + offset];
            if (byte < 0x80 || byte > 0xBF) {
                throw ProtocolError(ProtocolErrorKind::MALFORMED, "a CLOB read returned invalid UTF-8");
            }
        }
        index += continuation_count + 1;
    }
}

} // namespace

std::vector<uint8_t> DecodeTtcCharacterLobToUtf8(const std::vector<uint8_t> &content,
                                                 const std::vector<uint8_t> &locator,
                                                 uint8_t character_set_form) {
    if (locator.size() <= LOB_LOCATOR_FLAGS_OFFSET || locator.size() > MAX_LOCATOR_BYTES) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "a character LOB locator is too short or too large");
    }
    if (character_set_form == 2) {
        return DecodeUtf16ToUtf8(content, false);
    }
    if (character_set_form != 0 && character_set_form != 1) {
        throw ProtocolError(ProtocolErrorKind::UNSUPPORTED, "a character LOB has an unsupported character set form");
    }
    const bool utf16 = (locator[LOB_LOCATOR_ENCODING_OFFSET] & LOB_LOCATOR_UTF16_FLAG) != 0;
    const bool little_endian = (locator[LOB_LOCATOR_FLAGS_OFFSET] & LOB_LOCATOR_UTF16_LE_FLAG) != 0;
    if (!utf16 && little_endian) {
        throw ProtocolError(ProtocolErrorKind::UNSUPPORTED, "a character LOB has an unsupported locator encoding");
    }
    if (utf16) {
        return DecodeUtf16ToUtf8(content, little_endian);
    }
    ValidateUtf8(content);
    return content;
}

std::vector<uint8_t> DecodeUtf16BeToUtf8(const std::vector<uint8_t> &utf16) {
    return DecodeUtf16ToUtf8(utf16, false);
}

} // namespace oracle_scanner
