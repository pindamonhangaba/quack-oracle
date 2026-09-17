#include "oracle_scanner/ttc_parameter.hpp"
#include "oracle_scanner/byte_buffer.hpp"
#include "oracle_scanner/protocol_error.hpp"

#include <cctype>
#include <limits>
#include <map>

namespace oracle_scanner {

namespace {

constexpr size_t MAX_PARAMETER_COUNT = 64;
constexpr size_t MAX_PARAMETER_BYTES = 65535;
constexpr size_t MAX_RETURN_PARAMETER_COUNT = 4096;

std::vector<uint8_t> ToBytes(const std::string &value) {
    return std::vector<uint8_t>(value.begin(), value.end());
}

void WriteTwoLengths(ByteWriter &writer, const std::string &value) {
    if (value.size() > MAX_PARAMETER_BYTES) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "TTC parameter exceeds supported length");
    }
    writer.WriteUB4(static_cast<uint32_t>(value.size()));
    if (!value.empty()) {
        writer.WriteLengthPrefixed(ToBytes(value));
    }
}

std::string ReadReturnParameterString(ByteReader &reader) {
    const auto declared_size = reader.ReadUB4();
    if (declared_size > MAX_PARAMETER_BYTES) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "TTC parameter exceeds supported length");
    }
    if (declared_size == 0) {
        return {};
    }
    const auto encoded = reader.ReadLengthPrefixed(MAX_PARAMETER_BYTES);
    if (!encoded) {
        return {};
    }
    return {encoded->begin(), encoded->end()};
}

std::vector<TtcParameter> DecodeParameterList(ByteReader &reader, uint32_t count) {
    std::vector<TtcParameter> result;
    result.reserve(count);
    for (uint32_t index = 0; index < count; index++) {
        const auto parameter_start = reader.Position();
        size_t key_end = parameter_start;
        size_t value_end = parameter_start;
        try {
            TtcParameter parameter;
            parameter.key = ReadReturnParameterString(reader);
            key_end = reader.Position();
            parameter.value = ReadReturnParameterString(reader);
            value_end = reader.Position();
            parameter.flags = reader.ReadUB4();
            if (parameter.key.empty()) {
                throw ProtocolError(ProtocolErrorKind::MALFORMED, "TTC parameter key is empty");
            }
            result.push_back(std::move(parameter));
        } catch (const ProtocolError &error) {
            std::string next_byte = "none";
            if (reader.Remaining() > 0) {
                next_byte = std::to_string(reader.PeekByte());
            }
            throw ProtocolError(error.Kind(), "TTC return parameter " + std::to_string(index) + " (start " +
                                             std::to_string(parameter_start) + ", key-end " + std::to_string(key_end) +
                                             ", value-end " + std::to_string(value_end) + ", offset " +
                                             std::to_string(reader.Position()) + ", remaining " +
                                             std::to_string(reader.Remaining()) + ", next byte " + next_byte +
                                             "): " + error.what());
        }
    }
    return result;
}

uint32_t ParseIterations(const std::string &value) {
    if (value.empty() || value.size() > 8) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "O5LOGON iteration parameter is invalid");
    }
    uint32_t result = 0;
    for (const auto character : value) {
        if (!std::isdigit(static_cast<unsigned char>(character))) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "O5LOGON iteration parameter is not numeric");
        }
        result = result * 10 + static_cast<uint32_t>(character - '0');
        if (result > 10000000) {
            throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "O5LOGON iteration parameter is too large");
        }
    }
    if (result == 0) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "O5LOGON iteration parameter must be positive");
    }
    return result;
}

} // namespace

TtcReturnParameterPrefix DecodeTtcReturnParameterPrefix(const std::vector<uint8_t> &message) {
    ByteReader reader(message);
    if (reader.ReadByte() != TTC_MESSAGE_PARAMETER) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "expected TTC RETURN_PARAMETER message");
    }
    const auto parameter_count = reader.ReadUB2();
    if (parameter_count > MAX_RETURN_PARAMETER_COUNT) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "TTC RETURN_PARAMETER has too many parameter slots");
    }
    for (uint16_t index = 0; index < parameter_count; ++index) {
        reader.ReadUB4();
    }
    const auto transaction_id_size = reader.ReadUB2();
    if (transaction_id_size > MAX_PARAMETER_BYTES) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "TTC RETURN_PARAMETER transaction id is too large");
    }
    reader.Skip(transaction_id_size);
    const auto key_value_count = reader.ReadUB2();
    if (key_value_count > MAX_RETURN_PARAMETER_COUNT) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "TTC RETURN_PARAMETER has too many key/value entries");
    }
    for (uint16_t index = 0; index < key_value_count; ++index) {
        const auto key_size = reader.ReadUB2();
        if (key_size > 0) {
            (void)reader.ReadLengthPrefixed(key_size);
        }
        const auto value_size = reader.ReadUB2();
        if (value_size > 0) {
            (void)reader.ReadLengthPrefixed(value_size);
        }
        reader.ReadUB2(); // keyword number
    }
    const auto registration_size = reader.ReadUB2();
    if (registration_size > MAX_PARAMETER_BYTES) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "TTC RETURN_PARAMETER registration is too large");
    }
    reader.Skip(registration_size);
    return {reader.Position()};
}

std::vector<uint8_t> EncodeTtcParameters(const std::vector<TtcParameter> &parameters) {
    if (parameters.size() > MAX_PARAMETER_COUNT) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "too many TTC parameters");
    }
    ByteWriter writer;
    writer.WriteByte(TTC_MESSAGE_PARAMETER).WriteUB2(static_cast<uint16_t>(parameters.size()));
    for (const auto &parameter : parameters) {
        WriteTwoLengths(writer, parameter.key);
        WriteTwoLengths(writer, parameter.value);
        writer.WriteUB4(parameter.flags);
    }
    return writer.Take();
}

std::vector<TtcParameter> DecodeTtcParameters(const std::vector<uint8_t> &message) {
    ByteReader reader(message);
    if (reader.ReadByte() != TTC_MESSAGE_PARAMETER) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "expected TTC PARAMETER message");
    }
    const auto count = reader.ReadUB2();
    if (count > MAX_PARAMETER_COUNT) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "too many TTC parameters");
    }
    return DecodeParameterList(reader, count);
}

O5LogonChallenge O5LogonChallengeFromParameters(const std::vector<TtcParameter> &parameters) {
    std::map<std::string, std::string> values;
    uint32_t verifier_type = 0;
    for (const auto &parameter : parameters) {
        if (!values.emplace(parameter.key, parameter.value).second) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "O5LOGON response has duplicate parameters");
        }
        if (parameter.key == "AUTH_VFR_DATA") {
            verifier_type = parameter.flags;
        }
    }
    auto required = [&](const char *key) -> const std::string & {
        const auto found = values.find(key);
        if (found == values.end()) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "O5LOGON response is missing a required parameter");
        }
        return found->second;
    };
    O5LogonChallenge result;
    result.verifier_data_hex = required("AUTH_VFR_DATA");
    result.server_session_key_hex = required("AUTH_SESSKEY");
    result.combo_key_salt_hex = required("AUTH_PBKDF2_CSK_SALT");
    result.verifier_iterations = ParseIterations(required("AUTH_PBKDF2_VGEN_COUNT"));
    result.combo_key_iterations = ParseIterations(required("AUTH_PBKDF2_SDER_COUNT"));
    result.verifier_type = verifier_type;
    return result;
}

} // namespace oracle_scanner
