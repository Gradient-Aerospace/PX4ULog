"""
    PX4ULog

Read standard PX4 ULog (`.ulg`) files, inspect their metadata, and decode topic data into
typed, column-oriented Julia arrays.
"""
module PX4ULog

export ULogHeader, ULogMessage, read_ulog_header, each_message, scan_messages
export FieldDef, FormatDef, scan_formats, read_all_formats, parse_format_string
export Subscription, scan_subscriptions, read_all_subscriptions
export TopicData, read_topic, count_data_samples
export ULog, topics, build_data_index
export ULogMetadata, ParameterChange, LoggedMessage
export info_messages, info_message, info_types, info_multiple
export initial_parameters, changed_parameters, default_parameters, has_default_parameters
export logged_messages
export time_seconds
export audit_data_lengths
export to_dataframe

using Printf

# -----------------------------------------------------------------------------
# Public stubs (extensions)
# -----------------------------------------------------------------------------

"""
    to_dataframe(td::TopicData; kwargs...)
    to_dataframe(ulog::ULog, topic_name, multi_id = 0; kwargs...)

Convert decoded topic data to a `DataFrame`. Methods are provided by the optional
DataFrames extension after DataFrames.jl is loaded.

Set `time_s = true` to add time in seconds and use `expand_arrays` to select
`:columns`, `:rowviews`, or `:vectors` for fixed-size array fields.
"""
function to_dataframe end

# -----------------------------------------------------------------------------
# Types
# -----------------------------------------------------------------------------

"""
    ULogHeader

The fixed 16-byte header at the start of a ULog file. `start_timestamp_us` is the
logging start timestamp in microseconds.
"""
struct ULogHeader
    magic_ok::Bool
    version::UInt8
    start_timestamp_us::UInt64
    raw::NTuple{16,UInt8}
end

const ULOG_MAGIC = UInt8[0x55, 0x4c, 0x6f, 0x67, 0x01, 0x12, 0x35]  # "ULog" + 0x01 0x12 0x35

"""
    ULogMessage

A complete ULog message record. `offset` is the zero-based byte offset of the record,
`size` is the payload length, `type` is the ASCII message type byte, and `payload`
contains the raw message bytes.
"""
struct ULogMessage
    offset::Int64
    size::UInt16
    type::UInt8
    payload::Vector{UInt8}
end

struct FlagBits
    compat_flags::NTuple{8,UInt8}
    incompat_flags::NTuple{8,UInt8}
    appended_offsets::NTuple{3,UInt64}
end

"""
    FieldDef

A field parsed from a ULog `FORMAT` record. `array_len == 0` denotes a scalar;
positive values denote a fixed-size array.
"""
struct FieldDef
    name::Symbol
    ulog_type::String
    array_len::Int
end

"""
    FormatDef

A named ULog message format and its ordered fields.
"""
struct FormatDef
    name::String
    fields::Vector{FieldDef}
end

"""
    Subscription

A topic subscription from an `ADD_LOGGED_MSG` record, identified by `msg_id`,
`multi_id`, and topic `name`.
"""
struct Subscription
    msg_id::UInt16
    multi_id::UInt8
    name::String
end

"""
    TopicData

Decoded samples for one topic instance. Timestamps are in microseconds. Scalar fields
are vectors, fixed-size arrays are matrices with one row per sample, character arrays
are strings, and nested field names are flattened with underscores.

Fields in `cols` are also available through property and symbol indexing. The stored
arrays are mutable and returned directly.
"""
struct TopicData
    topic::String
    multi_id::UInt8
    timestamp::Union{Vector{UInt64}, Nothing}
    cols::Dict{Symbol, Any}   # Symbol => Vector{T} or Matrix{T} or Vector{String}, etc.
end

"""
    ParameterChange

A parameter update found after the ULog data section starts. `timestamp` is in
microseconds, `value` is the decoded Julia value, and `ulog_type` is the source type.
"""
struct ParameterChange
    timestamp::UInt64
    name::String
    value::Any
    ulog_type::String
end

"""
    LoggedMessage

A standard ULog text message. `timestamp` is in microseconds, `level` is the raw log
level byte, `level_name` is its symbolic interpretation, and `tag` is present only for
tagged messages.
"""
struct LoggedMessage
    timestamp::UInt64
    level::UInt8
    level_name::Symbol
    message::String
    tag::Union{Nothing,UInt16}
end

"""
    ULogMetadata

Decoded non-topic records: information messages, multi-information groups, initial and
default parameters, parameter changes, and logged strings. Dictionaries and vectors
are mutable and are exposed directly by the metadata accessors.
"""
struct ULogMetadata
    info::Dict{String, Any}
    info_types::Dict{String, String}
    info_multiple::Dict{String, Vector{Vector{Any}}}
    info_multiple_types::Dict{String, String}
    initial_parameters::Dict{String, Any}
    initial_parameter_types::Dict{String, String}
    default_parameters::Dict{Int, Dict{String, Any}}
    default_parameter_types::Dict{Int, Dict{String, String}}
    changed_parameters::Vector{ParameterChange}
    logged_messages::Vector{LoggedMessage}
    has_default_parameters::Bool
end

function ULogMetadata(; has_default_parameters::Bool=false)
    return ULogMetadata(
        Dict{String, Any}(),
        Dict{String, String}(),
        Dict{String, Vector{Vector{Any}}}(),
        Dict{String, String}(),
        Dict{String, Any}(),
        Dict{String, String}(),
        Dict{Int, Dict{String, Any}}(),
        Dict{Int, Dict{String, String}}(),
        ParameterChange[],
        LoggedMessage[],
        has_default_parameters,
    )
end

# -----------------------------------------------------------------------------
# Low-level binary helpers
# -----------------------------------------------------------------------------

@inline function read_u8(io::IO)::UInt8
    return read(io, UInt8)
end

@inline function read_u16_le(io::IO)::UInt16
    b1 = read(io, UInt8)
    b2 = read(io, UInt8)
    return UInt16(b1) | (UInt16(b2) << 8)
end

@inline function read_u16_le(bytes::Vector{UInt8}, i::Int)::UInt16
    return UInt16(bytes[i]) | (UInt16(bytes[i+1]) << 8)
end

@inline function read_u64_le(bytes::Vector{UInt8}, i::Int)::UInt64
    x = UInt64(0)
    @inbounds for k in 0:7
        x |= UInt64(bytes[i+k]) << (8*k)
    end
    return x
end

# Best-effort ASCII rendering for debug output
function ascii_type(t::UInt8)::Char
    c = Char(t)
    return (c >= '\x20' && c <= '\x7e') ? c : '?'
end

# -----------------------------------------------------------------------------
# Header
# -----------------------------------------------------------------------------

"""
Read the fixed 16-byte ULog header.
"""
function read_ulog_header(io::IO)::ULogHeader
    raw_vec = Vector{UInt8}(undef, 16)
    read!(io, raw_vec)

    raw = ntuple(i -> raw_vec[i], 16)

    magic_ok = all(raw_vec[i] == ULOG_MAGIC[i] for i in 1:7)
    version = raw_vec[8]

    ts = UInt64(0)
    for i in 0:7
        ts |= (UInt64(raw_vec[9+i]) << (8*i))
    end

    return ULogHeader(magic_ok, version, ts, raw)
end

function validate_ulog_header(hdr::ULogHeader)
    hdr.magic_ok || error("Invalid ULog magic bytes")
    return nothing
end

function decode_flag_bits(msg::ULogMessage)::FlagBits
    msg.type == UInt8('B') || error("decode_flag_bits: expected 'B', got $(Char(msg.type))")
    length(msg.payload) == 40 || error(
        "FLAG_BITS payload has $(length(msg.payload)) bytes, expected 40",
    )

    p = msg.payload
    compat_flags = ntuple(i -> p[i], 8)
    incompat_flags = ntuple(i -> p[8+i], 8)
    appended_offsets = ntuple(i -> read_u64_le(p, 17 + 8*(i-1)), 3)

    return FlagBits(compat_flags, incompat_flags, appended_offsets)
end

function validate_flag_bits(flags::FlagBits)
    unsupported_first = flags.incompat_flags[1] & 0xfe
    if unsupported_first != 0x00 || any(!iszero, flags.incompat_flags[2:end])
        bytes = join(("0x" * string(f; base=16, pad=2) for f in flags.incompat_flags), ", ")
        error("Unsupported ULog incompatibility flags: [$bytes]")
    end
    if (flags.incompat_flags[1] & 0x01) != 0x00 && any(!iszero, flags.appended_offsets)
        error("ULog appended data is not supported")
    end
    return nothing
end

function read_ulog_preamble!(io::IO)::Tuple{ULogHeader, FlagBits}
    hdr = read_ulog_header(io)
    validate_ulog_header(hdr)

    msg = read_message_at!(io)
    msg.type == UInt8('B') || error(
        "Expected ULog flag-bits message ('B') immediately after header",
    )
    flags = decode_flag_bits(msg)
    validate_flag_bits(flags)

    return hdr, flags
end

# -----------------------------------------------------------------------------
# Message iteration
# -----------------------------------------------------------------------------

function read_message_or_nothing!(io::IO)::Union{ULogMessage, Nothing}
    eof(io) && return nothing
    offset = position(io)

    b1 = try
        read(io, UInt8)
    catch e
        if e isa EOFError
            return nothing
        else
            rethrow()
        end
    end
    b2 = try
        read(io, UInt8)
    catch e
        if e isa EOFError
            return nothing
        else
            rethrow()
        end
    end
    msg_size = UInt16(b1) | (UInt16(b2) << 8)

    msg_type = try
        read(io, UInt8)
    catch e
        if e isa EOFError
            return nothing
        else
            rethrow()
        end
    end

    payload_len = Int(msg_size)
    payload = payload_len == 0 ? UInt8[] : read(io, payload_len)
    length(payload) == payload_len || return nothing

    return ULogMessage(offset, msg_size, msg_type, payload)
end

"""
Iterate complete ULog messages from the current IO position.

`msg_size` is interpreted as the number of payload bytes following `msg_type`.
If the file ends in the middle of a message, the partial message is discarded.
"""
function each_message(io::IO)
    return Channel{ULogMessage}(32) do ch
        while true
            msg = read_message_or_nothing!(io)
            msg === nothing && break
            put!(ch, msg)
        end
    end
end

"""
Read a single ULog record at the current file position.
Assumes position(io) is at the start of the message header (msg_size field).
"""
function read_message_at!(io::IO)::ULogMessage
    offset = position(io)
    msg = read_message_or_nothing!(io)
    msg === nothing && error("Truncated ULog message at offset $offset")
    return msg
end

# -----------------------------------------------------------------------------
# Debug scan: message counts
# -----------------------------------------------------------------------------

"""
    scan_messages(path; max_messages = 2000, show_types = true)

Print a diagnostic summary of complete ULog records and return their counts by message
type. A truncated final record is ignored. This function performs file I/O and writes
to standard output.
"""
function scan_messages(
    path::AbstractString;
    max_messages::Int = 2000,
    show_types::Bool = true,
)
    open(path, "r") do io
        hdr, _ = read_ulog_preamble!(io)
        println("ULog header:")
        println("  magic_ok            = $(hdr.magic_ok)")
        println("  version             = $(hdr.version)")
        println("  start_timestamp_us  = $(hdr.start_timestamp_us)")
        println()

        counts = Dict{UInt8, Int}(UInt8('B') => 1)
        n = 0
        for msg in each_message(io)
            n += 1
            counts[msg.type] = get(counts, msg.type, 0) + 1

            if n <= 20
                @printf(
                    "msg %5d  off=%10d  type=%c (0x%02x)  size=%d  payload=%d\n",
                    n,
                    msg.offset,
                    ascii_type(msg.type),
                    msg.type,
                    msg.size,
                    length(msg.payload),
                )
            end

            if n >= max_messages
                println("\nReached max_messages=$max_messages; stopping scan early.")
                break
            end
        end

        println("\nScanned $n messages.")

        if show_types
            println("\nMessage type counts:")
            for (t, c) in sort(collect(counts); by=x->x[1])
                @printf("  %c (0x%02x): %d\n", ascii_type(t), t, c)
            end
        end

        return counts
    end
end

# -----------------------------------------------------------------------------
# FORMAT decoding + parsing
# -----------------------------------------------------------------------------

function decode_format(msg::ULogMessage)::String
    msg.type == UInt8('F') || error("decode_format: expected 'F', got $(Char(msg.type))")
    return String(msg.payload)
end

function parse_field_token(tok::AbstractString)::FieldDef
    s = strip(tok)
    isempty(s) && error("Empty field token in FORMAT")

    parts = split(s; limit=2)
    length(parts) == 2 || error("Invalid field token (expected '<type> <name>'): '$s'")

    typ_raw = strip(parts[1])
    name_raw = strip(parts[2])

    mtype = match(r"^([A-Za-z_][A-Za-z0-9_]*)(?:\[(\d+)\])?$", typ_raw)
    mtype === nothing && error("Invalid type syntax in token: '$s'")
    base_type = String(mtype.captures[1])
    type_arr = mtype.captures[2] === nothing ? 0 : parse(Int, mtype.captures[2])

    mname = match(r"^([A-Za-z_][A-Za-z0-9_]*)(?:\[(\d+)\])?$", name_raw)
    mname === nothing && error("Invalid field name syntax in token: '$s'")
    field_name = String(mname.captures[1])
    name_arr = mname.captures[2] === nothing ? 0 : parse(Int, mname.captures[2])

    if type_arr > 0 && name_arr > 0
        error("Array length specified on both type and name in token: '$s'")
    end
    array_len = max(type_arr, name_arr)

    return FieldDef(Symbol(field_name), base_type, array_len)
end

"""
    parse_format_string(format_string) -> FormatDef

Parse the payload text of one ULog `FORMAT` record. Invalid field syntax throws an
`ErrorException`; nested type references are validated when all formats are loaded.
"""
function parse_format_string(fmt::AbstractString)::FormatDef
    s = strip(fmt)
    isempty(s) && error("Empty FORMAT string")

    k = findfirst(==(':'), s)
    k === nothing && error("FORMAT string missing ':' separator: '$s'")

    name = strip(s[1:k-1])
    rest = strip(s[k+1:end])
    isempty(name) && error("FORMAT string has empty name: '$s'")
    isempty(rest) && error("FORMAT string has empty field list: '$s'")

    raw_tokens = split(rest, ';')
    tokens = [t for t in raw_tokens if !isempty(strip(t))]

    fields = FieldDef[]
    for t in tokens
        push!(fields, parse_field_token(t))
    end

    return FormatDef(String(name), fields)
end

"""
    read_all_formats(path) -> Dict{String,FormatDef}

Read and validate every ULog format definition. Forward references are accepted;
unknown nested formats and cyclic definitions throw an `ErrorException`.
"""
function read_all_formats(path::AbstractString)
    open(path, "r") do io
        _ = read_ulog_preamble!(io)
        formats = Dict{String, FormatDef}()

        for msg in each_message(io)
            if msg.type == UInt8('F')
                s = decode_format(msg)
                fd = parse_format_string(s)
                formats[fd.name] = fd
            end
        end

        validate_format_graph(formats)
        return formats
    end
end

"""
    scan_formats(path; max_formats = 20) -> Int

Print up to `max_formats` raw ULog format definitions and return the number printed.
"""
function scan_formats(path::AbstractString; max_formats::Int = 20)
    open(path, "r") do io
        _ = read_ulog_preamble!(io)

        n = 0
        for msg in each_message(io)
            if msg.type == UInt8('F')
                n += 1
                println("F[$n] = ", decode_format(msg))
                if n >= max_formats
                    break
                end
            end
        end
        return n
    end
end

# -----------------------------------------------------------------------------
# ADD_LOGGED_MSG ('A')
# -----------------------------------------------------------------------------

@inline function read_cstring(bytes::Vector{UInt8}, start::Int=1)::Tuple{String, Int}
    i = start
    n = length(bytes)
    while i <= n && bytes[i] != 0x00
        i += 1
    end
    str = String(bytes[start:(i-1)])
    nexti = i <= n ? (i + 1) : (n + 1)
    return (str, nexti)
end

function decode_add_logged_msg(msg::ULogMessage)::Subscription
    msg.type == UInt8('A') || error("decode_add_logged_msg: expected 'A', got $(Char(msg.type))")

    p = msg.payload
    length(p) >= 3 || error("ADD_LOGGED_MSG payload too short: $(length(p)) bytes")

    multi_id = p[1]
    msg_id = UInt16(p[2]) | (UInt16(p[3]) << 8)

    name, _ = read_cstring(p, 4)
    isempty(name) && error("ADD_LOGGED_MSG has empty message_name (msg_id=$msg_id)")

    return Subscription(msg_id, multi_id, name)
end

"""
    read_all_subscriptions(path)

Read all topic subscriptions. Return dictionaries indexed by message identifier and by
`(topic_name, multi_id)`. Later records replace earlier records with the same key.
"""
function read_all_subscriptions(path::AbstractString)
    open(path, "r") do io
        _ = read_ulog_preamble!(io)

        subs_by_id = Dict{UInt16, Subscription}()
        subs_by_name = Dict{Tuple{String,UInt8}, UInt16}()

        for msg in each_message(io)
            if msg.type == UInt8('A')
                sub = decode_add_logged_msg(msg)
                subs_by_id[sub.msg_id] = sub
                subs_by_name[(sub.name, sub.multi_id)] = sub.msg_id
            end
        end

        return subs_by_id, subs_by_name
    end
end

"""
    scan_subscriptions(path; max_subs = 30) -> Int

Print up to `max_subs` topic subscriptions and return the number printed.
"""
function scan_subscriptions(path::AbstractString; max_subs::Int = 30)
    open(path, "r") do io
        _ = read_ulog_preamble!(io)
        n = 0
        for msg in each_message(io)
            if msg.type == UInt8('A')
                n += 1
                sub = decode_add_logged_msg(msg)
                @printf(
                    "A[%3d] msg_id=%5d  multi_id=%d  name=%s\n",
                    n,
                    sub.msg_id,
                    sub.multi_id,
                    sub.name,
                )
                if n >= max_subs
                    break
                end
            end
        end
        return n
    end
end

# -----------------------------------------------------------------------------
# Primitive types + little-endian loads
# -----------------------------------------------------------------------------

function primitive_info(t::AbstractString)
    s = String(strip(t))
    if s == "int8_t";   return (Int8,   1) end
    if s == "uint8_t";  return (UInt8,  1) end
    if s == "int16_t";  return (Int16,  2) end
    if s == "uint16_t"; return (UInt16, 2) end
    if s == "int32_t";  return (Int32,  4) end
    if s == "uint32_t"; return (UInt32, 4) end
    if s == "int64_t";  return (Int64,  8) end
    if s == "uint64_t"; return (UInt64, 8) end
    if s == "float";    return (Float32, 4) end
    if s == "double";   return (Float64, 8) end
    if s == "bool";     return (Bool,   1) end
    if s == "char";     return (UInt8,  1) end
    return nothing
end

function ulog_primitive(t::AbstractString)
    info = primitive_info(t)
    info === nothing && error("Unsupported/unknown ULog primitive type: '$(strip(t))'")
    return info
end

is_padding(f::FieldDef) = startswith(String(f.name), "_padding")
field_count(f::FieldDef) = f.array_len == 0 ? 1 : f.array_len

function format_lookup(formats::Dict{String, FormatDef}, name::AbstractString)::FormatDef
    key = String(name)
    haskey(formats, key) || error("Unknown nested ULog format: '$key'")
    return formats[key]
end

function validate_format_graph(formats::Dict{String, FormatDef})
    states = Dict{String, UInt8}()
    stack = String[]

    function visit(name::String)
        state = get(states, name, 0x00)
        if state == 0x01
            cycle_start = findfirst(==(name), stack)
            cycle = join([stack[cycle_start:end]; name], " -> ")
            error("Circular ULog FORMAT definition: $cycle")
        elseif state == 0x02
            return nothing
        end

        fmt = format_lookup(formats, name)
        states[name] = 0x01
        push!(stack, name)
        for field in fmt.fields
            primitive_info(field.ulog_type) === nothing || continue
            nested = String(field.ulog_type)
            format_lookup(formats, nested)
            visit(nested)
        end
        pop!(stack)
        states[name] = 0x02
        return nothing
    end

    for name in keys(formats)
        visit(name)
    end
    return nothing
end

function prefixed_name(prefix::AbstractString, name::Symbol)::Symbol
    isempty(prefix) && return name
    return Symbol(prefix, "_", name)
end

function child_prefix(prefix::AbstractString, name::Symbol)::String
    isempty(prefix) && return String(name)
    return string(prefix, "_", name)
end

function insert_column!(cols::Dict{Symbol, Any}, name::Symbol, col)
    haskey(cols, name) && error("Duplicate decoded column name: $name")
    cols[name] = col
    return nothing
end

function format_serialized_bytes(
    fmt::FormatDef,
    formats::Dict{String, FormatDef};
    omit_final_padding::Bool,
    stack::Vector{String}=String[],
)::Int
    if fmt.name in stack
        cycle = join([stack; fmt.name], " -> ")
        error("Circular ULog FORMAT definition: $cycle")
    end

    push!(stack, fmt.name)
    total = 0
    for (idx, f) in enumerate(fmt.fields)
        if is_padding(f) && omit_final_padding && idx == lastindex(fmt.fields)
            continue
        end

        n = field_count(f)
        info = primitive_info(f.ulog_type)
        if info === nothing
            nested = format_lookup(formats, f.ulog_type)
            total += n * format_serialized_bytes(
                nested,
                formats;
                omit_final_padding=false,
                stack=stack,
            )
        else
            (_, sz) = info
            total += sz * n
        end
    end
    pop!(stack)
    return total
end

function expected_struct_bytes(fmt::FormatDef, formats::Dict{String, FormatDef})::Int
    return format_serialized_bytes(fmt, formats; omit_final_padding=true)
end

function expected_struct_bytes(fmt::FormatDef)::Int
    return expected_struct_bytes(fmt, Dict{String, FormatDef}())
end

function full_struct_bytes(fmt::FormatDef, formats::Dict{String, FormatDef})::Int
    return format_serialized_bytes(fmt, formats; omit_final_padding=false)
end

function final_padding_omitted(
    struct_len::Int,
    expected_omitted::Int,
    expected_full::Int,
    topic_name::AbstractString,
    payload_len::Int,
)::Bool
    if struct_len == expected_omitted
        return true
    elseif struct_len == expected_full
        return false
    end

    if expected_omitted == expected_full
        error(
            "Unexpected struct length for topic=$(topic_name): got $struct_len bytes, " *
            "expected $expected_omitted. DATA payload len=$(payload_len)",
        )
    else
        error(
            "Unexpected struct length for topic=$(topic_name): got $struct_len bytes, " *
            "expected $expected_omitted without final padding or $expected_full with " *
            "final padding. DATA payload len=$(payload_len)",
        )
    end
end

function init_columns_for_format!(
    cols::Dict{Symbol, Any},
    fmt::FormatDef,
    formats::Dict{String, FormatDef},
    N::Int;
    prefix::String="",
    repetitions::Int=1,
    top_level::Bool=false,
)::Bool
    has_ts = false

    for f in fmt.fields
        is_padding(f) && continue

        info = primitive_info(f.ulog_type)
        if info === nothing
            nested = format_lookup(formats, f.ulog_type)
            child_has_ts = init_columns_for_format!(
                cols,
                nested,
                formats,
                N;
                prefix=child_prefix(prefix, f.name),
                repetitions=repetitions * field_count(f),
                top_level=false,
            )
            has_ts |= child_has_ts
            continue
        end

        (T, _) = info
        is_top_timestamp = top_level &&
                           isempty(prefix) &&
                           f.name == :timestamp &&
                           f.ulog_type == "uint64_t" &&
                           f.array_len == 0
        if is_top_timestamp
            has_ts = true
            continue
        end

        name = prefixed_name(prefix, f.name)
        if T == UInt8 && f.ulog_type == "char" && f.array_len > 0
            col = repetitions == 1 ?
                Vector{String}(undef, N) :
                Matrix{String}(undef, N, repetitions)
            insert_column!(cols, name, col)
        elseif f.array_len == 0 && repetitions == 1
            insert_column!(cols, name, Vector{T}(undef, N))
        else
            insert_column!(cols, name, Matrix{T}(undef, N, repetitions * field_count(f)))
        end
    end

    return has_ts
end

function init_columns_prealloc(fmt::FormatDef, formats::Dict{String, FormatDef}, N::Int)
    cols = Dict{Symbol, Any}()
    has_ts = init_columns_for_format!(cols, fmt, formats, N; top_level=true)
    ts = has_ts ? Vector{UInt64}(undef, N) : nothing
    return cols, ts
end

function init_columns_prealloc(fmt::FormatDef, N::Int)
    return init_columns_prealloc(fmt, Dict{String, FormatDef}(), N)
end

function decode_primitive_field!(
    f::FieldDef,
    payload::Vector{UInt8},
    i::Int,
    k::Int,
    timestamp::Union{Vector{UInt64}, Nothing},
    cols::Dict{Symbol, Any};
    prefix::String,
    repetition_index::Int,
    repetitions::Int,
    top_level::Bool,
)::Int
    (T, sz) = ulog_primitive(f.ulog_type)
    is_top_timestamp = top_level &&
                       isempty(prefix) &&
                       f.name == :timestamp &&
                       f.ulog_type == "uint64_t" &&
                       f.array_len == 0

    if f.array_len == 0
        x = load_le(T, payload, i)
        i += sz

        if is_top_timestamp
            timestamp === nothing && error("Internal: timestamp column not initialized")
            timestamp[k] = x::UInt64
        elseif repetitions == 1
            cols[prefixed_name(prefix, f.name)][k] = x
        else
            cols[prefixed_name(prefix, f.name)][k, repetition_index] = x
        end
        return i
    end

    n = f.array_len
    name = prefixed_name(prefix, f.name)
    if T == UInt8 && f.ulog_type == "char"
        last_nonzero = i + n - 1
        while last_nonzero >= i && payload[last_nonzero] == 0x00
            last_nonzero -= 1
        end
        str = last_nonzero < i ? "" : String(payload[i:last_nonzero])
        if repetitions == 1
            cols[name][k] = str
        else
            cols[name][k, repetition_index] = str
        end
        return i + n
    end

    M = cols[name]::Matrix{T}
    base_col = (repetition_index - 1) * n
    @inbounds for j in 1:n
        M[k, base_col + j] = load_le(T, payload, i)
        i += sz
    end
    return i
end

function decode_format_into_columns_at!(
    fmt::FormatDef,
    formats::Dict{String, FormatDef},
    payload::Vector{UInt8},
    i::Int,
    k::Int,
    timestamp::Union{Vector{UInt64}, Nothing},
    cols::Dict{Symbol, Any};
    prefix::String="",
    repetition_index::Int=1,
    repetitions::Int=1,
    top_level::Bool=false,
    omit_final_padding::Bool=false,
)::Int
    for (idx, f) in enumerate(fmt.fields)
        if is_padding(f)
            if !(top_level && omit_final_padding && idx == lastindex(fmt.fields))
                (_, sz) = ulog_primitive(f.ulog_type)
                i += sz * field_count(f)
            end
            continue
        end

        info = primitive_info(f.ulog_type)
        if info === nothing
            nested = format_lookup(formats, f.ulog_type)
            n = field_count(f)
            nested_repetitions = repetitions * n
            prefix_child = child_prefix(prefix, f.name)
            for r in 1:n
                child_index = (repetition_index - 1) * n + r
                i = decode_format_into_columns_at!(
                    nested,
                    formats,
                    payload,
                    i,
                    k,
                    timestamp,
                    cols;
                    prefix=prefix_child,
                    repetition_index=child_index,
                    repetitions=nested_repetitions,
                    top_level=false,
                    omit_final_padding=false,
                )
            end
        else
            i = decode_primitive_field!(
                f,
                payload,
                i,
                k,
                timestamp,
                cols;
                prefix=prefix,
                repetition_index=repetition_index,
                repetitions=repetitions,
                top_level=top_level,
            )
        end
    end

    return i
end

function decode_data_into_columns_at!(
    fmt::FormatDef,
    formats::Dict{String, FormatDef},
    payload::Vector{UInt8},
    k::Int,
    timestamp::Union{Vector{UInt64}, Nothing},
    cols::Dict{Symbol, Any};
    omit_final_padding::Bool,
)
    i = decode_format_into_columns_at!(
        fmt,
        formats,
        payload,
        3,
        k,
        timestamp,
        cols;
        top_level=true,
        omit_final_padding=omit_final_padding,
    )
    consumed = i - 3
    expected = length(payload) - 2
    consumed == expected || error(
        "Internal: decoded $consumed struct bytes but payload contains $expected bytes",
    )
    return nothing
end

function decode_data_into_columns_at!(
    fmt::FormatDef,
    payload::Vector{UInt8},
    k::Int,
    timestamp::Union{Vector{UInt64}, Nothing},
    cols::Dict{Symbol, Any},
)
    return decode_data_into_columns_at!(
        fmt,
        Dict{String, FormatDef}(),
        payload,
        k,
        timestamp,
        cols;
        omit_final_padding=true,
    )
end

@inline load_le(::Type{UInt8},  buf::Vector{UInt8}, i::Int) = buf[i]
@inline load_le(::Type{Bool},   buf::Vector{UInt8}, i::Int) = buf[i] != 0x00

@inline function load_le(::Type{Int8}, buf::Vector{UInt8}, i::Int)
    return reinterpret(Int8, buf[i])
end

@inline function load_le(::Type{UInt16}, buf::Vector{UInt8}, i::Int)
    return UInt16(buf[i]) | (UInt16(buf[i+1]) << 8)
end
@inline function load_le(::Type{Int16}, buf::Vector{UInt8}, i::Int)
    return reinterpret(Int16, load_le(UInt16, buf, i))
end

@inline function load_le(::Type{UInt32}, buf::Vector{UInt8}, i::Int)
    return UInt32(buf[i]) |
           (UInt32(buf[i+1]) << 8) |
           (UInt32(buf[i+2]) << 16) |
           (UInt32(buf[i+3]) << 24)
end
@inline function load_le(::Type{Int32}, buf::Vector{UInt8}, i::Int)
    return reinterpret(Int32, load_le(UInt32, buf, i))
end

@inline function load_le(::Type{UInt64}, buf::Vector{UInt8}, i::Int)
    x = UInt64(0)
    @inbounds for k in 0:7
        x |= (UInt64(buf[i+k]) << (8*k))
    end
    return x
end
@inline function load_le(::Type{Int64}, buf::Vector{UInt8}, i::Int)
    return reinterpret(Int64, load_le(UInt64, buf, i))
end

@inline function load_le(::Type{Float32}, buf::Vector{UInt8}, i::Int)
    u = load_le(UInt32, buf, i)
    return reinterpret(Float32, u)
end
@inline function load_le(::Type{Float64}, buf::Vector{UInt8}, i::Int)
    u = load_le(UInt64, buf, i)
    return reinterpret(Float64, u)
end

# -----------------------------------------------------------------------------
# Metadata, parameters, and logged strings
# -----------------------------------------------------------------------------

struct TypedKeyValue
    key::String
    ulog_type::String
    value::Any
end

function parse_type_token(tok::AbstractString)::Tuple{String, Int}
    s = strip(tok)
    m = match(r"^([A-Za-z_][A-Za-z0-9_]*)(?:\[(\d+)\])?$", s)
    m === nothing && error("Invalid ULog type token: '$s'")
    base = String(m.captures[1])
    array_len = m.captures[2] === nothing ? 0 : parse(Int, m.captures[2])
    return base, array_len
end

function trim_nul_string(bytes::Vector{UInt8}, start::Int, len::Int)
    last_nonzero = start + len - 1
    while last_nonzero >= start && bytes[last_nonzero] == 0x00
        last_nonzero -= 1
    end
    last_nonzero < start && return ""
    return String(bytes[start:last_nonzero])
end

function decode_typed_value(ulog_type::AbstractString, payload::Vector{UInt8}, i::Int)
    base_type, array_len = parse_type_token(ulog_type)
    is_array = occursin('[', ulog_type)
    remaining = length(payload) - i + 1
    remaining >= 0 || error("Typed value '$ulog_type' starts past the payload")
    info = primitive_info(base_type)

    if base_type == "char" && is_array
        remaining == array_len || error(
            "Typed value '$ulog_type' has $remaining bytes, expected $array_len",
        )
        return trim_nul_string(payload, i, array_len)
    end

    if info !== nothing && !is_array
        T, size = info
        remaining == size || error(
            "Typed value '$ulog_type' has $remaining bytes, expected $size",
        )
        return load_le(T, payload, i)
    elseif info !== nothing
        _, size = info
        expected = size * array_len
        remaining == expected || error(
            "Typed value '$ulog_type' has $remaining bytes, expected $expected",
        )
    end

    return copy(payload[i:end])
end

function decode_typed_key_value(payload::Vector{UInt8}, start::Int=1)::TypedKeyValue
    start <= length(payload) || error("Typed key/value payload is empty")
    key_len = Int(payload[start])
    key_start = start + 1
    value_start = key_start + key_len
    value_start <= length(payload) + 1 || error("Typed key/value key is truncated")

    type_key = String(payload[key_start:(value_start - 1)])
    parts = split(type_key; limit=2)
    length(parts) == 2 || error("Typed key/value key must be '<type> <name>', got '$type_key'")

    ulog_type = String(parts[1])
    key = String(parts[2])
    value = decode_typed_value(ulog_type, payload, value_start)
    return TypedKeyValue(key, ulog_type, value)
end

function decode_info_multiple(msg::ULogMessage)::Tuple{Bool, TypedKeyValue}
    msg.type == UInt8('M') || error("decode_info_multiple: expected 'M', got $(Char(msg.type))")
    length(msg.payload) >= 2 || error(
        "INFO_MULTIPLE payload too short: $(length(msg.payload)) bytes",
    )
    continued = msg.payload[1] != 0x00
    return continued, decode_typed_key_value(msg.payload, 2)
end

function add_info_multiple!(metadata::ULogMetadata, continued::Bool, kv::TypedKeyValue)
    groups = get!(metadata.info_multiple, kv.key, Vector{Any}[])
    if continued
        isempty(groups) && error(
            "INFO_MULTIPLE continuation for '$(kv.key)' has no preceding chunk",
        )
        push!(groups[end], kv.value)
    else
        push!(groups, Any[kv.value])
    end
    metadata.info_multiple_types[kv.key] = kv.ulog_type
    return nothing
end

function add_default_parameter!(metadata::ULogMetadata, default_types::UInt8, kv::TypedKeyValue)
    iszero(default_types) && error("PARAMETER_DEFAULT has an empty default-types bitfield")
    for bit in 0:7
        if (default_types & UInt8(1 << bit)) != 0
            values = get!(metadata.default_parameters, bit, Dict{String, Any}())
            types = get!(metadata.default_parameter_types, bit, Dict{String, String}())
            values[kv.key] = kv.value
            types[kv.key] = kv.ulog_type
        end
    end
    return nothing
end

function validate_parameter_type(kv::TypedKeyValue, record_name::AbstractString)
    base_type, array_len = parse_type_token(kv.ulog_type)
    is_array = occursin('[', kv.ulog_type)
    valid = !is_array && array_len == 0 &&
            (base_type == "int32_t" || base_type == "float")
    valid || error(
        "$record_name parameter '$(kv.key)' has unsupported type '$(kv.ulog_type)'; " *
        "expected int32_t or float",
    )
    return nothing
end

const LOG_LEVEL_NAMES = Dict{UInt8, Symbol}(
    UInt8('0') => :EMERGENCY,
    UInt8('1') => :ALERT,
    UInt8('2') => :CRITICAL,
    UInt8('3') => :ERROR,
    UInt8('4') => :WARNING,
    UInt8('5') => :NOTICE,
    UInt8('6') => :INFO,
    UInt8('7') => :DEBUG,
)

log_level_name(level::UInt8) = get(LOG_LEVEL_NAMES, level, :UNKNOWN)

function decode_logged_message(msg::ULogMessage)::LoggedMessage
    p = msg.payload
    if msg.type == UInt8('L')
        length(p) >= 9 || error("LOGGING payload too short: $(length(p)) bytes")
        level = p[1]
        timestamp = read_u64_le(p, 2)
        message = length(p) >= 10 ? String(p[10:end]) : ""
        return LoggedMessage(timestamp, level, log_level_name(level), message, nothing)
    elseif msg.type == UInt8('C')
        length(p) >= 11 || error("LOGGING_TAGGED payload too short: $(length(p)) bytes")
        level = p[1]
        tag = read_u16_le(p, 2)
        timestamp = read_u64_le(p, 4)
        message = length(p) >= 12 ? String(p[12:end]) : ""
        return LoggedMessage(timestamp, level, log_level_name(level), message, tag)
    else
        error("decode_logged_message: expected 'L' or 'C', got $(Char(msg.type))")
    end
end

function data_timestamp_or_nothing(
    msg::ULogMessage,
    formats::Dict{String, FormatDef},
    subs_by_id::Dict{UInt16, Subscription},
)::Union{UInt64, Nothing}
    msg.type == UInt8('D') || return nothing
    id = data_msg_id(msg)
    sub = get(subs_by_id, id, nothing)
    sub === nothing && return nothing
    fmt = get(formats, sub.name, nothing)
    fmt === nothing && return nothing

    i = 3
    for f in fmt.fields
        if f.name == :timestamp && f.ulog_type == "uint64_t" && f.array_len == 0
            i + 7 <= length(msg.payload) && return load_le(UInt64, msg.payload, i)
            return nothing
        end

        info = primitive_info(f.ulog_type)
        if info === nothing
            nested = format_lookup(formats, f.ulog_type)
            i += field_count(f) * full_struct_bytes(nested, formats)
        else
            _, sz = info
            i += sz * field_count(f)
        end
        i > length(msg.payload) && return nothing
    end
    return nothing
end

function read_all_metadata(
    path::AbstractString,
    formats::Dict{String, FormatDef},
    subs_by_id::Dict{UInt16, Subscription},
)::ULogMetadata
    open(path, "r") do io
        hdr, flags = read_ulog_preamble!(io)
        metadata = ULogMetadata(; has_default_parameters=(flags.compat_flags[1] & 0x01) != 0)

        data_section_started = false
        last_timestamp = hdr.start_timestamp_us
        for msg in each_message(io)
            if msg.type == UInt8('I')
                kv = decode_typed_key_value(msg.payload)
                metadata.info[kv.key] = kv.value
                metadata.info_types[kv.key] = kv.ulog_type
            elseif msg.type == UInt8('M')
                continued, kv = decode_info_multiple(msg)
                add_info_multiple!(metadata, continued, kv)
            elseif msg.type == UInt8('P')
                kv = decode_typed_key_value(msg.payload)
                validate_parameter_type(kv, "PARAMETER")
                if data_section_started
                    push!(
                        metadata.changed_parameters,
                        ParameterChange(last_timestamp, kv.key, kv.value, kv.ulog_type),
                    )
                else
                    metadata.initial_parameters[kv.key] = kv.value
                    metadata.initial_parameter_types[kv.key] = kv.ulog_type
                end
            elseif msg.type == UInt8('Q')
                length(msg.payload) >= 2 || error(
                    "PARAMETER_DEFAULT payload too short: $(length(msg.payload)) bytes",
                )
                default_types = msg.payload[1]
                kv = decode_typed_key_value(msg.payload, 2)
                validate_parameter_type(kv, "PARAMETER_DEFAULT")
                add_default_parameter!(metadata, default_types, kv)
            elseif msg.type == UInt8('D')
                data_section_started = true
                ts = data_timestamp_or_nothing(msg, formats, subs_by_id)
                ts === nothing || (last_timestamp = ts)
            elseif msg.type == UInt8('A')
                data_section_started = true
            elseif msg.type == UInt8('L') || msg.type == UInt8('C')
                data_section_started = true
                push!(metadata.logged_messages, decode_logged_message(msg))
            elseif msg.type == UInt8('R') || msg.type == UInt8('O') || msg.type == UInt8('S')
                data_section_started = true
            end
        end
        return metadata
    end
end

# -----------------------------------------------------------------------------
# DATA ('D')
# -----------------------------------------------------------------------------

@inline function data_msg_id(msg::ULogMessage)::UInt16
    msg.type == UInt8('D') || error("data_msg_id: expected 'D', got $(Char(msg.type))")
    p = msg.payload
    length(p) >= 2 || error("DATA payload too short: $(length(p)) bytes")
    return UInt16(p[1]) | (UInt16(p[2]) << 8)
end

"""
    count_data_samples(path_or_ulog, msg_id) -> Int

Count complete `DATA` records for one message identifier. This scans the log once and
does not decode the samples.
"""
function count_data_samples(path::AbstractString, msg_id::UInt16)
    n = 0
    open(path, "r") do io
        _ = read_ulog_preamble!(io)
        for msg in each_message(io)
            if msg.type == UInt8('D') && data_msg_id(msg) == msg_id
                n += 1
            end
        end
    end
    return n
end

"""
    read_topic(path_or_ulog, topic_name, multi_id = 0) -> TopicData
    read_topic(ulog, topic_name, multi_id, index) -> TopicData

Decode all samples for one topic instance into preallocated, column-oriented storage.
The non-indexed overload performs a count pass followed by a decode pass. The indexed
overload uses offsets from [`build_data_index`](@ref). Missing subscriptions, malformed
formats, and invalid data payload lengths throw an `ErrorException`.
"""
function read_topic(path::AbstractString, topic_name::AbstractString, multi_id::Integer=0)
    fmts = read_all_formats(path)
    _, subs_by_name = read_all_subscriptions(path)

    key = (String(topic_name), UInt8(multi_id))
    haskey(subs_by_name, key) || error(
        "No subscription for topic=$(topic_name) multi_id=$(multi_id)",
    )
    msg_id = subs_by_name[key]

    haskey(fmts, String(topic_name)) || error("No FORMAT definition found for topic=$(topic_name)")
    fmt = fmts[String(topic_name)]

    N = count_data_samples(path, msg_id)
    cols, ts = init_columns_prealloc(fmt, fmts, N)

    expected_omitted = expected_struct_bytes(fmt, fmts)
    expected_full = full_struct_bytes(fmt, fmts)

    k = 0
    open(path, "r") do io
        _ = read_ulog_preamble!(io)
        for msg in each_message(io)
            if msg.type == UInt8('D') && data_msg_id(msg) == msg_id
                k += 1
                p = msg.payload
                omit_final_padding = final_padding_omitted(
                    length(p) - 2,
                    expected_omitted,
                    expected_full,
                    topic_name,
                    length(p),
                )
                decode_data_into_columns_at!(
                    fmt,
                    fmts,
                    p,
                    k,
                    ts,
                    cols;
                    omit_final_padding=omit_final_padding,
                )
            end
        end
    end

    k == N || error("Internal: counted N=$N samples but decoded k=$k")

    return TopicData(String(topic_name), UInt8(multi_id), ts, cols)
end

"""
    audit_data_lengths(path, topic_name, multi_id = 0; max_hits = 200)

Print observed and expected `DATA` payload lengths for a topic and return
`((bytes_without_final_padding, bytes_with_final_padding), observed_counts)`.
At most `max_hits` samples are inspected.
"""
function audit_data_lengths(
    path::AbstractString,
    topic_name::AbstractString,
    multi_id::Integer = 0;
    max_hits::Int = 200,
)
    fmts = read_all_formats(path)
    _, subs_by_name = read_all_subscriptions(path)

    key = (String(topic_name), UInt8(multi_id))
    haskey(subs_by_name, key) || error(
        "No subscription for topic=$(topic_name) multi_id=$(multi_id)",
    )
    msg_id = subs_by_name[key]

    haskey(fmts, String(topic_name)) || error("No FORMAT definition found for topic=$(topic_name)")
    fmt = fmts[String(topic_name)]

    expected_omitted = expected_struct_bytes(fmt, fmts)
    expected_full = full_struct_bytes(fmt, fmts)

    lengths = Dict{Int,Int}()
    hits = 0

    open(path, "r") do io
        _ = read_ulog_preamble!(io)
        for msg in each_message(io)
            if msg.type == UInt8('D') && data_msg_id(msg) == msg_id
                hits += 1
                L = length(msg.payload)
                lengths[L] = get(lengths, L, 0) + 1
                hits >= max_hits && break
            end
        end
    end

    println("Topic: $(topic_name) multi_id=$(multi_id)")
    println("msg_id: $(msg_id)")
    println("Expected struct bytes without final padding: $expected_omitted")
    println("Expected struct bytes with final padding: $expected_full")
    println("Expected DATA payload bytes: $(2 + expected_omitted) or $(2 + expected_full)")
    println("Observed DATA payload lengths (bytes):")
    for (L, c) in sort(collect(lengths); by=x->x[1])
        println("  $L : $c")
    end

    return (expected_omitted, expected_full), lengths
end

# -----------------------------------------------------------------------------
# ULog object API
# -----------------------------------------------------------------------------

"""
    ULog(path)

Open a standard ULog file and eagerly read its header, validated format graph, topic
subscriptions, and metadata. Topic `DATA` records remain on disk until [`read_topic`](@ref)
is called. Invalid headers, unsupported incompatibility flags, malformed formats, and
malformed metadata throw an `ErrorException`.
"""
struct ULog
    path::String
    header::ULogHeader
    formats::Dict{String, FormatDef}
    subs_by_id::Dict{UInt16, Subscription}
    subs_by_name::Dict{Tuple{String,UInt8}, UInt16}
    metadata::ULogMetadata
end

function ULog(path::AbstractString)
    p = String(path)
    hdr = open(p, "r") do io
        hdr, _ = read_ulog_preamble!(io)
        hdr
    end
    fmts = read_all_formats(p)
    subs_by_id, subs_by_name = read_all_subscriptions(p)
    metadata = read_all_metadata(p, fmts, subs_by_id)
    return ULog(p, hdr, fmts, subs_by_id, subs_by_name, metadata)
end

"""
    info_messages(ulog) -> Dict{String,Any}

Return the mutable dictionary of decoded `INFO` values.
"""
info_messages(ulog::ULog) = ulog.metadata.info

"""
    info_types(ulog) -> Dict{String,String}

Return the mutable dictionary mapping `INFO` keys to their original ULog type strings.
"""
info_types(ulog::ULog) = ulog.metadata.info_types

"""
    info_multiple(ulog) -> Dict{String,Vector{Vector{Any}}}

Return grouped `INFO_MULTIPLE` chunks. Each outer entry is a logical message and each
inner vector contains its continued chunks. The returned dictionary is mutable.
"""
info_multiple(ulog::ULog) = ulog.metadata.info_multiple

"""
    info_message(ulog, key; default = nothing)

Return one decoded `INFO` value, or `default` when `key` is absent.
"""
info_message(ulog::ULog, key::AbstractString; default=nothing) =
    get(ulog.metadata.info, String(key), default)

"""
    initial_parameters(ulog) -> Dict{String,Any}

Return the mutable dictionary of parameters recorded before the data section.
"""
initial_parameters(ulog::ULog) = ulog.metadata.initial_parameters

"""
    changed_parameters(ulog) -> Vector{ParameterChange}

Return parameter updates recorded after the data section starts. The vector is mutable
and remains in file order.
"""
changed_parameters(ulog::ULog) = ulog.metadata.changed_parameters

function default_parameter_index(which::Symbol)::Int
    which === :system && return 0
    which === :current_setup && return 1
    error(
        "Unknown default parameter set: $which. Use :system, :current_setup, " *
        "or an integer bit index.",
    )
end

"""
    default_parameters(ulog, which = :system) -> Dict{String,Any}

Return default parameter values for `:system`, `:current_setup`, or an integer bit
index. An absent set returns a new empty dictionary. Unknown symbols throw an
`ErrorException`.
"""
function default_parameters(ulog::ULog, which::Symbol=:system)
    return default_parameters(ulog, default_parameter_index(which))
end

function default_parameters(ulog::ULog, which::Integer)
    return get(ulog.metadata.default_parameters, Int(which), Dict{String, Any}())
end

"""
    has_default_parameters(ulog) -> Bool

Return whether the log advertises or contains default parameter records.
"""
has_default_parameters(ulog::ULog) =
    ulog.metadata.has_default_parameters || !isempty(ulog.metadata.default_parameters)

"""
    logged_messages(ulog; tag = nothing) -> Vector{LoggedMessage}

Return logged strings in file order. Supplying `tag` returns a new vector containing
only matching tagged messages; without a tag, the metadata's mutable vector is returned.
"""
function logged_messages(ulog::ULog; tag=nothing)
    msgs = ulog.metadata.logged_messages
    tag === nothing && return msgs
    tag_value = UInt16(tag)
    return [msg for msg in msgs if msg.tag == tag_value]
end

"""
    topics(ulog) -> Vector{Tuple{String,UInt8}}

Return all subscribed `(topic_name, multi_id)` pairs in deterministic sorted order.
"""
function topics(ulog::ULog)
    ks = collect(keys(ulog.subs_by_name))
    sort!(ks; by = x -> (x[1], x[2]))
    return ks
end

function count_data_samples(ulog::ULog, msg_id::UInt16)
    n = 0
    open(ulog.path, "r") do io
        _ = read_ulog_preamble!(io)
        for msg in each_message(io)
            if msg.type == UInt8('D') && data_msg_id(msg) == msg_id
                n += 1
            end
        end
    end
    return n
end

function read_topic(ulog::ULog, topic_name::AbstractString, multi_id::Integer=0)
    key = (String(topic_name), UInt8(multi_id))
    haskey(ulog.subs_by_name, key) || error(
        "No subscription for topic=$(topic_name) multi_id=$(multi_id)",
    )
    msg_id = ulog.subs_by_name[key]

    haskey(ulog.formats, String(topic_name)) || error(
        "No FORMAT definition found for topic=$(topic_name)",
    )
    fmt = ulog.formats[String(topic_name)]

    N = count_data_samples(ulog, msg_id)
    cols, ts = init_columns_prealloc(fmt, ulog.formats, N)

    expected_omitted = expected_struct_bytes(fmt, ulog.formats)
    expected_full = full_struct_bytes(fmt, ulog.formats)

    k = 0
    open(ulog.path, "r") do io
        _ = read_ulog_preamble!(io)
        for msg in each_message(io)
            if msg.type == UInt8('D') && data_msg_id(msg) == msg_id
                k += 1
                p = msg.payload
                omit_final_padding = final_padding_omitted(
                    length(p) - 2,
                    expected_omitted,
                    expected_full,
                    topic_name,
                    length(p),
                )
                decode_data_into_columns_at!(
                    fmt,
                    ulog.formats,
                    p,
                    k,
                    ts,
                    cols;
                    omit_final_padding=omit_final_padding,
                )
            end
        end
    end

    k == N || error("Internal: counted N=$N samples but decoded k=$k")
    return TopicData(String(topic_name), UInt8(multi_id), ts, cols)
end

"""
    build_data_index(ulog) -> Dict{UInt16,Vector{Int64}}

Scan a log once and return zero-based file offsets for every `DATA` message identifier.
Use the result with indexed [`read_topic`](@ref) calls to avoid repeated full scans.
"""
function build_data_index(ulog::ULog)
    index = Dict{UInt16, Vector{Int64}}()
    open(ulog.path, "r") do io
        _ = read_ulog_preamble!(io)
        for msg in each_message(io)
            if msg.type == UInt8('D')
                id = data_msg_id(msg)
                v = get!(index, id, Int64[])
                push!(v, msg.offset)
            end
        end
    end
    return index
end

function read_topic(
    ulog::ULog,
    topic_name::AbstractString,
    multi_id::Integer,
    index::Dict{UInt16, Vector{Int64}},
)
    key = (String(topic_name), UInt8(multi_id))
    haskey(ulog.subs_by_name, key) || error(
        "No subscription for topic=$(topic_name) multi_id=$(multi_id)",
    )
    msg_id = ulog.subs_by_name[key]

    haskey(ulog.formats, String(topic_name)) || error(
        "No FORMAT definition found for topic=$(topic_name)",
    )
    fmt = ulog.formats[String(topic_name)]

    offsets = get(index, msg_id, Int64[])
    N = length(offsets)
    cols, ts = init_columns_prealloc(fmt, ulog.formats, N)

    expected_omitted = expected_struct_bytes(fmt, ulog.formats)
    expected_full = full_struct_bytes(fmt, ulog.formats)

    open(ulog.path, "r") do io
        for (k, off) in enumerate(offsets)
            seek(io, off)
            msg = read_message_at!(io)
            msg.type == UInt8('D') || error(
                "Index corruption: offset $off not DATA (type=$(Char(msg.type)))",
            )
            data_msg_id(msg) == msg_id || error(
                "Index corruption: DATA at offset $off has wrong msg_id",
            )

            p = msg.payload
            omit_final_padding = final_padding_omitted(
                length(p) - 2,
                expected_omitted,
                expected_full,
                topic_name,
                length(p),
            )
            decode_data_into_columns_at!(
                fmt,
                ulog.formats,
                p,
                k,
                ts,
                cols;
                omit_final_padding=omit_final_padding,
            )
        end
    end

    return TopicData(String(topic_name), UInt8(multi_id), ts, cols)
end

# -----------------------------------------------------------------------------
# TopicData ergonomics
# -----------------------------------------------------------------------------

Base.propertynames(td::TopicData; private::Bool=false) =
    private ? (:topic, :multi_id, :timestamp, :cols) :
              (:topic, :multi_id, :timestamp, keys(td.cols)...)

function Base.getproperty(td::TopicData, name::Symbol)
    if name === :topic || name === :multi_id || name === :timestamp || name === :cols
        return getfield(td, name)
    end
    cols = getfield(td, :cols)
    if haskey(cols, name)
        return cols[name]
    end
    error("TopicData has no field/column named $(name). Available: $(collect(keys(cols)))")
end

Base.getindex(td::TopicData, name::Symbol) = getproperty(td, name)

"""
    time_seconds(td; t0_us = nothing) -> Vector{Float64}
    time_seconds(td, ulog) -> Vector{Float64}

Convert topic timestamps from microseconds to seconds relative to the first sample, an
explicit `t0_us`, or the ULog start timestamp. Empty timestamp columns return an empty
`Float64` vector. Topics without a timestamp field throw an `ErrorException`.
"""
function time_seconds(td::TopicData; t0_us::Union{UInt64,Nothing}=nothing)
    ts = td.timestamp
    ts === nothing && error("Topic has no :timestamp field")
    isempty(ts) && return Float64[]
    t0 = t0_us === nothing ? ts[1] : t0_us
    return (Float64.(ts) .- Float64(t0)) .* 1e-6
end

function time_seconds(td::TopicData, ulog::ULog)
    td.timestamp === nothing && error("Topic has no :timestamp")
    t0 = ulog.header.start_timestamp_us
    return (Float64.(td.timestamp) .- Float64(t0)) .* 1e-6
end

end # module PX4ULog
