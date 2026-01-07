module PX4ULog

export ULogHeader, ULogMessage, read_ulog_header, each_message, scan_messages
export FieldDef, FormatDef, scan_formats, read_all_formats, parse_format_string
export Subscription, scan_subscriptions, read_all_subscriptions
export TopicData, read_topic, count_data_samples
export ULog, topics, build_data_index
export time_seconds
export audit_data_lengths
export to_dataframe

using Printf

# -----------------------------------------------------------------------------
# Public stubs (extensions)
# -----------------------------------------------------------------------------

"""
Convert TopicData to a DataFrame. Methods are provided by an extension when
DataFrames is loaded.
"""
function to_dataframe end

# -----------------------------------------------------------------------------
# Types
# -----------------------------------------------------------------------------

"""
Represents the fixed header area at the start of a ULog file.
"""
struct ULogHeader
    magic_ok::Bool
    version::UInt8
    start_timestamp_us::UInt64
    raw::NTuple{16,UInt8}
end

const ULOG_MAGIC = UInt8[0x55, 0x4c, 0x6f, 0x67, 0x01, 0x12, 0x35]  # "ULog" + 0x01 0x12 0x35

"""
Represents a single ULog message record.
- size: msg_size field from the file (little-endian)
- type: UInt8 message type (typically ASCII)
- payload: raw payload bytes
- offset: file offset where msg_size starts
"""
struct ULogMessage
    offset::Int64
    size::UInt16
    type::UInt8
    payload::Vector{UInt8}
end

"""
Field definition from a FORMAT message.
- `name`: field name
- `ulog_type`: primitive token (e.g. "uint64_t", "float", "bool", "char")
- `array_len`: 0 = scalar, >0 = fixed array
"""
struct FieldDef
    name::Symbol
    ulog_type::String
    array_len::Int
end

"""
Format definition from a FORMAT message.
"""
struct FormatDef
    name::String
    fields::Vector{FieldDef}
end

struct Subscription
    msg_id::UInt16
    multi_id::UInt8
    name::String
end

struct TopicData
    topic::String
    multi_id::UInt8
    timestamp::Union{Vector{UInt64}, Nothing}
    cols::Dict{Symbol, Any}   # Symbol => Vector{T} or Matrix{T} or Vector{String}, etc.
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

# -----------------------------------------------------------------------------
# Message iteration
# -----------------------------------------------------------------------------

"""
Iterate ULog messages from the current IO position.

We interpret msg_size as the number of bytes in payload following msg_type.
This matches the behavior you validated on your .ulg.
"""
function each_message(io::IO)
    return Channel{ULogMessage}(32) do ch
        while !eof(io)
            offset = position(io)

            msg_size = try
                read_u16_le(io)
            catch e
                if e isa EOFError
                    break
                else
                    rethrow()
                end
            end

            msg_type = read_u8(io)

            payload_len = Int(msg_size)
            payload = payload_len == 0 ? UInt8[] : read(io, payload_len)

            put!(ch, ULogMessage(offset, msg_size, msg_type, payload))
        end
    end
end

"""
Read a single ULog record at the current file position.
Assumes position(io) is at the start of the message header (msg_size field).
"""
function read_message_at!(io::IO)::ULogMessage
    offset = position(io)
    msg_size = read_u16_le(io)
    msg_type = read_u8(io)
    payload = msg_size == 0 ? UInt8[] : read(io, Int(msg_size))
    return ULogMessage(offset, msg_size, msg_type, payload)
end

# -----------------------------------------------------------------------------
# Debug scan: message counts
# -----------------------------------------------------------------------------

function scan_messages(path::AbstractString; max_messages::Int=2000, show_types::Bool=true)
    open(path, "r") do io
        hdr = read_ulog_header(io)
        println("ULog header:")
        println("  magic_ok            = $(hdr.magic_ok)")
        println("  version             = $(hdr.version)")
        println("  start_timestamp_us  = $(hdr.start_timestamp_us)")
        println()

        counts = Dict{UInt8, Int}()
        n = 0
        for msg in each_message(io)
            n += 1
            counts[msg.type] = get(counts, msg.type, 0) + 1

            if n <= 20
                @printf("msg %5d  off=%10d  type=%c (0x%02x)  size=%d  payload=%d\n",
                        n, msg.offset, ascii_type(msg.type), msg.type, msg.size, length(msg.payload))
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

function read_all_formats(path::AbstractString)
    open(path, "r") do io
        _ = read_ulog_header(io)
        formats = Dict{String, FormatDef}()

        for msg in each_message(io)
            if msg.type == UInt8('F')
                s = decode_format(msg)
                fd = parse_format_string(s)
                formats[fd.name] = fd
            end
        end

        return formats
    end
end

function scan_formats(path::AbstractString; max_formats::Int=20)
    open(path, "r") do io
        _ = read_ulog_header(io)

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

function read_all_subscriptions(path::AbstractString)
    open(path, "r") do io
        _ = read_ulog_header(io)

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

function scan_subscriptions(path::AbstractString; max_subs::Int=30)
    open(path, "r") do io
        _ = read_ulog_header(io)
        n = 0
        for msg in each_message(io)
            if msg.type == UInt8('A')
                n += 1
                sub = decode_add_logged_msg(msg)
                @printf("A[%3d] msg_id=%5d  multi_id=%d  name=%s\n", n, sub.msg_id, sub.multi_id, sub.name)
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

function ulog_primitive(t::AbstractString)
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
    error("Unsupported/unknown ULog primitive type: '$s'")
end

@inline load_le(::Type{UInt8},  buf::Vector{UInt8}, i::Int) = buf[i]
@inline load_le(::Type{Bool},   buf::Vector{UInt8}, i::Int) = buf[i] != 0x00

@inline function load_le(::Type{Int8}, buf::Vector{UInt8}, i::Int)
    return reinterpret(Int8, buf[i:i])[1]
end

@inline function load_le(::Type{UInt16}, buf::Vector{UInt8}, i::Int)
    return UInt16(buf[i]) | (UInt16(buf[i+1]) << 8)
end
@inline function load_le(::Type{Int16}, buf::Vector{UInt8}, i::Int)
    return reinterpret(Int16, load_le(UInt16, buf, i))[1]
end

@inline function load_le(::Type{UInt32}, buf::Vector{UInt8}, i::Int)
    return UInt32(buf[i]) |
           (UInt32(buf[i+1]) << 8) |
           (UInt32(buf[i+2]) << 16) |
           (UInt32(buf[i+3]) << 24)
end
@inline function load_le(::Type{Int32}, buf::Vector{UInt8}, i::Int)
    return reinterpret(Int32, load_le(UInt32, buf, i))[1]
end

@inline function load_le(::Type{UInt64}, buf::Vector{UInt8}, i::Int)
    x = UInt64(0)
    @inbounds for k in 0:7
        x |= (UInt64(buf[i+k]) << (8*k))
    end
    return x
end
@inline function load_le(::Type{Int64}, buf::Vector{UInt8}, i::Int)
    return reinterpret(Int64, load_le(UInt64, buf, i))[1]
end

@inline function load_le(::Type{Float32}, buf::Vector{UInt8}, i::Int)
    u = load_le(UInt32, buf, i)
    return reinterpret(Float32, u)[1]
end
@inline function load_le(::Type{Float64}, buf::Vector{UInt8}, i::Int)
    u = load_le(UInt64, buf, i)
    return reinterpret(Float64, u)[1]
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

function expected_struct_bytes(fmt::FormatDef)::Int
    total = 0
    for f in fmt.fields
        if startswith(String(f.name), "_padding")
            continue
        end
        (_, sz) = ulog_primitive(f.ulog_type)
        n = f.array_len == 0 ? 1 : f.array_len
        total += sz * n
    end
    return total
end

function nonpadding_fields(fmt::FormatDef)
    return [f for f in fmt.fields if !startswith(String(f.name), "_padding")]
end

function init_columns_prealloc(fmt::FormatDef, N::Int)
    cols = Dict{Symbol, Any}()
    has_ts = false

    for f in nonpadding_fields(fmt)
        if f.name == :timestamp && f.ulog_type == "uint64_t" && f.array_len == 0
            has_ts = true
            continue
        end

        (T, _) = ulog_primitive(f.ulog_type)

        if f.array_len == 0
            cols[f.name] = Vector{T}(undef, N)
        else
            if T == UInt8 && f.ulog_type == "char"
                cols[f.name] = Vector{String}(undef, N)
            else
                cols[f.name] = Matrix{T}(undef, N, f.array_len)
            end
        end
    end

    ts = has_ts ? Vector{UInt64}(undef, N) : nothing
    return cols, ts
end

function decode_data_into_columns_at!(
    fmt::FormatDef,
    payload::Vector{UInt8},
    k::Int,
    timestamp::Union{Vector{UInt64}, Nothing},
    cols::Dict{Symbol, Any},
)
    i = 3  # after msg_id (2 bytes)

    for f in fmt.fields
        if startswith(String(f.name), "_padding")
            continue
        end

        (T, sz) = ulog_primitive(f.ulog_type)

        if f.array_len == 0
            x = load_le(T, payload, i)
            i += sz

            if f.name == :timestamp && f.ulog_type == "uint64_t"
                timestamp === nothing && error("Internal: timestamp column not initialized")
                timestamp[k] = x::UInt64
            else
                cols[f.name][k] = x
            end
        else
            n = f.array_len

            if T == UInt8 && f.ulog_type == "char"
                bytes = payload[i:(i+n-1)]
                lastnz = findlast(!=(0x00), bytes)
                cols[f.name][k] = lastnz === nothing ? "" : String(bytes[1:lastnz])
                i += n
            else
                M = cols[f.name]::Matrix{T}
                @inbounds for j in 1:n
                    M[k, j] = load_le(T, payload, i)
                    i += sz
                end
            end
        end
    end

    return nothing
end

function count_data_samples(path::AbstractString, msg_id::UInt16)
    n = 0
    open(path, "r") do io
        _ = read_ulog_header(io)
        for msg in each_message(io)
            if msg.type == UInt8('D') && data_msg_id(msg) == msg_id
                n += 1
            end
        end
    end
    return n
end

"""
Read a topic from a path into TopicData (fast two-pass, preallocated).
"""
function read_topic(path::AbstractString, topic_name::AbstractString, multi_id::Integer=0)
    fmts = read_all_formats(path)
    _, subs_by_name = read_all_subscriptions(path)

    key = (String(topic_name), UInt8(multi_id))
    haskey(subs_by_name, key) || error("No subscription for topic=$(topic_name) multi_id=$(multi_id)")
    msg_id = subs_by_name[key]

    haskey(fmts, String(topic_name)) || error("No FORMAT definition found for topic=$(topic_name)")
    fmt = fmts[String(topic_name)]

    N = count_data_samples(path, msg_id)
    cols, ts = init_columns_prealloc(fmt, N)

    exp = expected_struct_bytes(fmt)
    checked_len = false

    k = 0
    open(path, "r") do io
        _ = read_ulog_header(io)
        for msg in each_message(io)
            if msg.type == UInt8('D') && data_msg_id(msg) == msg_id
                k += 1
                p = msg.payload
                if !checked_len
                    struct_len = length(p) - 2
                    if struct_len != exp
                        error("Unexpected struct length for topic=$(topic_name): got $struct_len bytes, expected $exp (excluding padding). DATA payload len=$(length(p))")
                    end
                    checked_len = true
                end
                decode_data_into_columns_at!(fmt, p, k, ts, cols)
            end
        end
    end

    k == N || error("Internal: counted N=$N samples but decoded k=$k")

    return TopicData(String(topic_name), UInt8(multi_id), ts, cols)
end

function audit_data_lengths(path::AbstractString, topic_name::AbstractString, multi_id::Integer=0; max_hits::Int=200)
    fmts = read_all_formats(path)
    _, subs_by_name = read_all_subscriptions(path)

    key = (String(topic_name), UInt8(multi_id))
    haskey(subs_by_name, key) || error("No subscription for topic=$(topic_name) multi_id=$(multi_id)")
    msg_id = subs_by_name[key]

    haskey(fmts, String(topic_name)) || error("No FORMAT definition found for topic=$(topic_name)")
    fmt = fmts[String(topic_name)]

    expected = 0
    for f in fmt.fields
        (T, sz) = ulog_primitive(f.ulog_type)
        n = f.array_len == 0 ? 1 : f.array_len
        expected += sz * n
    end

    lengths = Dict{Int,Int}()
    hits = 0

    open(path, "r") do io
        _ = read_ulog_header(io)
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
    println("Expected struct bytes (from FORMAT): $expected")
    println("Expected DATA payload bytes (2 + struct): $(2 + expected)")
    println("Observed DATA payload lengths (bytes):")
    for (L, c) in sort(collect(lengths); by=x->x[1])
        println("  $L : $c")
    end

    return expected, lengths
end

# -----------------------------------------------------------------------------
# ULog object API
# -----------------------------------------------------------------------------

struct ULog
    path::String
    header::ULogHeader
    formats::Dict{String, FormatDef}
    subs_by_id::Dict{UInt16, Subscription}
    subs_by_name::Dict{Tuple{String,UInt8}, UInt16}
end

function ULog(path::AbstractString)
    p = String(path)
    hdr = open(p, "r") do io
        read_ulog_header(io)
    end
    fmts = read_all_formats(p)
    subs_by_id, subs_by_name = read_all_subscriptions(p)
    return ULog(p, hdr, fmts, subs_by_id, subs_by_name)
end

function topics(ulog::ULog)
    ks = collect(keys(ulog.subs_by_name))
    sort!(ks; by = x -> (x[1], x[2]))
    return ks
end

function count_data_samples(ulog::ULog, msg_id::UInt16)
    n = 0
    open(ulog.path, "r") do io
        _ = read_ulog_header(io)
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
    haskey(ulog.subs_by_name, key) || error("No subscription for topic=$(topic_name) multi_id=$(multi_id)")
    msg_id = ulog.subs_by_name[key]

    haskey(ulog.formats, String(topic_name)) || error("No FORMAT definition found for topic=$(topic_name)")
    fmt = ulog.formats[String(topic_name)]

    N = count_data_samples(ulog, msg_id)
    cols, ts = init_columns_prealloc(fmt, N)

    exp = expected_struct_bytes(fmt)
    checked_len = false

    k = 0
    open(ulog.path, "r") do io
        _ = read_ulog_header(io)
        for msg in each_message(io)
            if msg.type == UInt8('D') && data_msg_id(msg) == msg_id
                k += 1
                p = msg.payload
                if !checked_len
                    struct_len = length(p) - 2
                    if struct_len != exp
                        error("Unexpected struct length for topic=$(topic_name): got $struct_len bytes, expected $exp (excluding padding). DATA payload len=$(length(p))")
                    end
                    checked_len = true
                end
                decode_data_into_columns_at!(fmt, p, k, ts, cols)
            end
        end
    end

    k == N || error("Internal: counted N=$N samples but decoded k=$k")
    return TopicData(String(topic_name), UInt8(multi_id), ts, cols)
end

function build_data_index(ulog::ULog)
    index = Dict{UInt16, Vector{Int64}}()
    open(ulog.path, "r") do io
        _ = read_ulog_header(io)
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

function read_topic(ulog::ULog, topic_name::AbstractString, multi_id::Integer, index::Dict{UInt16, Vector{Int64}})
    key = (String(topic_name), UInt8(multi_id))
    haskey(ulog.subs_by_name, key) || error("No subscription for topic=$(topic_name) multi_id=$(multi_id)")
    msg_id = ulog.subs_by_name[key]

    haskey(ulog.formats, String(topic_name)) || error("No FORMAT definition found for topic=$(topic_name)")
    fmt = ulog.formats[String(topic_name)]

    offsets = get(index, msg_id, Int64[])
    N = length(offsets)
    cols, ts = init_columns_prealloc(fmt, N)

    exp = expected_struct_bytes(fmt)
    checked_len = false

    open(ulog.path, "r") do io
        for (k, off) in enumerate(offsets)
            seek(io, off)
            msg = read_message_at!(io)
            msg.type == UInt8('D') || error("Index corruption: offset $off not DATA (type=$(Char(msg.type)))")
            data_msg_id(msg) == msg_id || error("Index corruption: DATA at offset $off has wrong msg_id")

            p = msg.payload
            if !checked_len
                struct_len = length(p) - 2
                if struct_len != exp
                    error("Unexpected struct length for topic=$(topic_name): got $struct_len bytes, expected $exp (excluding padding). DATA payload len=$(length(p))")
                end
                checked_len = true
            end

            decode_data_into_columns_at!(fmt, p, k, ts, cols)
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

function time_seconds(td::TopicData; t0_us::Union{UInt64,Nothing}=nothing)
    ts = td.timestamp
    ts === nothing && error("Topic has no :timestamp field")
    t0 = t0_us === nothing ? ts[1] : t0_us
    return (Float64.(ts) .- Float64(t0)) .* 1e-6
end

function time_seconds(td::TopicData, ulog::ULog)
    td.timestamp === nothing && error("Topic has no :timestamp")
    t0 = ulog.header.start_timestamp_us
    return (Float64.(td.timestamp) .- Float64(t0)) .* 1e-6
end

end # module PX4ULog
