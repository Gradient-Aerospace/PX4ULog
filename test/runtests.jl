using Test
using PX4ULog
using DataFrames

const ULOG_MAGIC_BYTES = UInt8[0x55, 0x4c, 0x6f, 0x67, 0x01, 0x12, 0x35]

function push_le!(bytes::Vector{UInt8}, x::UInt16)
    push!(bytes, UInt8(x & 0x00ff))
    push!(bytes, UInt8(x >> 8))
    return bytes
end

function push_le!(bytes::Vector{UInt8}, x::UInt64)
    for shift in 0:8:56
        push!(bytes, UInt8((x >> shift) & 0xff))
    end
    return bytes
end

function message_bytes(msg_type::Char, payload::Vector{UInt8})
    bytes = UInt8[]
    push_le!(bytes, UInt16(length(payload)))
    push!(bytes, UInt8(msg_type))
    append!(bytes, payload)
    return bytes
end

format_payload(s::AbstractString) = collect(codeunits(s))

function add_subscription_payload(multi_id::UInt8, msg_id::UInt16, name::AbstractString)
    bytes = UInt8[multi_id]
    push_le!(bytes, msg_id)
    append!(bytes, codeunits(name))
    return bytes
end

function flag_bits_payload(; incompat_first::UInt8=0x00, appended_offset::UInt64=UInt64(0))
    bytes = zeros(UInt8, 40)
    bytes[9] = incompat_first
    if appended_offset != 0
        offset_bytes = UInt8[]
        push_le!(offset_bytes, appended_offset)
        bytes[17:24] .= offset_bytes
    end
    return bytes
end

function write_header!(io; magic=ULOG_MAGIC_BYTES)
    write(io, magic)
    write(io, UInt8[0x01])
    timestamp_us = UInt64(1_000_000)
    bytes = UInt8[]
    push_le!(bytes, timestamp_us)
    write(io, bytes)
    return nothing
end

function nested_data_payload()
    bytes = UInt8[]
    push_le!(bytes, UInt16(0))
    push_le!(bytes, UInt64(2_000_000))
    push!(bytes, 0xaa)             # non-final top-level padding, must be consumed

    push_le!(bytes, UInt16(0x1234))
    append!(bytes, UInt8[0x00, 0x00])
    push!(bytes, 0x42)
    push!(bytes, 0xee)             # final nested padding, still serialized

    push_le!(bytes, UInt16(0x5678))
    append!(bytes, UInt8[0x00, 0x00])
    push!(bytes, 0x24)
    push!(bytes, 0xdd)             # final nested padding, still serialized

    # The top-level final padding from `outer` is intentionally omitted.
    return bytes
end

function write_nested_fixture(path; incompat_first::UInt8=0x00, appended_offset::UInt64=UInt64(0), magic=ULOG_MAGIC_BYTES, truncated_tail::Bool=false)
    open(path, "w") do io
        write_header!(io; magic=magic)
        write(io, message_bytes('B', flag_bits_payload(; incompat_first=incompat_first, appended_offset=appended_offset)))
        write(io, message_bytes('F', format_payload("inner:uint16_t a;uint8_t[2] _padding0;uint8_t b;uint8_t[1] _padding1;")))
        write(io, message_bytes('F', format_payload("outer:uint64_t timestamp;uint8_t[1] _padding0;inner[2] inner;uint8_t[3] _padding1;")))
        write(io, message_bytes('A', add_subscription_payload(0x00, UInt16(0), "outer")))
        write(io, message_bytes('D', nested_data_payload()))

        if truncated_tail
            write(io, UInt8[0x05, 0x00, UInt8('D'), 0x00])
        end
    end
    return path
end

@testset "PX4ULog parser" begin
    mktempdir() do dir
        path = joinpath(dir, "nested.ulg")
        write_nested_fixture(path)

        ulog = PX4ULog.ULog(path)
        @test ulog.header.magic_ok
        @test PX4ULog.topics(ulog) == [("outer", UInt8(0))]

        td = PX4ULog.read_topic(ulog, "outer", 0)
        @test td.timestamp == UInt64[2_000_000]
        @test sort(collect(keys(td.cols)); by=String) == [:inner_a, :inner_b]
        @test td.inner_a == reshape(UInt16[0x1234, 0x5678], 1, 2)
        @test td.inner_b == reshape(UInt8[0x42, 0x24], 1, 2)
        @test PX4ULog.time_seconds(td) == [0.0]

        index = PX4ULog.build_data_index(ulog)
        indexed = PX4ULog.read_topic(ulog, "outer", 0, index)
        @test indexed.inner_a == td.inner_a
        @test indexed.inner_b == td.inner_b

        df = PX4ULog.to_dataframe(td; time_s=true)
        @test names(df) == ["timestamp", "t", "inner_a_1", "inner_a_2", "inner_b_1", "inner_b_2"]
        @test df.t == [0.0]
        @test df.inner_a_1 == UInt16[0x1234]
        @test df.inner_b_2 == UInt8[0x24]
    end
end

@testset "Validation and truncation" begin
    mktempdir() do dir
        bad_magic = joinpath(dir, "bad_magic.ulg")
        write_nested_fixture(bad_magic; magic=UInt8[0x00, ULOG_MAGIC_BYTES[2:end]...])
        @test_throws ErrorException PX4ULog.ULog(bad_magic)

        bad_flags = joinpath(dir, "bad_flags.ulg")
        write_nested_fixture(bad_flags; incompat_first=0x02)
        @test_throws ErrorException PX4ULog.ULog(bad_flags)

        appended = joinpath(dir, "appended.ulg")
        write_nested_fixture(appended; incompat_first=0x01, appended_offset=UInt64(128))
        @test_throws ErrorException PX4ULog.ULog(appended)

        truncated = joinpath(dir, "truncated.ulg")
        write_nested_fixture(truncated; truncated_tail=true)
        td = PX4ULog.read_topic(truncated, "outer", 0)
        @test td.timestamp == UInt64[2_000_000]
        @test td.inner_a == reshape(UInt16[0x1234, 0x5678], 1, 2)
    end
end
