using Test
using PX4ULog
using DataFrames
using StaticArrays: SVector
using SystemsOfSystems: SampleAndHold, select

const ULOG_MAGIC_BYTES = UInt8[0x55, 0x4c, 0x6f, 0x67, 0x01, 0x12, 0x35]

push_le!(bytes::Vector{UInt8}, x::UInt8) = (push!(bytes, x); bytes)
push_le!(bytes::Vector{UInt8}, x::Int8) = push_le!(bytes, reinterpret(UInt8, x))
push_le!(bytes::Vector{UInt8}, x::Bool) = push_le!(bytes, UInt8(x))

function push_le!(bytes::Vector{UInt8}, x::UInt16)
    push!(bytes, UInt8(x & 0x00ff))
    push!(bytes, UInt8(x >> 8))
    return bytes
end

push_le!(bytes::Vector{UInt8}, x::Int16) = push_le!(bytes, reinterpret(UInt16, x))

function push_le!(bytes::Vector{UInt8}, x::UInt32)
    for shift in 0:8:24
        push!(bytes, UInt8((x >> shift) & 0xff))
    end
    return bytes
end

push_le!(bytes::Vector{UInt8}, x::Int32) = push_le!(bytes, reinterpret(UInt32, x))
push_le!(bytes::Vector{UInt8}, x::Float32) = push_le!(bytes, reinterpret(UInt32, x))

function push_le!(bytes::Vector{UInt8}, x::UInt64)
    for shift in 0:8:56
        push!(bytes, UInt8((x >> shift) & 0xff))
    end
    return bytes
end

push_le!(bytes::Vector{UInt8}, x::Int64) = push_le!(bytes, reinterpret(UInt64, x))
push_le!(bytes::Vector{UInt8}, x::Float64) = push_le!(bytes, reinterpret(UInt64, x))

function message_bytes(msg_type::Char, payload::Vector{UInt8} = UInt8[])
    bytes = UInt8[]
    push_le!(bytes, UInt16(length(payload)))
    push!(bytes, UInt8(msg_type))
    append!(bytes, payload)
    return bytes
end

format_payload(s::AbstractString) = collect(codeunits(s))

function fixed_string_bytes(value::AbstractString, len::Int)
    value_bytes = collect(codeunits(value))
    length(value_bytes) <= len || error("String is longer than its declared test type")
    bytes = zeros(UInt8, len)
    copyto!(bytes, value_bytes)
    return bytes
end

function typed_value_payload(ulog_type::AbstractString, value)

    match_result = match(r"^([A-Za-z_][A-Za-z0-9_]*)(?:\[(\d+)\])?$", ulog_type)
    match_result === nothing && error("Invalid test ULog type: $ulog_type")
    base_type = String(match_result.captures[1])
    array_len = match_result.captures[2]

    if base_type == "char" && array_len !== nothing
        return fixed_string_bytes(String(value), parse(Int, array_len))
    elseif array_len !== nothing
        values = collect(value)
        length(values) == parse(Int, array_len) || error("Wrong test array length")
        bytes = UInt8[]
        foreach(x -> push_le!(bytes, x), values)
        return bytes
    elseif value isa Vector{UInt8} && !(base_type in ("uint8_t", "char"))
        return copy(value)
    end

    bytes = UInt8[]
    push_le!(bytes, value)
    return bytes

end

function typed_key_value_payload_raw(
    ulog_type::AbstractString,
    key::AbstractString,
    value_bytes::Vector{UInt8},
)
    key_bytes = collect(codeunits(string(ulog_type, " ", key)))
    bytes = UInt8[UInt8(length(key_bytes))]
    append!(bytes, key_bytes)
    append!(bytes, value_bytes)
    return bytes
end

function typed_key_value_payload(ulog_type::AbstractString, key::AbstractString, value)
    return typed_key_value_payload_raw(
        ulog_type,
        key,
        typed_value_payload(ulog_type, value),
    )
end

function info_multiple_payload(
    continued::Bool,
    ulog_type::AbstractString,
    key::AbstractString,
    value,
)
    bytes = UInt8[continued ? 0x01 : 0x00]
    append!(bytes, typed_key_value_payload(ulog_type, key, value))
    return bytes
end

function default_parameter_payload(
    default_types::UInt8,
    ulog_type::AbstractString,
    key::AbstractString,
    value,
)
    bytes = UInt8[default_types]
    append!(bytes, typed_key_value_payload(ulog_type, key, value))
    return bytes
end

function logging_payload(level::Char, timestamp::UInt64, message::AbstractString)
    bytes = UInt8[UInt8(level)]
    push_le!(bytes, timestamp)
    append!(bytes, codeunits(message))
    return bytes
end

function tagged_logging_payload(
    level::Char,
    tag::UInt16,
    timestamp::UInt64,
    message::AbstractString,
)
    bytes = UInt8[UInt8(level)]
    push_le!(bytes, tag)
    push_le!(bytes, timestamp)
    append!(bytes, codeunits(message))
    return bytes
end

function add_subscription_payload(multi_id::UInt8, msg_id::UInt16, name::AbstractString)
    bytes = UInt8[multi_id]
    push_le!(bytes, msg_id)
    append!(bytes, codeunits(name))
    return bytes
end

function flag_bits_payload(
    ;
    compat_first::UInt8 = 0x00,
    incompat_first::UInt8 = 0x00,
    appended_offset::UInt64 = UInt64(0),
)
    bytes = zeros(UInt8, 40)
    bytes[1] = compat_first
    bytes[9] = incompat_first
    if appended_offset != 0
        offset_bytes = UInt8[]
        push_le!(offset_bytes, appended_offset)
        bytes[17:24] .= offset_bytes
    end
    return bytes
end

function write_header!(
    io;
    magic = ULOG_MAGIC_BYTES,
    start_timestamp_us::UInt64 = UInt64(1_000_000),
)
    write(io, magic)
    write(io, UInt8[0x01])
    bytes = UInt8[]
    push_le!(bytes, start_timestamp_us)
    write(io, bytes)
    return nothing
end

function write_log(
    path,
    records;
    magic = ULOG_MAGIC_BYTES,
    compat_first::UInt8 = 0x00,
    incompat_first::UInt8 = 0x00,
    appended_offset::UInt64 = UInt64(0),
    tail::Vector{UInt8} = UInt8[],
)
    open(path, "w") do io
        write_header!(io; magic = magic)
        flags = flag_bits_payload(
            ;
            compat_first = compat_first,
            incompat_first = incompat_first,
            appended_offset = appended_offset,
        )
        write(io, message_bytes('B', flags))
        for (msg_type, payload) in records
            write(io, message_bytes(msg_type, payload))
        end
        write(io, tail)
    end
    return path
end

function data_payload(msg_id::UInt16, values...)
    bytes = UInt8[]
    push_le!(bytes, msg_id)
    foreach(value -> push_le!(bytes, value), values)
    return bytes
end

function nested_data_payload()

    bytes = UInt8[]
    push_le!(bytes, UInt16(0))
    push_le!(bytes, UInt64(2_000_000))
    push!(bytes, 0xaa)

    push_le!(bytes, UInt16(0x1234))
    append!(bytes, UInt8[0x00, 0x00])
    push!(bytes, 0x42)
    push!(bytes, 0xee)

    push_le!(bytes, UInt16(0x5678))
    append!(bytes, UInt8[0x00, 0x00])
    push!(bytes, 0x24)
    push!(bytes, 0xdd)
    return bytes

end

function nested_records(; include_metadata::Bool = false)

    records = Tuple{Char, Vector{UInt8}}[]
    if include_metadata
        push!(records, ('I', typed_key_value_payload(
            "char[32]", "camera_model", "MAPSTAROblique_v5",
        )))
        push!(records, ('I', typed_key_value_payload(
            "int32_t", "camera_image_count", Int32(134),
        )))
        push!(records, ('M', info_multiple_payload(
            false, "char[16]", "boot_console_output", "part1",
        )))
        push!(records, ('M', info_multiple_payload(
            true, "char[16]", "boot_console_output", "part2",
        )))
        push!(records, ('M', info_multiple_payload(
            false, "char[16]", "boot_console_output", "part3",
        )))
        push!(records, ('P', typed_key_value_payload(
            "int32_t", "AIRCRAFT_ID", Int32(10507),
        )))
        push!(records, ('P', typed_key_value_payload(
            "float", "MC_PITCHRATE_P", 0.1f0,
        )))
        push!(records, ('Q', default_parameter_payload(
            0x03, "int32_t", "SYS_PARAM", Int32(42),
        )))
        push!(records, ('Q', default_parameter_payload(
            0x04, "float", "CUSTOM_DEFAULT", 1.5f0,
        )))
    end

    # `outer` intentionally precedes `inner` to exercise forward references.
    push!(records, ('F', format_payload(
        "outer:uint64_t timestamp;uint8_t[1] _padding0;" *
        "inner[2] inner;uint8_t[3] _padding1;",
    )))
    push!(records, ('F', format_payload(
        "inner:uint16_t a;uint8_t[2] _padding0;" *
        "uint8_t b;uint8_t[1] _padding1;",
    )))
    push!(records, ('A', add_subscription_payload(0x00, UInt16(0), "outer")))
    push!(records, ('D', nested_data_payload()))

    if include_metadata
        push!(records, ('P', typed_key_value_payload(
            "float", "MC_PITCHRATE_P", 0.2f0,
        )))
        push!(records, ('L', logging_payload('6', UInt64(2_500_000), "plain log")))
        push!(records, ('C', tagged_logging_payload(
            '4', UInt16(0x002a), UInt64(2_600_000), "tagged log",
        )))
    end
    push!(records, ('R', UInt8[0x00, 0x00]))
    push!(records, ('X', UInt8[0xde, 0xad]))
    return records

end

function error_text(f)
    try
        f()
    catch error
        return sprint(showerror, error)
    end
    return ""
end

@testset "Nested formats and indexed decoding" begin
    mktempdir() do dir
        path = write_log(joinpath(dir, "nested.ulg"), nested_records())
        ulog = PX4ULog.ULog(path)

        @test ulog.header.magic_ok
        @test PX4ULog.topics(ulog) == [("outer", UInt8(0))]
        @test isnothing(ulog.cache.data_index)

        # The first topic read builds the index owned by this ULog.
        td = PX4ULog.read_topic(ulog, "outer", 0)
        cached_index = ulog.cache.data_index
        @test !isnothing(cached_index)
        @test td.timestamp == UInt64[2_000_000]
        @test sort(collect(keys(td.cols)); by = String) == [:inner_a, :inner_b]
        @test td.inner_a == reshape(UInt16[0x1234, 0x5678], 1, 2)
        @test td.inner_b == reshape(UInt8[0x42, 0x24], 1, 2)
        @test PX4ULog.time_seconds(td) == [0.0]
        @test PX4ULog.time_seconds(td, ulog) == [1.0]

        # The path overload performs its own count pass before decoding. Compare it with
        # the cached ULog reader so this internal preallocation path remains covered.
        path_topic = PX4ULog.read_topic(path, "outer", 0)
        @test path_topic.timestamp == td.timestamp
        @test path_topic.cols == td.cols

        # Explicit low-level indexing remains equivalent to the cached reader.
        explicit_index = PX4ULog.build_data_index(ulog)
        indexed = PX4ULog.read_topic(ulog, "outer", 0, explicit_index)
        @test indexed.inner_a == td.inner_a
        @test indexed.inner_b == td.inner_b
        @test ulog.cache.data_index === cached_index

        df = PX4ULog.to_dataframe(td; time_s = true)
        @test names(df) == [
            "timestamp", "t", "inner_a_1", "inner_a_2", "inner_b_1", "inner_b_2",
        ]
        @test df.t == [0.0]
        @test df.inner_a_1 == UInt16[0x1234]
        @test df.inner_b_2 == UInt8[0x24]

        # A complete topic becomes a typed stream of messages on the ULog time axis.
        ts = PX4ULog.to_timeseries(td, ulog)
        @test ts.time == [1.0]
        @test ts.title == "outer"
        @test ts.path == "/px4/outer/0"
        @test ts.time_dimension.label == "Time"
        @test ts.time_dimension.units == "s"
        @test isempty(ts.dimensions)
        @test isempty(ts.groups)
        @test ts.discrete
        @test ts.interpolator isa SampleAndHold
        @test eltype(ts.data) == NamedTuple{
            (:timestamp, :inner_a, :inner_b),
            Tuple{UInt64,SVector{2,UInt16},SVector{2,UInt8}},
        }
        @test ts.data == [(
            timestamp = UInt64(2_000_000),
            inner_a = SVector{2,UInt16}(0x1234, 0x5678),
            inner_b = SVector{2,UInt8}(0x42, 0x24),
        )]
        @test td.inner_a == reshape(UInt16[0x1234, 0x5678], 1, 2)
        @test td.inner_b == reshape(UInt8[0x42, 0x24], 1, 2)

        # Direct reading reuses the cached index and the common ULog time origin.
        direct_ts = PX4ULog.to_timeseries(ulog, "outer", 0)
        @test direct_ts.time == ts.time
        @test direct_ts.data == ts.data
        @test ulog.cache.data_index === cached_index

        explicit_origin_ts = PX4ULog.to_timeseries(
            td;
            t0_us = UInt64(1_500_000),
            title = "Nested values",
            path = "/nested",
        )
        @test explicit_origin_ts.time == [0.5]
        @test explicit_origin_ts.title == "Nested values"
        @test explicit_origin_ts.path == "/nested"

        # Fixed-array fields can be selected as ordinary, dimensioned signals.
        inner_a_ts = select(
            message -> message.inner_a,
            ts;
            dimensions = ["First value" => "", "Second value" => ""],
        )
        @test inner_a_ts.data == SVector{2,UInt16}[SVector(0x1234, 0x5678)]

        # Cache ownership and first-read initialization are local to each ULog object.
        other_ulog = PX4ULog.ULog(path)
        @test isnothing(other_ulog.cache.data_index)
        @test PX4ULog.cached_data_index(other_ulog) !== cached_index

        # Concurrent first reads all receive the one index installed in the cache.
        concurrent_ulog = PX4ULog.ULog(path)
        tasks = [
            Threads.@spawn(PX4ULog.cached_data_index(concurrent_ulog))
            for _ in 1:4
        ]
        concurrent_indexes = fetch.(tasks)
        @test all(index -> index === concurrent_indexes[1], concurrent_indexes)
        @test concurrent_ulog.cache.data_index === concurrent_indexes[1]
    end
end

@testset "Primitive scalars and arrays" begin
    mktempdir() do dir
        scalar_values = (
            Int8(-12), UInt8(250), Int16(-1234), UInt16(54321), Int32(-1_234_567),
            UInt32(3_000_000_000), Int64(-5_000_000_000), UInt64(10_000_000_000),
            Float32(1.25), Float64(-2.5), true, UInt8('Z'),
        )
        array_values = (
            Int8[-1, 2], UInt8[3, 4], Int16[-5, 6], UInt16[7, 8],
            Int32[-9, 10], UInt32[11, 12], Int64[-13, 14], UInt64[15, 16],
            Float32[1.5, 2.5], Float64[-3.5, 4.5], Bool[true, false],
        )
        format_string =
            "primitives:uint64_t timestamp;int8_t i8;uint8_t u8;int16_t i16;" *
            "uint16_t u16;int32_t i32;uint32_t u32;int64_t i64;uint64_t u64;" *
            "float f32;double f64;bool flag;char letter;int8_t[2] i8_arr;" *
            "uint8_t[2] u8_arr;int16_t[2] i16_arr;uint16_t[2] u16_arr;" *
            "int32_t[2] i32_arr;uint32_t[2] u32_arr;int64_t[2] i64_arr;" *
            "uint64_t[2] u64_arr;float[2] f32_arr;double[2] f64_arr;" *
            "bool[2] flag_arr;char[6] label;"

        payload = UInt8[]
        push_le!(payload, UInt16(7))
        push_le!(payload, UInt64(2_000_000))
        foreach(value -> push_le!(payload, value), scalar_values)
        for values in array_values
            foreach(value -> push_le!(payload, value), values)
        end
        append!(payload, fixed_string_bytes("PX4", 6))

        records = [
            ('F', format_payload(format_string)),
            ('A', add_subscription_payload(0x00, UInt16(7), "primitives")),
            ('D', payload),
        ]
        path = write_log(joinpath(dir, "primitives.ulg"), records)
        td = PX4ULog.read_topic(PX4ULog.ULog(path), "primitives")

        scalar_names = [
            :i8, :u8, :i16, :u16, :i32, :u32, :i64, :u64, :f32, :f64, :flag,
            :letter,
        ]
        for (name, value) in zip(scalar_names, scalar_values)
            @test td.cols[name] == [value]
        end

        array_names = [
            :i8_arr, :u8_arr, :i16_arr, :u16_arr, :i32_arr, :u32_arr, :i64_arr,
            :u64_arr, :f32_arr, :f64_arr, :flag_arr,
        ]
        for (name, values) in zip(array_names, array_values)
            @test td.cols[name] == reshape(values, 1, 2)
        end
        @test td.label == ["PX4"]
    end
end

@testset "Multi-instance and empty topics" begin
    mktempdir() do dir
        format = format_payload("sample:uint64_t timestamp;float value;")
        multi_records = [
            ('F', format),
            ('A', add_subscription_payload(0x00, UInt16(10), "sample")),
            ('A', add_subscription_payload(0x01, UInt16(11), "sample")),
            ('D', data_payload(UInt16(10), UInt64(2_000_000), 1.0f0)),
            ('D', data_payload(UInt16(11), UInt64(2_100_000), 2.0f0)),
        ]
        multi_path = write_log(joinpath(dir, "multi.ulg"), multi_records)
        multi_ulog = PX4ULog.ULog(multi_path)
        @test PX4ULog.topics(multi_ulog) == [
            ("sample", UInt8(0)), ("sample", UInt8(1)),
        ]
        @test PX4ULog.read_topic(multi_ulog, "sample", 0).value == Float32[1.0]
        @test PX4ULog.read_topic(multi_ulog, "sample", 1).value == Float32[2.0]

        # Both instances retain their actual offset from the common ULog start.
        first_ts = PX4ULog.to_timeseries(multi_ulog, "sample", 0)
        second_ts = PX4ULog.to_timeseries(multi_ulog, "sample", 1)
        @test first_ts.time == [1.0]
        @test second_ts.time ≈ [1.1]

        value_ts = select(
            message -> message.value,
            first_ts;
            dimensions = ["Value" => "m"],
        )
        @test value_ts.data == Float32[1.0]

        held_topic = PX4ULog.TopicData(
            "held_sample",
            UInt8(0),
            UInt64[1_000_000, 2_000_000],
            Dict{Symbol,Any}(:value => Float32[1.0, 2.0]),
        )
        held_ts = PX4ULog.to_timeseries(held_topic; t0_us = UInt64(1_000_000))
        @test held_ts(0.5).value == 1.0f0

        empty_records = [
            ('F', format),
            ('A', add_subscription_payload(0x00, UInt16(12), "sample")),
        ]
        empty_path = write_log(joinpath(dir, "empty.ulg"), empty_records)
        empty_ulog = PX4ULog.ULog(empty_path)
        empty_topic = PX4ULog.read_topic(empty_ulog, "sample")
        @test empty_topic.timestamp == UInt64[]
        @test empty_topic.value == Float32[]
        @test PX4ULog.time_seconds(empty_topic) == Float64[]
        @test PX4ULog.time_seconds(empty_topic; t0_us = UInt64(0)) == Float64[]
        @test PX4ULog.time_seconds(empty_topic, empty_ulog) == Float64[]

        indexed = PX4ULog.read_topic(
            empty_ulog,
            "sample",
            0,
            PX4ULog.build_data_index(empty_ulog),
        )
        @test indexed.timestamp == UInt64[]

        empty_df = PX4ULog.to_dataframe(empty_topic; time_s = true)
        @test names(empty_df) == ["timestamp", "t", "value"]
        @test nrow(empty_df) == 0
        @test empty_df.t == Float64[]

        # Empty topics retain the concrete message type derived from their columns.
        empty_ts = PX4ULog.to_timeseries(empty_topic, empty_ulog)
        @test isempty(empty_ts.time)
        @test isempty(empty_ts.data)
        @test eltype(empty_ts.data) == NamedTuple{
            (:timestamp, :value),
            Tuple{UInt64,Float32},
        }

        empty_array_topic = PX4ULog.TopicData(
            "empty_array",
            UInt8(0),
            UInt64[],
            Dict{Symbol,Any}(:q => Matrix{Float32}(undef, 0, 4)),
        )
        empty_array_ts = PX4ULog.to_timeseries(
            empty_array_topic;
            t0_us = UInt64(0),
        )
        @test eltype(empty_array_ts.data) == NamedTuple{
            (:timestamp, :q),
            Tuple{UInt64,SVector{4,Float32}},
        }

        missing_timestamp = PX4ULog.TopicData(
            "missing_timestamp",
            UInt8(0),
            nothing,
            Dict{Symbol,Any}(:value => Float32[1.0]),
        )
        @test_throws ErrorException PX4ULog.to_timeseries(
            missing_timestamp;
            t0_us = UInt64(0),
        )

        unsupported_storage = PX4ULog.TopicData(
            "unsupported_storage",
            UInt8(0),
            UInt64[0],
            Dict{Symbol,Any}(:value => 1.0f0),
        )
        @test_throws ErrorException PX4ULog.to_timeseries(
            unsupported_storage;
            t0_us = UInt64(0),
        )
    end
end

@testset "Format graph validation" begin
    mktempdir() do dir
        cycle_path = write_log(joinpath(dir, "cycle.ulg"), [
            ('F', format_payload("A:B b;")),
            ('F', format_payload("B:A a;")),
        ])
        cycle_error = error_text(() -> PX4ULog.ULog(cycle_path))
        @test occursin("Circular ULog FORMAT definition", cycle_error)
        @test occursin("A", cycle_error)
        @test occursin("B", cycle_error)

        unknown_path = write_log(joinpath(dir, "unknown.ulg"), [
            ('F', format_payload("A:Missing child;")),
        ])
        unknown_error = error_text(() -> PX4ULog.ULog(unknown_path))
        @test occursin("Unknown nested ULog format: 'Missing'", unknown_error)

        @test_throws ErrorException PX4ULog.parse_format_string("bad-format")
        @test_throws ErrorException PX4ULog.parse_format_string("x:uint8_t[2] y[2];")
    end
end

@testset "Metadata values, parameters, and logged messages" begin
    mktempdir() do dir
        path = write_log(
            joinpath(dir, "metadata.ulg"),
            nested_records(; include_metadata = true),
        )
        ulog = PX4ULog.ULog(path)

        @test PX4ULog.info_message(ulog, "camera_model") == "MAPSTAROblique_v5"
        @test PX4ULog.info_message(ulog, "camera_image_count") == Int32(134)
        @test PX4ULog.info_message(ulog, "missing"; default = "fallback") == "fallback"
        @test PX4ULog.info_types(ulog)["camera_model"] == "char[32]"
        @test PX4ULog.info_messages(ulog) === ulog.metadata.info

        multi = PX4ULog.info_multiple(ulog)["boot_console_output"]
        @test multi == Vector{Any}[Any["part1", "part2"], Any["part3"]]

        params = PX4ULog.initial_parameters(ulog)
        @test params["AIRCRAFT_ID"] == Int32(10507)
        @test params["MC_PITCHRATE_P"] == 0.1f0

        @test PX4ULog.has_default_parameters(ulog)
        @test PX4ULog.default_parameters(ulog, :system)["SYS_PARAM"] == Int32(42)
        @test PX4ULog.default_parameters(ulog, :current_setup)["SYS_PARAM"] == Int32(42)
        @test PX4ULog.default_parameters(ulog, 0)["SYS_PARAM"] == Int32(42)
        @test PX4ULog.default_parameters(ulog, 2)["CUSTOM_DEFAULT"] == 1.5f0
        @test isempty(PX4ULog.default_parameters(ulog, 7))
        @test_throws ErrorException PX4ULog.default_parameters(ulog, :invalid)

        changes = PX4ULog.changed_parameters(ulog)
        @test length(changes) == 1
        @test changes[1].timestamp == UInt64(2_000_000)
        @test changes[1].name == "MC_PITCHRATE_P"
        @test changes[1].value == 0.2f0
        @test changes[1].ulog_type == "float"

        logs = PX4ULog.logged_messages(ulog)
        @test logs == [
            PX4ULog.LoggedMessage(
                UInt64(2_500_000), UInt8('6'), :INFO, "plain log", nothing,
            ),
            PX4ULog.LoggedMessage(
                UInt64(2_600_000), UInt8('4'), :WARNING, "tagged log", UInt16(0x2a),
            ),
        ]
        @test PX4ULog.logged_messages(ulog; tag = 0x2a) == [logs[2]]
    end
end

@testset "Metadata primitive types and raw arrays" begin
    mktempdir() do dir
        values = [
            ("int8_t", "i8", Int8(-1)),
            ("uint8_t", "u8", UInt8(2)),
            ("int16_t", "i16", Int16(-3)),
            ("uint16_t", "u16", UInt16(4)),
            ("int32_t", "i32", Int32(-5)),
            ("uint32_t", "u32", UInt32(6)),
            ("int64_t", "i64", Int64(-7)),
            ("uint64_t", "u64", UInt64(8)),
            ("float", "f32", 1.25f0),
            ("double", "f64", 2.5),
            ("bool", "flag", true),
            ("char", "letter", UInt8('Q')),
            ("char[8]", "text", "hello"),
            ("char[0]", "empty_text", ""),
        ]
        records = Tuple{Char, Vector{UInt8}}[
            ('I', typed_key_value_payload(type, key, value))
            for (type, key, value) in values
        ]
        array_bytes = typed_value_payload("uint16_t[2]", UInt16[0x1234, 0x5678])
        push!(records, ('I', typed_key_value_payload_raw(
            "uint16_t[2]", "raw_array", array_bytes,
        )))
        push!(records, ('I', typed_key_value_payload_raw(
            "vendor_type", "vendor_value", UInt8[0xde, 0xad],
        )))
        push!(records, ('I', typed_key_value_payload_raw(
            "future_type", "empty_value", UInt8[],
        )))

        ulog = PX4ULog.ULog(write_log(joinpath(dir, "types.ulg"), records))
        for (_, key, value) in values
            @test PX4ULog.info_message(ulog, key) == value
        end
        @test PX4ULog.info_message(ulog, "raw_array") == array_bytes
        @test PX4ULog.info_message(ulog, "vendor_value") == UInt8[0xde, 0xad]
        @test PX4ULog.info_message(ulog, "empty_value") == UInt8[]
    end
end

@testset "Malformed metadata is rejected" begin
    mktempdir() do dir
        cases = [
            (
                "short_scalar",
                'I',
                typed_key_value_payload_raw("int32_t", "bad", UInt8[0x01, 0x02]),
                "has 2 bytes, expected 4",
            ),
            (
                "long_scalar",
                'I',
                typed_key_value_payload_raw(
                    "int32_t", "bad", UInt8[0x01, 0x02, 0x03, 0x04, 0x05],
                ),
                "has 5 bytes, expected 4",
            ),
            (
                "short_char",
                'I',
                typed_key_value_payload_raw("char[4]", "bad", UInt8[0x41, 0x42]),
                "has 2 bytes, expected 4",
            ),
            (
                "short_array",
                'I',
                typed_key_value_payload_raw("uint16_t[2]", "bad", UInt8[0x01, 0x02]),
                "has 2 bytes, expected 4",
            ),
            (
                "bad_parameter_type",
                'P',
                typed_key_value_payload("uint32_t", "BAD_PARAM", UInt32(1)),
                "expected int32_t or float",
            ),
            (
                "array_parameter",
                'P',
                typed_key_value_payload("int32_t[1]", "BAD_PARAM", Int32[1]),
                "expected int32_t or float",
            ),
            (
                "zero_default_bits",
                'Q',
                default_parameter_payload(0x00, "int32_t", "BAD_DEFAULT", Int32(1)),
                "empty default-types bitfield",
            ),
            (
                "bad_default_type",
                'Q',
                default_parameter_payload(0x01, "uint32_t", "BAD_DEFAULT", UInt32(1)),
                "expected int32_t or float",
            ),
            (
                "orphan_multi",
                'M',
                info_multiple_payload(true, "char[4]", "orphan", "x"),
                "has no preceding chunk",
            ),
        ]

        for (name, msg_type, payload, expected) in cases
            path = write_log(joinpath(dir, "$name.ulg"), [(msg_type, payload)])
            message = error_text(() -> PX4ULog.ULog(path))
            @test occursin(expected, message)
        end
    end
end

@testset "Header, flags, unknown records, and truncation" begin
    mktempdir() do dir
        bad_magic = joinpath(dir, "bad_magic.ulg")
        write_log(
            bad_magic,
            nested_records();
            magic = UInt8[0x00, ULOG_MAGIC_BYTES[2:end]...],
        )
        @test_throws ErrorException PX4ULog.ULog(bad_magic)

        bad_flags = joinpath(dir, "bad_flags.ulg")
        write_log(bad_flags, nested_records(); incompat_first = 0x02)
        @test_throws ErrorException PX4ULog.ULog(bad_flags)

        appended = joinpath(dir, "appended.ulg")
        write_log(
            appended,
            nested_records();
            incompat_first = 0x01,
            appended_offset = UInt64(128),
        )
        @test_throws ErrorException PX4ULog.ULog(appended)

        advertised_defaults = write_log(
            joinpath(dir, "advertised_defaults.ulg"),
            Tuple{Char, Vector{UInt8}}[];
            compat_first = 0x01,
        )
        @test PX4ULog.has_default_parameters(PX4ULog.ULog(advertised_defaults))

        for (name, tail) in [
            ("partial_size", UInt8[0x05]),
            ("partial_type", UInt8[0x05, 0x00]),
            ("partial_payload", UInt8[0x05, 0x00, UInt8('D'), 0x00]),
        ]
            path = write_log(joinpath(dir, "$name.ulg"), nested_records(); tail = tail)
            ulog = PX4ULog.ULog(path)
            td = PX4ULog.read_topic(ulog, "outer")
            @test td.timestamp == UInt64[2_000_000]
            @test td.inner_a == reshape(UInt16[0x1234, 0x5678], 1, 2)
        end
    end
end

@testset "Public API documentation" begin
    @test isempty(Base.Docs.undocumented_names(PX4ULog; private = false))
end
