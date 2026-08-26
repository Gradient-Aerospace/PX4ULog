module PX4ULogSystemsOfSystemsExt

import PX4ULog
using StaticArrays: SVector
using SystemsOfSystems: TimeSeries

function topic_path(topic::PX4ULog.TopicData)
    return "/px4/$(topic.topic)/$(topic.multi_id)"
end

function sample_column(
    name::Symbol,
    column::AbstractVector,
    sample_count::Int,
)

    length(column) == sample_count || error(
        "Topic column $name has $(length(column)) samples, expected $sample_count.",
    )
    return column

end


function sample_column(
    name::Symbol,
    column::AbstractMatrix{T},
    sample_count::Int,
) where {T}

    size(column, 1) == sample_count || error(
        "Topic column $name has $(size(column, 1)) samples, expected $sample_count.",
    )

    N = size(column, 2)
    row_type = SVector{N,T}
    rows = Vector{row_type}(undef, sample_count)
    for i in eachindex(rows)
        rows[i] = row_type(view(column, i, :))
    end
    return rows

end


function sample_column(name::Symbol, column, _sample_count::Int)
    error("Unsupported topic column storage for $name: $(typeof(column)).")
end


function topic_samples(topic::PX4ULog.TopicData)

    timestamp = topic.timestamp
    isnothing(timestamp) && error("Topic $(topic.topic) has no timestamp field.")
    sample_count = length(timestamp)

    sorted_columns = sort(collect(topic.cols); by = pair -> String(first(pair)))
    names = (:timestamp, map(first, sorted_columns)...)
    columns = (
        timestamp,
        map(
            pair -> sample_column(first(pair), last(pair), sample_count),
            sorted_columns,
        )...,
    )

    field_types = Tuple{map(eltype, columns)...}
    sample_type = NamedTuple{names,field_types}
    samples = Vector{sample_type}(undef, sample_count)
    for i in eachindex(samples)
        samples[i] = sample_type(map(column -> column[i], columns))
    end
    return samples

end


function make_timeseries(
    topic::PX4ULog.TopicData,
    time;
    title::AbstractString = topic.topic,
    path::String = topic_path(topic),
)

    return TimeSeries(;
        title,
        time,
        data = topic_samples(topic),
        time_dimension = "Time" => "s",
        dimensions = [],
        path,
        discrete = true,
        groups = [],
    )

end


function PX4ULog.to_timeseries(
    topic::PX4ULog.TopicData,
    ulog::PX4ULog.ULog;
    kwargs...,
)

    return make_timeseries(
        topic,
        PX4ULog.time_seconds(topic, ulog);
        kwargs...,
    )

end


function PX4ULog.to_timeseries(
    topic::PX4ULog.TopicData;
    t0_us::UInt64,
    kwargs...,
)

    return make_timeseries(
        topic,
        PX4ULog.time_seconds(topic; t0_us);
        kwargs...,
    )

end


function PX4ULog.to_timeseries(
    ulog::PX4ULog.ULog,
    topic_name::AbstractString,
    multi_id::Integer = 0;
    kwargs...,
)

    topic = PX4ULog.read_topic(ulog, topic_name, multi_id)
    return PX4ULog.to_timeseries(topic, ulog; kwargs...)

end

end # module
