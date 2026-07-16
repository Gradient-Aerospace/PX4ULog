module PX4ULogDataFramesExt

using PX4ULog
using DataFrames

"""
Convert a TopicData to a DataFrame.

Keyword args:
- include_timestamp::Bool = true
- timestamp_name::Symbol = :timestamp
- time_s::Bool = false
- t0_us::Union{Nothing,UInt64} = nothing   # time origin (defaults to first timestamp)
- expand_arrays::Symbol = :columns         # :columns, :rowviews, or :vectors
- drop_cols::Function = (sym->false)       # allow user to drop columns by name
- copycols::Bool = false                   # if true, copy vectors into the DataFrame
"""
function PX4ULog.to_dataframe(
    td::PX4ULog.TopicData;
    include_timestamp::Bool = true,
    timestamp_name::Symbol = :timestamp,
    time_s::Bool = false,
    t0_us::Union{Nothing,UInt64} = nothing,
    expand_arrays::Symbol = :columns,
    drop_cols::Function = (sym::Symbol)->false,
    copycols::Bool = false,
)
    df = DataFrame()

    # Determine row count N
    N = if td.timestamp !== nothing
        length(td.timestamp)
    else
        isempty(td.cols) && return df
        length(first(values(td.cols)))
    end

    # Timestamp / time
    if include_timestamp && td.timestamp !== nothing
        df[!, timestamp_name] = copycols ? copy(td.timestamp) : td.timestamp
        if time_s
            df[!, :t] = PX4ULog.time_seconds(td; t0_us = t0_us)
        end
    elseif time_s
        error("time_s=true requested but TopicData has no :timestamp")
    end

    # Add columns
    for (k, v) in sort(collect(td.cols); by=kv->String(kv[1]))
        drop_cols(k) && continue

        if v isa AbstractVector
            length(v) == N || error("Column $k has length $(length(v)) but expected $N")
            df[!, k] = copycols ? copy(v) : v

        elseif v isa AbstractMatrix
            size(v, 1) == N || error("Column $k has N=$(size(v,1)) but expected $N")

            if expand_arrays == :columns
                M = size(v, 2)
                for j in 1:M
                    df[!, Symbol(string(k), "_", j)] = v[:, j]  # copies the column slice
                end
            elseif expand_arrays == :rowviews
                df[!, k] = [view(v, i, :) for i in 1:N]         # lightweight views
            elseif expand_arrays == :vectors
                df[!, k] = [collect(view(v, i, :)) for i in 1:N]
            else
                error("expand_arrays must be :columns, :rowviews, or :vectors")
            end

        else
            error("Unsupported column storage for $k: $(typeof(v))")
        end
    end

    return df
end

function PX4ULog.to_dataframe(
    ulog::PX4ULog.ULog,
    topic_name::AbstractString,
    multi_id::Integer=0;
    index=nothing,
    kwargs...
)
    td = index === nothing ?
        PX4ULog.read_topic(ulog, topic_name, multi_id) :
        PX4ULog.read_topic(ulog, topic_name, multi_id, index)
    return PX4ULog.to_dataframe(td; kwargs...)
end

end # module
