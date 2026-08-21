# PX4ULog.jl

PX4ULog.jl reads and decodes standard PX4 ULog (`.ulg`) flight logs in Julia. It
provides typed, column-oriented topic data together with information messages,
parameters, and logged strings for post-flight analysis and debugging.

## Requirements

PX4ULog requires Julia 1.12 or later. The core package depends only on Julia standard
libraries. DataFrames.jl and SystemsOfSystems.jl support is provided through optional
package extensions.

## Installation

PX4ULog is currently installed directly from GitHub:

```julia
using Pkg
Pkg.add(url = "https://github.com/Gradient-Aerospace/PX4ULog.git")
```

For local development:

```julia
using Pkg
Pkg.develop(path = "/path/to/PX4ULog")
```

Install DataFrames.jl separately to enable `to_dataframe`:

```julia
Pkg.add("DataFrames")
```

## Reading A Log

```julia
using PX4ULog

ulog = PX4ULog.ULog("flight.ulg")
PX4ULog.topics(ulog)
```

Construction reads and validates the header, format graph, subscriptions, information
messages, parameters, and logged strings. Topic samples remain on disk until requested.

Decode one topic instance:

```julia
attitude = PX4ULog.read_topic(ulog, "vehicle_attitude", 0)

attitude.timestamp  # microseconds
attitude.q          # N x 4 matrix
attitude[:q]        # equivalent symbol indexing
```

Scalar fields are vectors, fixed-size arrays are `N x array_length` matrices, character
arrays are strings, and nested field names are flattened with underscores. Multi-instance
topics are selected with `multi_id`.

The first topic read builds a data index. Later reads from the same `ULog` reuse it
automatically:

```julia
attitude = PX4ULog.read_topic(ulog, "vehicle_attitude", 0)
position = PX4ULog.read_topic(ulog, "vehicle_local_position", 0)
```

## Time

Topic timestamps are stored in microseconds. Convert them to seconds relative to the
topic's first sample:

```julia
t_s = PX4ULog.time_seconds(attitude)
```

An explicit origin or the log start time can also be used:

```julia
t_s = PX4ULog.time_seconds(attitude; t0_us = UInt64(1_000_000))
t_s = PX4ULog.time_seconds(attitude, ulog)
```

Empty topics produce empty timestamp, column, and time vectors.

## TimeSeries

After loading SystemsOfSystems.jl, a complete topic can be converted to a discrete
`TimeSeries`. Each sample is a concrete `NamedTuple`, and fixed-size array fields are
represented by `SVector`s.

```julia
using SystemsOfSystems

position_messages_ts = PX4ULog.to_timeseries(
    ulog,
    "vehicle_local_position",
    0,
)

vx_ts = select(
    position_messages_ts,
    :vx;
    title = "North Velocity",
    dimensions = ["North velocity" => "m/s"],
)
```

The ULog start timestamp provides a common time origin, preserving the actual timing
between topics. Previously decoded data can be converted with the same origin:

```julia
position = PX4ULog.read_topic(ulog, "vehicle_local_position", 0)
position_messages_ts = PX4ULog.to_timeseries(position, ulog)
```

When no `ULog` is available, the origin must be explicit:

```julia
position_messages_ts = PX4ULog.to_timeseries(
    position;
    t0_us = UInt64(1_000_000),
)
```

ULog records describe fixed array lengths but not higher-level meaning. PX4ULog therefore
does not infer that an array represents a quaternion, matrix, or physical vector. Analyses
can make those domain-specific conversions explicitly.

## Metadata And Parameters

Metadata is available immediately after constructing `ULog`:

```julia
PX4ULog.info_message(ulog, "camera_model")
PX4ULog.info_message(ulog, "camera_serial_number"; default = "unknown")
PX4ULog.info_messages(ulog)
PX4ULog.info_types(ulog)
PX4ULog.info_multiple(ulog)

PX4ULog.initial_parameters(ulog)["AIRCRAFT_ID"]
PX4ULog.changed_parameters(ulog)
PX4ULog.has_default_parameters(ulog)
PX4ULog.default_parameters(ulog, :system)
PX4ULog.default_parameters(ulog, :current_setup)

PX4ULog.logged_messages(ulog)
PX4ULog.logged_messages(ulog; tag = 42)
```

Known scalar metadata values are decoded to native Julia values. Character arrays become
strings. Other fixed-size arrays and unknown vendor types are retained as raw
`Vector{UInt8}` values so their bytes remain available without package-specific decoding.

## DataFrames

After loading DataFrames.jl, decoded topics can be converted without making DataFrames a
core dependency:

```julia
using DataFrames

df = PX4ULog.to_dataframe(attitude; time_s = true)
```

Fixed-size arrays use one DataFrame column per element by default. Other representations
are selected with `expand_arrays = :rowviews` or `expand_arrays = :vectors`.

## Validation And Limitations

PX4ULog rejects invalid magic bytes, unsupported incompatibility flags, unknown or cyclic
nested formats, malformed known metadata values, and topic payloads that do not match
their declared format. A partial final record is discarded as required by ULog, but the
parser does not resynchronize after arbitrary mid-file corruption.

The package currently targets standard ULog framing. PX4 event metadata is exposed as raw
topic or information data rather than expanded into high-level event objects.

## Performance

The first topic read indexes the log and later reads reuse those data offsets. Numeric
scalar and array fields are written directly into preallocated destination columns.
Character array fields allocate one `String` per decoded sample.

## Testing

Run the synthetic parser and DataFrames test suite with:

```sh
julia --project=. -e 'import Pkg; Pkg.test()'
```

The tests cover primitive wire types, nested and forward-referenced formats, padding,
multi-instance and empty topics, metadata, malformed records, compatibility flags, and
truncated final records.

## License

PX4ULog.jl is available under the [MIT License](LICENSE).
