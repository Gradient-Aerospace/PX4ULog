# PX4ULog.jl

PX4ULog.jl is a Julia package for reading and decoding PX4 ULog (`.ulg`) flight log files.

The focus of the package is:
- correctness on real PX4 logs
- predictable, efficient data access
- minimal dependencies
- a clear separation between parsing and analysis

It is intended for post-flight analysis, debugging, plotting, and research workflows.

---

## Features

- Reads ULog headers and message records
- Parses FORMAT (`F`) and ADD_LOGGED_MSG (`A`) definitions
- Decodes metadata, parameters, default parameters, and logged strings
- Decodes DATA (`D`) messages into typed Julia data
- Column-oriented storage for efficient access
- Supports nested FORMAT definitions by flattening nested field paths
- Supports multi-instance topics (`multi_id`)
- Optional integration with DataFrames.jl (via extension)
- No required dependencies beyond Julia itself

---

## Installation

For development:

```julia
pkg> dev path/to/PX4ULog
```

Once registered:

```julia
pkg> add PX4ULog
```

Optional DataFrames support:

```julia
pkg> add DataFrames
```

DataFrames is a weak dependency and is only loaded if present.

---

## Basic usage

### Open a log file

```julia
using PX4ULog

ulog = PX4ULog.ULog("flight.ulg")
```

This reads:
- the ULog header
- all FORMAT definitions
- all topic subscriptions
- INFO and INFO_MULTIPLE metadata
- initial/default parameters and later parameter changes
- logged string messages

No DATA messages are decoded at this stage.

---

### List available topics

```julia
PX4ULog.topics(ulog)
```

Returns a list of `(topic_name, multi_id)` pairs.

---

### Read a topic

```julia
att = PX4ULog.read_topic(ulog, "vehicle_attitude", 0)
```

This decodes all samples for the given topic and returns a `TopicData` object.

---

### Read metadata and parameters

```julia
PX4ULog.info_message(ulog, "camera_model")
PX4ULog.info_message(ulog, "camera_serial_number")
PX4ULog.initial_parameters(ulog)["AIRCRAFT_ID"]
PX4ULog.logged_messages(ulog)
```

Other metadata helpers include:

```julia
PX4ULog.info_messages(ulog)
PX4ULog.info_types(ulog)
PX4ULog.info_multiple(ulog)
PX4ULog.changed_parameters(ulog)
PX4ULog.default_parameters(ulog, :system)
PX4ULog.default_parameters(ulog, :current_setup)
PX4ULog.has_default_parameters(ulog)
```

`logged_messages(ulog; tag=...)` filters tagged log messages by tag.

---

## TopicData

Decoded data is stored in a `TopicData` struct:

```julia
TopicData(
    topic::String,
    multi_id::UInt8,
    timestamp::Union{Vector{UInt64}, Nothing},
    cols::Dict{Symbol, Any}
)
```

- Scalar fields are stored as vectors
- Fixed-size array fields are stored as matrices (`N × array_length`)
- Nested fields are flattened with underscore-separated names
- Padding fields are consumed where serialized and are not exposed as columns

For example, a nested field such as `position_setpoint current` is exposed as
columns like `current_lat`, `current_lon`, and `current_timestamp`. Arrays of
nested structs are stored as matrices with one column per nested instance.

### Accessing data

Columns can be accessed as properties:

```julia
att.q
att.timestamp
att.quat_reset_counter
```

or via indexing:

```julia
att[:q]
```

---

### Time helper

```julia
t = PX4ULog.time_seconds(att)
```

Returns time in seconds relative to the first timestamp in the topic.

---

## DataFrames integration (optional)

If `DataFrames.jl` is installed, a conversion helper is available:

```julia
using DataFrames

df = PX4ULog.to_dataframe(att; time_s=true)
```

### Array handling

By default, array fields are expanded into multiple columns:

```text
q_1, q_2, q_3, q_4
```

This can be configured:

```julia
PX4ULog.to_dataframe(att; expand_arrays=:columns)
PX4ULog.to_dataframe(att; expand_arrays=:rowviews)
PX4ULog.to_dataframe(att; expand_arrays=:vectors)
```

---

## Performance notes

- DATA decoding uses a two-pass approach:
  1. count samples
  2. preallocate and decode
- No per-row allocations during decoding
- Array fields are stored as matrices, not vectors of vectors
- Repeated topic reads can use `build_data_index(ulog)` to avoid rescanning
- Suitable for large logs and repeated topic extraction

---

## Design notes

- The core package does not depend on DataFrames
- No Tables.jl interface is provided (by design, for now)
- The API exposes structured data directly rather than hiding it behind abstractions
- The goal is to be predictable and easy to reason about

---

## Limitations

- PX4 event metadata is not yet expanded into high-level event objects
- Abruptly truncated final messages are discarded, but full resynchronization
  after arbitrary mid-file corruption is not implemented

---

## License

MIT
