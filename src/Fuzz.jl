"""
    Fuzz

Security fuzzing toolkit for Julia providing mutation-based, generation-based,
and coverage-guided fuzzing strategies for finding bugs and vulnerabilities.

# Quick Start
```julia
using Fuzz

# Fuzz a function with mutation-based fuzzing
results = fuzz(my_parser, UInt8[]; max_iterations=10000)

# Use a dictionary-guided fuzzer for protocol testing
results = fuzz(my_handler, b"GET / HTTP/1.1";
               strategy=:dictionary,
               dictionary=[b"GET", b"POST", b"\\r\\n"])
```
"""
module Fuzz

using Random
using SHA

export fuzz, FuzzResult, FuzzConfig, FuzzCorpus,
       mutate, generate_input,
       BitFlipMutator, ByteFlipMutator, ArithmeticMutator,
       InsertMutator, DeleteMutator, SpliceMutator,
       DictionaryMutator, CompositeMutator,
       IntegerGenerator, StringGenerator, BinaryGenerator,
       StructuredGenerator

# ─────────────────────────────────────────────────────────────────────────────
#                              TYPES
# ─────────────────────────────────────────────────────────────────────────────

"""Result of a single fuzz test execution."""
struct FuzzResult
    input::Vector{UInt8}
    crashed::Bool
    error_type::Union{String, Nothing}
    error_msg::Union{String, Nothing}
    coverage_hash::UInt64
end

"""Configuration for a fuzzing campaign."""
Base.@kwdef struct FuzzConfig
    max_iterations::Int = 10000
    max_input_size::Int = 4096
    timeout_ms::Int = 5000
    seed::Int = 0
    strategy::Symbol = :mutation
    dictionary::Vector{Vector{UInt8}} = Vector{UInt8}[]
    verbose::Bool = false
    save_crashes::Bool = true
    crash_dir::String = "crashes"
end

"""Corpus of interesting inputs for coverage-guided fuzzing."""
mutable struct FuzzCorpus
    inputs::Vector{Vector{UInt8}}
    coverage_set::Set{UInt64}
    crashes::Vector{FuzzResult}
    total_runs::Int
end

FuzzCorpus() = FuzzCorpus(Vector{UInt8}[], Set{UInt64}(), FuzzResult[], 0)

function Base.show(io::IO, c::FuzzCorpus)
    print(io, "FuzzCorpus(inputs=$(length(c.inputs)), coverage=$(length(c.coverage_set)), crashes=$(length(c.crashes)), runs=$(c.total_runs))")
end

# ─────────────────────────────────────────────────────────────────────────────
#                              MUTATORS
# ─────────────────────────────────────────────────────────────────────────────

"""Abstract base type for mutators."""
abstract type AbstractMutator end

"""Flip random bits in the input."""
struct BitFlipMutator <: AbstractMutator
    num_bits::Int
    BitFlipMutator(n::Int=1) = new(n)
end

function mutate(m::BitFlipMutator, input::Vector{UInt8}, rng::AbstractRNG)
    isempty(input) && return UInt8[rand(rng, UInt8)]
    result = copy(input)
    for _ in 1:m.num_bits
        pos = rand(rng, 1:length(result))
        bit = rand(rng, 0:7)
        result[pos] ⊻= UInt8(1) << bit
    end
    return result
end

"""Replace random bytes with new random values."""
struct ByteFlipMutator <: AbstractMutator
    num_bytes::Int
    ByteFlipMutator(n::Int=1) = new(n)
end

function mutate(m::ByteFlipMutator, input::Vector{UInt8}, rng::AbstractRNG)
    isempty(input) && return UInt8[rand(rng, UInt8)]
    result = copy(input)
    for _ in 1:m.num_bytes
        pos = rand(rng, 1:length(result))
        result[pos] = rand(rng, UInt8)
    end
    return result
end

"""Apply arithmetic operations to random bytes/words."""
struct ArithmeticMutator <: AbstractMutator
    max_delta::Int
    ArithmeticMutator(d::Int=35) = new(d)
end

function mutate(m::ArithmeticMutator, input::Vector{UInt8}, rng::AbstractRNG)
    isempty(input) && return UInt8[rand(rng, UInt8)]
    result = copy(input)
    pos = rand(rng, 1:length(result))
    delta = rand(rng, -m.max_delta:m.max_delta)
    result[pos] = UInt8(mod(Int(result[pos]) + delta, 256))
    return result
end

"""Insert random bytes at a random position."""
struct InsertMutator <: AbstractMutator
    max_insert::Int
    InsertMutator(n::Int=16) = new(n)
end

function mutate(m::InsertMutator, input::Vector{UInt8}, rng::AbstractRNG)
    n = rand(rng, 1:m.max_insert)
    pos = isempty(input) ? 1 : rand(rng, 1:length(input)+1)
    new_bytes = rand(rng, UInt8, n)
    return vcat(input[1:pos-1], new_bytes, input[pos:end])
end

"""Delete random bytes from the input."""
struct DeleteMutator <: AbstractMutator
    max_delete::Int
    DeleteMutator(n::Int=16) = new(n)
end

function mutate(m::DeleteMutator, input::Vector{UInt8}, rng::AbstractRNG)
    (isempty(input) || length(input) <= 1) && return input
    n = min(rand(rng, 1:m.max_delete), length(input) - 1)
    pos = rand(rng, 1:length(input) - n + 1)
    return vcat(input[1:pos-1], input[pos+n:end])
end

"""Splice two inputs together."""
struct SpliceMutator <: AbstractMutator end

function mutate(m::SpliceMutator, input::Vector{UInt8}, rng::AbstractRNG;
                other::Vector{UInt8}=UInt8[])
    isempty(other) && return mutate(ByteFlipMutator(), input, rng)
    pos1 = isempty(input) ? 1 : rand(rng, 1:length(input))
    pos2 = rand(rng, 1:length(other))
    return vcat(input[1:pos1], other[pos2:end])
end

"""Insert tokens from a dictionary."""
struct DictionaryMutator <: AbstractMutator
    tokens::Vector{Vector{UInt8}}
end

function mutate(m::DictionaryMutator, input::Vector{UInt8}, rng::AbstractRNG)
    isempty(m.tokens) && return mutate(ByteFlipMutator(), input, rng)
    token = m.tokens[rand(rng, 1:length(m.tokens))]
    
    # Either insert or overwrite
    if rand(rng, Bool) || isempty(input)
        pos = isempty(input) ? 1 : rand(rng, 1:length(input)+1)
        return vcat(input[1:pos-1], token, input[pos:end])
    else
        pos = rand(rng, 1:max(1, length(input) - length(token) + 1))
        endpos = min(pos + length(token) - 1, length(input))
        result = copy(input)
        result[pos:endpos] .= token[1:endpos-pos+1]
        return result
    end
end

"""Combine multiple mutators with weighted selection."""
struct CompositeMutator <: AbstractMutator
    mutators::Vector{AbstractMutator}
    weights::Vector{Float64}
end

function CompositeMutator(mutators::Vector{<:AbstractMutator})
    n = length(mutators)
    CompositeMutator(collect(AbstractMutator, mutators), fill(1.0 / n, n))
end

function mutate(m::CompositeMutator, input::Vector{UInt8}, rng::AbstractRNG)
    # Weighted random selection
    r = rand(rng)
    cumulative = 0.0
    idx = length(m.mutators)
    for (i, w) in enumerate(m.weights)
        cumulative += w
        if r <= cumulative
            idx = i
            break
        end
    end
    return mutate(m.mutators[idx], input, rng)
end

"""Default mutation strategy combining all mutators."""
function default_mutator(; dictionary::Vector{Vector{UInt8}} = Vector{UInt8}[])
    mutators = AbstractMutator[
        BitFlipMutator(1),
        BitFlipMutator(4),
        ByteFlipMutator(1),
        ByteFlipMutator(4),
        ArithmeticMutator(35),
        InsertMutator(16),
        DeleteMutator(16),
    ]
    weights = [0.15, 0.10, 0.15, 0.10, 0.15, 0.15, 0.10]
    
    if !isempty(dictionary)
        push!(mutators, DictionaryMutator(dictionary))
        push!(weights, 0.10)
    end
    
    # Normalize
    total = sum(weights)
    weights ./= total
    
    CompositeMutator(mutators, weights)
end

# ─────────────────────────────────────────────────────────────────────────────
#                              GENERATORS
# ─────────────────────────────────────────────────────────────────────────────

"""Abstract base type for input generators."""
abstract type AbstractGenerator end

"""Generate random integers of various sizes and encodings."""
struct IntegerGenerator <: AbstractGenerator
    sizes::Vector{Int}  # byte widths: 1, 2, 4, 8
    include_boundaries::Bool
end

IntegerGenerator() = IntegerGenerator([1, 2, 4, 8], true)

function generate_input(g::IntegerGenerator, rng::AbstractRNG)
    size = g.sizes[rand(rng, 1:length(g.sizes))]
    
    if g.include_boundaries && rand(rng) < 0.3
        # Generate boundary values (common bug triggers)
        boundaries = if size == 1
            UInt8[0x00, 0x01, 0x7f, 0x80, 0xff]
        elseif size == 2
            reinterpret(UInt8, UInt16[0x0000, 0x0001, 0x7fff, 0x8000, 0xffff])
        elseif size == 4
            reinterpret(UInt8, UInt32[0x00000000, 0x00000001, 0x7fffffff, 0x80000000, 0xffffffff])
        else
            reinterpret(UInt8, UInt64[0x0000000000000000, 0x0000000000000001,
                                     0x7fffffffffffffff, 0x8000000000000000,
                                     0xffffffffffffffff])
        end
        n_boundaries = length(boundaries) ÷ size
        idx = rand(rng, 1:n_boundaries)
        return collect(boundaries[(idx-1)*size+1 : idx*size])
    end
    
    return rand(rng, UInt8, size)
end

"""Generate random strings with various character sets."""
struct StringGenerator <: AbstractGenerator
    min_length::Int
    max_length::Int
    charset::Symbol  # :ascii, :alphanumeric, :printable, :binary, :unicode
end

StringGenerator() = StringGenerator(0, 256, :printable)

function generate_input(g::StringGenerator, rng::AbstractRNG)
    n = rand(rng, g.min_length:g.max_length)
    
    if g.charset == :ascii
        return rand(rng, UInt8(0x00):UInt8(0x7f), n)
    elseif g.charset == :alphanumeric
        chars = vcat(UInt8('a'):UInt8('z'), UInt8('A'):UInt8('Z'), UInt8('0'):UInt8('9'))
        return UInt8[chars[rand(rng, 1:length(chars))] for _ in 1:n]
    elseif g.charset == :printable
        return rand(rng, UInt8(0x20):UInt8(0x7e), n)
    elseif g.charset == :unicode
        # Mix of ASCII and multi-byte UTF-8 sequences
        result = UInt8[]
        while length(result) < n
            if rand(rng) < 0.7
                push!(result, rand(rng, UInt8(0x20):UInt8(0x7e)))
            else
                # 2-byte UTF-8 character
                c = rand(rng, 0x80:0x7ff)
                push!(result, UInt8(0xc0 | (c >> 6)))
                push!(result, UInt8(0x80 | (c & 0x3f)))
            end
        end
        return result[1:min(n, length(result))]
    else  # :binary
        return rand(rng, UInt8, n)
    end
end

"""Generate random binary data."""
struct BinaryGenerator <: AbstractGenerator
    min_length::Int
    max_length::Int
end

BinaryGenerator() = BinaryGenerator(0, 1024)

function generate_input(g::BinaryGenerator, rng::AbstractRNG)
    n = rand(rng, g.min_length:g.max_length)
    return rand(rng, UInt8, n)
end

"""Generate structured inputs from a grammar/template."""
struct StructuredGenerator <: AbstractGenerator
    templates::Vector{Vector{Any}}  # Mix of UInt8[] literals and :random/:int/:string markers
end

function generate_input(g::StructuredGenerator, rng::AbstractRNG)
    isempty(g.templates) && return rand(rng, UInt8, 16)
    template = g.templates[rand(rng, 1:length(g.templates))]
    
    result = UInt8[]
    for part in template
        if part isa Vector{UInt8}
            append!(result, part)
        elseif part == :random
            append!(result, rand(rng, UInt8, rand(rng, 1:32)))
        elseif part == :int
            append!(result, generate_input(IntegerGenerator(), rng))
        elseif part == :string
            append!(result, generate_input(StringGenerator(1, 32, :printable), rng))
        elseif part isa Pair
            # :repeat => (element, min, max)
            elem, lo, hi = part.second
            n = rand(rng, lo:hi)
            for _ in 1:n
                if elem isa Vector{UInt8}
                    append!(result, elem)
                else
                    append!(result, rand(rng, UInt8, 4))
                end
            end
        end
    end
    return result
end

# ─────────────────────────────────────────────────────────────────────────────
#                              COVERAGE
# ─────────────────────────────────────────────────────────────────────────────

"""Compute a lightweight coverage hash from execution trace.

Uses the error/non-error path plus input characteristics as a proxy
for code coverage (true coverage instrumentation requires compiler support).
"""
function coverage_hash(input::Vector{UInt8}, crashed::Bool, error_type::Union{String,Nothing})
    h = sha256(input)
    val = reinterpret(UInt64, h[1:8])[1]
    if crashed
        val ⊻= hash(error_type)
    end
    # Also factor in input length buckets
    bucket = Int(floor(log2(max(1, length(input)))))
    val ⊻= UInt64(bucket) << 48
    return val
end

# ─────────────────────────────────────────────────────────────────────────────
#                              ENERGY / SCHEDULING
# ─────────────────────────────────────────────────────────────────────────────

"""Calculate energy (number of mutations) for a corpus entry."""
function calculate_energy(corpus::FuzzCorpus, idx::Int)
    # Inputs that discovered new coverage get more energy
    base_energy = 4
    input = corpus.inputs[idx]
    
    # Shorter inputs get more energy (prefer minimal test cases)
    if length(input) < 64
        base_energy += 4
    elseif length(input) < 256
        base_energy += 2
    end
    
    return base_energy
end

# ─────────────────────────────────────────────────────────────────────────────
#                              MAIN FUZZER
# ─────────────────────────────────────────────────────────────────────────────

"""
    fuzz(target, seed_input; kwargs...) -> FuzzCorpus

Fuzz a target function to find crashes and interesting inputs.

# Arguments
- `target`: Function that takes `Vector{UInt8}` and processes it.
  Any exception thrown is recorded as a crash.
- `seed_input`: Initial input to start fuzzing from.

# Keyword Arguments
- `max_iterations::Int=10000`: Maximum number of test cases to run.
- `max_input_size::Int=4096`: Maximum input size in bytes.
- `strategy::Symbol=:mutation`: Fuzzing strategy (`:mutation`, `:generation`, `:dictionary`).
- `dictionary::Vector{Vector{UInt8}}=[]`: Token dictionary for dictionary-guided fuzzing.
- `verbose::Bool=false`: Print progress information.
- `seed::Int=0`: RNG seed (0 = random).
- `save_crashes::Bool=true`: Save crash inputs to disk.
- `crash_dir::String="crashes"`: Directory for crash files.

# Returns
A `FuzzCorpus` containing all interesting inputs and crashes found.

# Examples
```julia
# Fuzz a parser
results = fuzz(my_parser, UInt8[]; max_iterations=10000)
println("Found \$(length(results.crashes)) crashes")

# Dictionary-guided fuzzing for HTTP
results = fuzz(http_handler, b"GET / HTTP/1.1\\r\\n";
               strategy=:dictionary,
               dictionary=[b"GET", b"POST", b"\\r\\n", b"Content-Length:"])
```
"""
function fuzz(target::Function, seed_input::Vector{UInt8} = UInt8[];
              max_iterations::Int = 10000,
              max_input_size::Int = 4096,
              strategy::Symbol = :mutation,
              dictionary::Vector{Vector{UInt8}} = Vector{UInt8}[],
              verbose::Bool = false,
              seed::Int = 0,
              save_crashes::Bool = true,
              crash_dir::String = "crashes")
    
    rng = seed == 0 ? Random.default_rng() : Random.MersenneTwister(seed)
    
    corpus = FuzzCorpus()
    push!(corpus.inputs, copy(seed_input))
    
    # Set up mutator based on strategy
    mutator = if strategy == :dictionary && !isempty(dictionary)
        default_mutator(; dictionary=dictionary)
    elseif strategy == :generation
        # Pure generation mode - not mutation-based
        nothing
    else
        default_mutator()
    end
    
    # Set up generator for generation mode
    generator = BinaryGenerator(0, min(256, max_input_size))
    
    if verbose
        println("🔍 Fuzzing started: strategy=$strategy, max_iterations=$max_iterations")
    end
    
    for i in 1:max_iterations
        # Generate next input
        input = if strategy == :generation
            generate_input(generator, rng)
        else
            # Pick from corpus and mutate
            base_idx = rand(rng, 1:length(corpus.inputs))
            base = corpus.inputs[base_idx]
            
            # Apply multiple mutations based on energy
            energy = calculate_energy(corpus, base_idx)
            result = copy(base)
            for _ in 1:rand(rng, 1:energy)
                result = mutate(mutator, result, rng)
            end
            result
        end
        
        # Enforce size limit
        if length(input) > max_input_size
            input = input[1:max_input_size]
        end
        
        # Execute target
        crashed = false
        error_type = nothing
        error_msg = nothing
        
        try
            target(input)
        catch e
            crashed = true
            error_type = string(typeof(e))
            error_msg = try
                sprint(showerror, e)
            catch
                "Error during showerror"
            end
        end
        
        corpus.total_runs += 1
        
        # Compute coverage
        ch = coverage_hash(input, crashed, error_type)
        
        if crashed
            result = FuzzResult(copy(input), true, error_type, error_msg, ch)
            push!(corpus.crashes, result)
            
            if verbose
                println("💥 CRASH #$(length(corpus.crashes)) at iteration $i: $error_type")
            end
            
            if save_crashes
                _save_crash(crash_dir, result, length(corpus.crashes))
            end
        end
        
        # Add to corpus if new coverage
        if !(ch in corpus.coverage_set)
            push!(corpus.coverage_set, ch)
            push!(corpus.inputs, copy(input))
        end
        
        # Progress report
        if verbose && i % 1000 == 0
            println("📊 Progress: $i/$max_iterations | corpus=$(length(corpus.inputs)) | crashes=$(length(corpus.crashes))")
        end
    end
    
    if verbose
        println("✅ Fuzzing complete: $(corpus.total_runs) runs, $(length(corpus.crashes)) crashes, $(length(corpus.inputs)) corpus entries")
    end
    
    return corpus
end

"""Save a crash-triggering input to disk."""
function _save_crash(dir::String, result::FuzzResult, idx::Int)
    try
        mkpath(dir)
        filename = joinpath(dir, "crash_$(lpad(idx, 6, '0')).bin")
        write(filename, result.input)
        
        # Write metadata
        meta_file = joinpath(dir, "crash_$(lpad(idx, 6, '0')).txt")
        open(meta_file, "w") do f
            println(f, "Error Type: $(result.error_type)")
            println(f, "Error Message: $(result.error_msg)")
            println(f, "Input Length: $(length(result.input))")
            println(f, "Input (hex): $(bytes2hex(result.input))")
        end
    catch
        # Don't crash the fuzzer if we can't save
    end
end

# ─────────────────────────────────────────────────────────────────────────────
#                              UTILITIES
# ─────────────────────────────────────────────────────────────────────────────

"""
    minimize(target, crash_input; max_iterations=1000) -> Vector{UInt8}

Attempt to minimize a crash-triggering input while preserving the crash.
Uses delta debugging to find a minimal reproducer.
"""
function minimize(target::Function, crash_input::Vector{UInt8};
                  max_iterations::Int = 1000)
    current = copy(crash_input)
    
    # Verify it actually crashes
    crashes = try
        target(current)
        false
    catch
        true
    end
    crashes || error("Input does not crash the target")
    
    # Try progressively smaller chunks
    for _ in 1:max_iterations
        improved = false
        
        # Try removing chunks of decreasing size
        for chunk_size in [length(current) ÷ 2, length(current) ÷ 4,
                           length(current) ÷ 8, 1]
            chunk_size < 1 && continue
            
            pos = 1
            while pos + chunk_size - 1 <= length(current)
                candidate = vcat(current[1:pos-1], current[pos+chunk_size:end])
                isempty(candidate) && break
                
                still_crashes = try
                    target(candidate)
                    false
                catch
                    true
                end
                
                if still_crashes
                    current = candidate
                    improved = true
                else
                    pos += 1
                end
            end
        end
        
        !improved && break
    end
    
    return current
end

"""
    fuzz_compare(f1, f2, seed_input; kwargs...) -> Vector{FuzzResult}

Differential fuzzing: find inputs where f1 and f2 produce different results.
Returns inputs that cause divergent behavior.
"""
function fuzz_compare(f1::Function, f2::Function, seed_input::Vector{UInt8} = UInt8[];
                      max_iterations::Int = 10000, seed::Int = 0)
    rng = seed == 0 ? Random.default_rng() : Random.MersenneTwister(seed)
    mutator = default_mutator()
    
    divergences = FuzzResult[]
    inputs = [copy(seed_input)]
    
    for i in 1:max_iterations
        base = inputs[rand(rng, 1:length(inputs))]
        input = mutate(mutator, base, rng)
        
        r1 = try
            (result=f1(input), error=nothing)
        catch e
            (result=nothing, error=e)
        end
        r2 = try
            (result=f2(input), error=nothing)
        catch e
            (result=nothing, error=e)
        end
        
        # Check for divergence
        diverged = false
        if r1.error !== nothing && r2.error === nothing
            diverged = true
        elseif r1.error === nothing && r2.error !== nothing
            diverged = true
        elseif r1.error === nothing && r2.error === nothing
            if r1.result != r2.result
                diverged = true
            end
        end
        
        if diverged
            push!(divergences, FuzzResult(copy(input), true, "Divergence",
                  "f1=$(r1) vs f2=$(r2)", UInt64(0)))
        end
        
        push!(inputs, input)
        if length(inputs) > 100
            deleteat!(inputs, 1:length(inputs)-50)
        end
    end
    
    return divergences
end

end # module Fuzz
