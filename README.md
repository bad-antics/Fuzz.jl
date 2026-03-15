# Fuzz.jl

[![Tests](https://img.shields.io/badge/tests-100%20passed-brightgreen)]()
[![Julia](https://img.shields.io/badge/julia-1.6%2B-blue)]()

**Security fuzzing toolkit for Julia** — mutation-based, generation-based, and coverage-guided fuzzing for finding bugs and vulnerabilities.

## Features

- **Mutation-based fuzzing** — bit/byte flip, arithmetic, insert, delete, splice, dictionary
- **Generation-based fuzzing** — integers, strings, binary, structured templates
- **Coverage-guided** — corpus management with energy scheduling
- **Crash minimization** — delta debugging to find minimal reproducers
- **Differential fuzzing** — compare two implementations for divergent behavior
- **Crash recording** — automatic saving of crash inputs and metadata

## Installation

```julia
using Pkg
Pkg.add("Fuzz")
```

## Quick Start

```julia
using Fuzz

# Fuzz a parser to find crashes
corpus = fuzz(my_parser, UInt8[]; max_iterations=10000)
println("Found $(length(corpus.crashes)) crashes in $(corpus.total_runs) runs")

# Check results
for crash in corpus.crashes
    println("  $(crash.error_type): $(crash.error_msg)")
end
```

## Mutators

| Mutator | Description |
|---------|-------------|
| `BitFlipMutator(n)` | Flip `n` random bits |
| `ByteFlipMutator(n)` | Replace `n` random bytes |
| `ArithmeticMutator(d)` | Add/subtract up to `d` from a byte |
| `InsertMutator(n)` | Insert up to `n` random bytes |
| `DeleteMutator(n)` | Delete up to `n` bytes |
| `SpliceMutator()` | Splice two inputs together |
| `DictionaryMutator(tokens)` | Insert/overwrite with dictionary tokens |
| `CompositeMutator(mutators)` | Weighted combination of mutators |

## Generators

| Generator | Description |
|-----------|-------------|
| `IntegerGenerator()` | Random integers (1/2/4/8 byte, boundary values) |
| `StringGenerator(min, max, charset)` | Random strings (`:ascii`, `:alphanumeric`, `:printable`, `:unicode`, `:binary`) |
| `BinaryGenerator(min, max)` | Random binary data |
| `StructuredGenerator(templates)` | Template-based structured input |

## Advanced Usage

```julia
# Dictionary-guided fuzzing for protocol testing
tokens = [collect(UInt8, "GET"), collect(UInt8, "POST"),
          UInt8[0x0d, 0x0a], collect(UInt8, "HTTP/1.1")]
corpus = fuzz(http_handler, collect(UInt8, "GET / HTTP/1.1\r\n");
              strategy=:dictionary, dictionary=tokens)

# Minimize a crash
minimized = Fuzz.minimize(buggy_fn, crash_input)

# Differential fuzzing
divergences = Fuzz.fuzz_compare(impl_v1, impl_v2, UInt8[])
```

## License

MIT
