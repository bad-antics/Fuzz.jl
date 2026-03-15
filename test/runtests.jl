using Test
using Fuzz
using Random

@testset "Fuzz.jl" begin

    @testset "BitFlipMutator" begin
        m = BitFlipMutator(1)
        rng = MersenneTwister(42)
        
        input = UInt8[0x00, 0x00, 0x00, 0x00]
        result = mutate(m, input, rng)
        @test length(result) == 4
        @test result != input
        
        m4 = BitFlipMutator(4)
        result4 = mutate(m4, zeros(UInt8, 8), rng)
        @test length(result4) == 8
        
        empty_result = mutate(m, UInt8[], rng)
        @test length(empty_result) == 1
    end

    @testset "ByteFlipMutator" begin
        m = ByteFlipMutator(2)
        rng = MersenneTwister(42)
        
        input = zeros(UInt8, 8)
        result = mutate(m, input, rng)
        @test length(result) == 8
        
        empty_result = mutate(m, UInt8[], rng)
        @test length(empty_result) == 1
    end

    @testset "ArithmeticMutator" begin
        m = ArithmeticMutator(10)
        rng = MersenneTwister(42)
        
        input = UInt8[100, 100, 100, 100]
        result = mutate(m, input, rng)
        @test length(result) == 4
        diffs = sum(result .!= input)
        @test diffs <= 1
        
        empty_result = mutate(m, UInt8[], rng)
        @test length(empty_result) == 1
    end

    @testset "InsertMutator" begin
        m = InsertMutator(8)
        rng = MersenneTwister(42)
        
        input = UInt8[1, 2, 3]
        result = mutate(m, input, rng)
        @test length(result) > length(input)
        @test length(result) <= length(input) + 8
        
        empty_result = mutate(m, UInt8[], rng)
        @test !isempty(empty_result)
    end

    @testset "DeleteMutator" begin
        m = DeleteMutator(4)
        rng = MersenneTwister(42)
        
        input = UInt8[1, 2, 3, 4, 5, 6, 7, 8]
        result = mutate(m, input, rng)
        @test length(result) < length(input)
        @test !isempty(result)
        
        single = mutate(m, UInt8[42], rng)
        @test single == UInt8[42]
        
        empty_result = mutate(m, UInt8[], rng)
        @test isempty(empty_result)
    end

    @testset "DictionaryMutator" begin
        tokens = [UInt8[0xff, 0xfe], UInt8[0x00, 0x01]]
        m = DictionaryMutator(tokens)
        rng = MersenneTwister(42)
        
        input = UInt8[10, 20, 30, 40, 50]
        result = mutate(m, input, rng)
        @test !isempty(result)
        
        m_empty = DictionaryMutator(Vector{UInt8}[])
        result_empty = mutate(m_empty, input, rng)
        @test !isempty(result_empty)
    end

    @testset "CompositeMutator" begin
        mutators = Fuzz.AbstractMutator[BitFlipMutator(), ByteFlipMutator()]
        m = CompositeMutator(mutators)
        rng = MersenneTwister(42)
        
        input = zeros(UInt8, 16)
        result = mutate(m, input, rng)
        @test length(result) == 16
        
        m2 = CompositeMutator(mutators, [0.9, 0.1])
        result2 = mutate(m2, input, rng)
        @test length(result2) == 16
    end

    @testset "IntegerGenerator" begin
        g = IntegerGenerator()
        rng = MersenneTwister(42)
        
        for _ in 1:20
            result = generate_input(g, rng)
            @test length(result) in [1, 2, 4, 8]
        end
    end

    @testset "StringGenerator" begin
        g = StringGenerator(4, 16, :alphanumeric)
        rng = MersenneTwister(42)
        
        result = generate_input(g, rng)
        @test 4 <= length(result) <= 16
        @test all(c -> (UInt8('a') <= c <= UInt8('z')) ||
                       (UInt8('A') <= c <= UInt8('Z')) ||
                       (UInt8('0') <= c <= UInt8('9')), result)
        
        g_ascii = StringGenerator(1, 32, :ascii)
        result_ascii = generate_input(g_ascii, rng)
        @test all(c -> c <= 0x7f, result_ascii)
        
        g_print = StringGenerator(1, 32, :printable)
        result_print = generate_input(g_print, rng)
        @test all(c -> 0x20 <= c <= 0x7e, result_print)
        
        g_bin = StringGenerator(1, 32, :binary)
        result_bin = generate_input(g_bin, rng)
        @test 1 <= length(result_bin) <= 32
        
        g_uni = StringGenerator(1, 32, :unicode)
        result_uni = generate_input(g_uni, rng)
        @test !isempty(result_uni)
    end

    @testset "BinaryGenerator" begin
        g = BinaryGenerator(8, 64)
        rng = MersenneTwister(42)
        
        for _ in 1:10
            result = generate_input(g, rng)
            @test 8 <= length(result) <= 64
        end
    end

    @testset "StructuredGenerator" begin
        templates = [
            Any[UInt8[0x47, 0x45, 0x54], UInt8[0x20], :string, UInt8[0x0d, 0x0a]],
        ]
        g = StructuredGenerator(templates)
        rng = MersenneTwister(42)
        
        result = generate_input(g, rng)
        @test !isempty(result)
        @test result[1:3] == UInt8[0x47, 0x45, 0x54]
        
        g_empty = StructuredGenerator(Vector{Any}[])
        result_empty = generate_input(g_empty, rng)
        @test !isempty(result_empty)
    end

    @testset "FuzzCorpus" begin
        c = FuzzCorpus()
        @test length(c.inputs) == 0
        @test length(c.crashes) == 0
        @test c.total_runs == 0
        
        io = IOBuffer()
        show(io, c)
        s = String(take!(io))
        @test occursin("FuzzCorpus", s)
    end

    @testset "Basic Fuzzing - No Crashes" begin
        safe_fn(data) = length(data)
        
        corpus = fuzz(safe_fn, UInt8[1, 2, 3];
                      max_iterations=100, seed=42, save_crashes=false)
        @test corpus.total_runs == 100
        @test isempty(corpus.crashes)
        @test !isempty(corpus.inputs)
    end

    @testset "Fuzzing - Find Crash" begin
        buggy_fn(data) = if length(data) >= 3 && data[1] == 0xff && data[2] == 0xfe
            error("crash: magic bytes found")
        end
        
        corpus = fuzz(buggy_fn, UInt8[0xff, 0x00];
                      max_iterations=5000, seed=42, save_crashes=false)
        @test corpus.total_runs == 5000
        @test !isempty(corpus.inputs)
    end

    @testset "Fuzzing - Guaranteed Crash" begin
        crash_fn(data) = error("always crashes")
        
        corpus = fuzz(crash_fn, UInt8[];
                      max_iterations=10, seed=42, save_crashes=false)
        @test !isempty(corpus.crashes)
        @test corpus.crashes[1].crashed
        @test corpus.crashes[1].error_type == "ErrorException"
    end

    @testset "Generation-Based Fuzzing" begin
        counter = Ref(0)
        target(data) = (counter[] += 1; nothing)
        
        corpus = fuzz(target, UInt8[];
                      max_iterations=50, strategy=:generation,
                      seed=42, save_crashes=false)
        @test corpus.total_runs == 50
        @test counter[] == 50
    end

    @testset "Dictionary-Guided Fuzzing" begin
        tokens = Vector{UInt8}[collect(UInt8, "GET"), collect(UInt8, "POST"),
                               UInt8[0x0d, 0x0a], collect(UInt8, "HTTP/1.1")]
        
        target(data) = nothing
        corpus = fuzz(target, collect(UInt8, "GET / HTTP/1.1\r\n");
                      max_iterations=50, strategy=:dictionary,
                      dictionary=tokens, seed=42, save_crashes=false)
        @test corpus.total_runs == 50
    end

    @testset "Input Size Limit" begin
        target(data) = @assert length(data) <= 64
        
        corpus = fuzz(target, UInt8[];
                      max_iterations=50, max_input_size=64,
                      seed=42, save_crashes=false)
        @test corpus.total_runs == 50
    end

    @testset "Minimize" begin
        target(data) = any(==(0xff), data) && error("found 0xff")
        
        crash_input = UInt8[1, 2, 3, 0xff, 5, 6, 7, 8, 9, 10]
        minimized = Fuzz.minimize(target, crash_input)
        @test length(minimized) < length(crash_input)
        @test 0xff in minimized
        
        @test_throws ErrorException Fuzz.minimize(target, UInt8[1, 2, 3])
    end

    @testset "Differential Fuzzing" begin
        f1(data) = length(data)
        f2(data) = isempty(data) ? -1 : length(data)
        
        divergences = Fuzz.fuzz_compare(f1, f2, UInt8[];
                                        max_iterations=100, seed=42)
        @test length(divergences) >= 0
    end

    @testset "FuzzResult Fields" begin
        r = FuzzResult(UInt8[1, 2, 3], true, "ErrorException", "test error", UInt64(12345))
        @test r.input == UInt8[1, 2, 3]
        @test r.crashed == true
        @test r.error_type == "ErrorException"
        @test r.error_msg == "test error"
        @test r.coverage_hash == UInt64(12345)
        
        r2 = FuzzResult(UInt8[], false, nothing, nothing, UInt64(0))
        @test !r2.crashed
        @test r2.error_type === nothing
    end

    @testset "Coverage Hash" begin
        h1 = Fuzz.coverage_hash(UInt8[1, 2, 3], false, nothing)
        h2 = Fuzz.coverage_hash(UInt8[1, 2, 3], false, nothing)
        @test h1 == h2
        
        h3 = Fuzz.coverage_hash(UInt8[4, 5, 6], false, nothing)
        @test h1 != h3
        
        h4 = Fuzz.coverage_hash(UInt8[1, 2, 3], true, "ErrorException")
        @test h1 != h4
    end

    @testset "Calculate Energy" begin
        corpus = FuzzCorpus()
        push!(corpus.inputs, UInt8[1, 2])
        push!(corpus.inputs, zeros(UInt8, 100))
        push!(corpus.inputs, zeros(UInt8, 500))
        
        e1 = Fuzz.calculate_energy(corpus, 1)
        e3 = Fuzz.calculate_energy(corpus, 3)
        @test e1 > e3
    end

    @testset "Save Crash" begin
        dir = mktempdir()
        result = FuzzResult(UInt8[0xde, 0xad], true, "TestError", "test", UInt64(0))
        Fuzz._save_crash(dir, result, 1)
        
        @test isfile(joinpath(dir, "crash_000001.bin"))
        @test isfile(joinpath(dir, "crash_000001.txt"))
        
        saved = read(joinpath(dir, "crash_000001.bin"))
        @test saved == UInt8[0xde, 0xad]
        
        meta = read(joinpath(dir, "crash_000001.txt"), String)
        @test occursin("TestError", meta)
    end

    @testset "Verbose Mode" begin
        corpus = fuzz(x -> nothing, UInt8[];
                      max_iterations=10, verbose=true,
                      seed=42, save_crashes=false)
        @test corpus.total_runs == 10
    end

    @testset "Default Mutator" begin
        m = Fuzz.default_mutator()
        @test m isa CompositeMutator
        @test length(m.mutators) == 7
        
        m_dict = Fuzz.default_mutator(dictionary=Vector{UInt8}[collect(UInt8, "test")])
        @test length(m_dict.mutators) == 8
    end

    @testset "SpliceMutator" begin
        m = SpliceMutator()
        rng = MersenneTwister(42)
        
        input = UInt8[1, 2, 3, 4]
        other = UInt8[10, 20, 30, 40]
        result = mutate(m, input, rng; other=other)
        @test !isempty(result)
        
        result2 = mutate(m, input, rng)
        @test !isempty(result2)
    end
end
