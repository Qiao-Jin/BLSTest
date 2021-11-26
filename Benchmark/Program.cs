using System;
using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;
using BLSTest;
namespace Benchmarks
{
    public class BLSBenchmark
    {

        BLS_N3 init(uint a, uint b)
        {
            var blstest = new BLS_N3(a, b); // number of dishonest node is no more than f, therefore we only need signatures from f+1 CNs

            blstest.KeyDistribution();

            blstest.PublicKeysforSignatureDistribution();

            return blstest;
        }

        BLS_N3 bls4_2 => init(4, 2);

        [Benchmark]
        public void BLS4_2() =>bls4_2.GetSignatures();

        BLS_N3 bls5_2 => init(5, 2);

        [Benchmark]
        public void BLS5_2() => bls5_2.GetSignatures();

        BLS_N3 bls6_3 => init(6, 3);
        [Benchmark]
        public void BLS6_3() => bls6_3.GetSignatures();


        BLS_N3 bls7_3 => init(7, 3);

        [Benchmark]
        public void BLS7_3() => bls7_3.GetSignatures();


        BLS_N3 bls8_3 => init(8, 3);

        [Benchmark]
        public void BLS8_3() => bls8_3.GetSignatures();

        BLS_N3 bls9_4 => init(9, 4);

        [Benchmark]
        public void BLS9_4() => bls9_4.GetSignatures();

        BLS_N3 bls10_4 => init(10, 4);

        [Benchmark]
        public void BLS10_4() => bls10_4.GetSignatures();

        //Calculate final signature
        //Console.WriteLine("\n\n-----------------------------");
        //    Console.WriteLine("Calculate final signature");
        //    Console.WriteLine("-----------------------------\n");

        //    blstest.GetFinalSignatures(sigs);};
    }

    public class Program
    {
        public static void Main(string[] args)
        {
            var summary = BenchmarkRunner.Run(typeof(Program).Assembly);
        }
    }
}