using System;
using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;
using BLSTest;
namespace Benchmarks
{
    [MarkdownExporter, AsciiDocExporter, HtmlExporter, CsvExporter, RPlotExporter]
    public class BLSBenchmark
    {

        BLS_N3 init(uint a)
        {
            

            var blstest = new BLS_N3(a, (a + 2) / 3); // number of dishonest node is no more than f, therefore we only need signatures from f+1 CNs

            blstest.KeyDistribution();

            blstest.PublicKeysforSignatureDistribution();

            return blstest;
        }


        BLS_N3 bls4 => init(4);

        [Benchmark]
        public void BLS4() =>bls4.GetSignatures();

        BLS_N3 bls5 => init(5);

        [Benchmark]
        public void BLS5() => bls5.GetSignatures();

        BLS_N3 bls6 => init(6);
        [Benchmark]
        public void BLS6() => bls6.GetSignatures();


        BLS_N3 bls7 => init(7);

        [Benchmark]
        public void BLS7() => bls7.GetSignatures();


        BLS_N3 bls8 => init(8);

        [Benchmark]
        public void BLS8() => bls8.GetSignatures();

        BLS_N3 bls9 => init(9);

        [Benchmark]
        public void BLS9() => bls9.GetSignatures();

        BLS_N3 bls10 => init(10);

        [Benchmark]
        public void BLS10() => bls10.GetSignatures();


        BLS_N3 bls11 => init(11);

        [Benchmark]
        public void BLS11() => bls11.GetSignatures();

        BLS_N3 bls12 => init(12);

        [Benchmark]
        public void BLS12() => bls12.GetSignatures();

        BLS_N3 bls13=> init(13);

        [Benchmark]
        public void BLS13() => bls13.GetSignatures();

        BLS_N3 bls14=> init(14);

        [Benchmark]
        public void BLS14() => bls14.GetSignatures();

        BLS_N3 bls15 => init(15);

        [Benchmark]
        public void BLS15() => bls15.GetSignatures();


        BLS_N3 bls16 => init(16);

        [Benchmark]
        public void BLS16() => bls16.GetSignatures();


        BLS_N3 bls17 => init(17);

        [Benchmark]
        public void BLS17() => bls17.GetSignatures();


        BLS_N3 bls18 => init(18);

        [Benchmark]
        public void BLS18() => bls18.GetSignatures();


        //BLS_N3 bls19 => init(19);

        //[Benchmark]
        //public void BLS19() => bls19.GetSignatures();


        //BLS_N3 bls20 => init(20);

        //[Benchmark]
        //public void BLS20() => bls20.GetSignatures();

        //BLS_N3 bls21 => init(21);

        //[Benchmark]
        //public void BLS21() => bls21.GetSignatures();

        //BLS_N3 bls22 => init(22);

        //[Benchmark]
        //public void BLS22() => bls22.GetSignatures();

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