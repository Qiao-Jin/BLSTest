
BenchmarkDotNet=v0.13.1, OS=Windows 10.0.22000
Intel Core i7-8700 CPU 3.20GHz (Coffee Lake), 1 CPU, 12 logical and 6 physical cores
.NET SDK=6.0.100
  [Host]     : .NET 6.0.0 (6.0.21.52210), X64 RyuJIT  [AttachedDebugger]
  DefaultJob : .NET 6.0.0 (6.0.21.52210), X64 RyuJIT


  Method |      Mean |    Error |   StdDev |    Median |
-------- |----------:|---------:|---------:|----------:|
  BLS4_2 |  31.99 ms | 0.506 ms | 0.422 ms |  31.99 ms |
  BLS5_2 |  48.25 ms | 0.932 ms | 0.826 ms |  48.13 ms |
  BLS6_3 |  69.97 ms | 1.398 ms | 2.411 ms |  68.64 ms |
  BLS7_3 |  90.03 ms | 0.557 ms | 0.493 ms |  89.90 ms |
  BLS8_3 | 115.57 ms | 0.892 ms | 0.876 ms | 115.34 ms |
  BLS9_4 | 154.24 ms | 0.389 ms | 0.325 ms | 154.32 ms |
 BLS10_4 | 192.25 ms | 0.553 ms | 0.490 ms | 192.16 ms |
