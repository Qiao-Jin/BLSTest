``` ini

BenchmarkDotNet=v0.13.1, OS=Windows 10.0.22000
Intel Core i7-8700 CPU 3.20GHz (Coffee Lake), 1 CPU, 12 logical and 6 physical cores
.NET SDK=6.0.100
  [Host]     : .NET 6.0.0 (6.0.21.52210), X64 RyuJIT  [AttachedDebugger]
  DefaultJob : .NET 6.0.0 (6.0.21.52210), X64 RyuJIT


```
| Method |         Mean |      Error |     StdDev |
|------- |-------------:|-----------:|-----------:|
|   BLS4 |     31.60 ms |   0.260 ms |   0.203 ms |
|   BLS5 |     47.45 ms |   0.339 ms |   0.317 ms |
|   BLS6 |     66.09 ms |   0.317 ms |   0.297 ms |
|   BLS7 |     89.48 ms |   0.375 ms |   0.333 ms |
|   BLS8 |    115.30 ms |   0.470 ms |   0.367 ms |
|   BLS9 |    144.50 ms |   0.863 ms |   0.807 ms |
|  BLS10 |    192.17 ms |   0.802 ms |   0.750 ms |
|  BLS11 |    235.34 ms |   1.527 ms |   1.429 ms |
|  BLS12 |    295.38 ms |   1.484 ms |   1.315 ms |
|  BLS13 |    824.90 ms |   4.211 ms |   3.939 ms |
|  BLS14 |  1,170.45 ms |   3.394 ms |   3.175 ms |
|  BLS15 |  1,596.20 ms |   7.840 ms |   7.334 ms |
|  BLS16 | 24,311.59 ms |  53.162 ms |  49.728 ms |
|  BLS17 | 36,491.57 ms | 140.292 ms | 117.150 ms |
|  BLS18 | 53,476.61 ms | 212.708 ms | 166.068 ms |
