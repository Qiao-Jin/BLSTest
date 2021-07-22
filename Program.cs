using Cortex.Cryptography;
using System;
using System.Collections.Generic;
using System.Linq;

namespace BLSTest
{
    class Fraction
    {
        //coefficient
        public uint numerator;
        public uint denominator;
        public bool sign;

        //ID
        public uint id;
    }

    public class Program
    {
        private static uint getGCD(uint m, uint n)
        {
            uint result = 0;
            while (n != 0)
            {
                result = m % n;
                m = n;
                n = result;
            }
            return m;
        }

        private static uint getLCM (uint m, uint n)
        {
            return m * (n / getGCD(m, n));
        }

        private static uint getLCM (uint[] input)
        {
            if (input == null || input.Length == 0) return 0;
            if (input.Length == 1) return input[0];
            uint result = getLCM(input[0], input[1]);
            for (int i = 2; i < input.Length; i++)
            {
                result = getLCM(result, input[i]);
            }
            return result;
        }

        private static Fraction[] getCoefficient(bool[] input)
        {
            List<uint> convertedInput = new List<uint>();
            for (uint i = 0; i < input.Length; i++)
            {
                if (input[i])convertedInput.Add(i + 1);
            }
            return getCoefficient(convertedInput.ToArray());
        }

        private static Fraction[] getCoefficient(uint[] input)
        {
            if (input == null || input.Length == 0) return null;
            Array.Sort(input);
            uint product = input[0];
            if (product == 0) return null;
            for(int i = 1; i < input.Length; i++)
            {
                if (input[i] == 0 || input[i - 1] == input[i]) return null;
                product *= input[i];
            }
            Fraction[] result = new Fraction[input.Length];
            for (int i = 0; i < input.Length; i++)
            {
                result[i] = new Fraction();
                result[i].numerator = product / input[i];
                result[i].denominator = 1;
                for (int j = 0; j < input.Length; j++)
                {
                    if (j == i) continue;
                    result[i].denominator *= i < j ? input[j] - input[i] : input[i] - input[j];
                }
                uint gcd = getGCD(result[i].numerator, result[i].denominator);
                result[i].numerator /= gcd;
                result[i].denominator /= gcd;
                result[i].sign = i % 2 == 0;
                result[i].id = input[i] - 1;
            }
            return result;
        }

        private static IList<byte[]> Domains => new List<byte[]>
        {
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 },
            new byte[] { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
            new byte[] { 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
            new byte[] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef },
            new byte[] { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
        };

        private static IList<byte[]> MessageHashes => new List<byte[]>
        {
            Enumerable.Repeat((byte)0x00, BLSHerumi.HashLength).ToArray(),
            Enumerable.Repeat((byte)0x56, BLSHerumi.HashLength).ToArray(),
            Enumerable.Repeat((byte)0xab, BLSHerumi.HashLength).ToArray(),
        };

        private static byte[] generatePrivateKey()
        {
            Random rand = new Random();
            byte[] privateKey = BitConverter.GetBytes(rand.Next()).ToArray();
            for (int i = 0; i < BLSHerumi.PrivateKeyLength / 4 - 1; i++)
            {
                privateKey = privateKey.Concat(BitConverter.GetBytes(rand.Next())).ToArray();
            }

            //In case that aggregated private keys surpass limit
            privateKey[0] = 0;
            privateKey[1] = 0;
            privateKey[2] = 0;
            return privateKey;
        }

        private static byte[] aggregatePrivateKey(byte[][] privateKeys, uint[] weight)
        {
            if (privateKeys == null || privateKeys.Length == 0) return null;
            if (weight == null || weight.Length == 0) return null;
            if (privateKeys.Length != weight.Length) return null;
            byte[] result = new byte[privateKeys[0].Length];
            for (int j = 0; j < privateKeys.Length; j++)
            {
                for (int i = result.Length - 1; i >= 0; i--)
                {
                    uint roughResult = result[i] + privateKeys[j][i] * weight[j];
                    result[i] = (byte)roughResult;
                    uint flap = roughResult / 256;
                    int p = i - 1;
                    while (flap != 0)
                    {
                        if (p < 0) throw new ArithmeticException("Private key exceeds limit");
                        flap += result[p];
                        result[p] = (byte)flap;
                        flap /= 256;
                        p--;
                    }
                }
            }
            return result;
        }

        private static byte[] aggregatePublicKey(byte[][] publicKeys, uint[] weight)
        {
            if (publicKeys == null || publicKeys.Length == 0) return null;
            if (weight == null || weight.Length == 0) return null;
            if (publicKeys.Length != weight.Length) return null;

            uint overallweights = (uint)weight.Sum(p => p);
            var contractedPublicKeys = new Span<byte>(new byte[BLSHerumi.PublicKeyLength * overallweights]);
            int start = 0;
            for (int i = 0; i < publicKeys.Length; i++)
            {
                for (int j = 0; j < weight[i]; j++)
                {
                    publicKeys[i].CopyTo(contractedPublicKeys.Slice(start));
                    start += BLSHerumi.PublicKeyLength;
                }
            }
            using var blsAggregateKeys = new BLSHerumi(new BLSParameters());
            var aggregatePublicKey = new byte[BLSHerumi.PublicKeyLength];
            blsAggregateKeys.TryAggregatePublicKeys(contractedPublicKeys, aggregatePublicKey, out var _);
            return aggregatePublicKey;
        }

        private static void AggregateSignature(uint n, uint m)
        {
            //filter
            if (m == 0 || n == 0 || m > n) return;

            //initiate
            byte[][][] privateKeys = new byte[n][][];
            for (int i = 0; i < privateKeys.Length; i++)
            {
                privateKeys[i] = new byte[m][];
                for (int j = 0; j < m; j++)
                {
                    privateKeys[i][j] = generatePrivateKey();
                }
            }
            uint[][] commonWeightSet = new uint[n][];
            for (int i = 0; i < n; i++)
            {
                commonWeightSet[i] = new uint[m];
                commonWeightSet[i][0] = 1;
                for (int j = 1; j < m; j++)
                {
                    commonWeightSet[i][j] = (uint)(commonWeightSet[i][j - 1] * (i + 1));
                }
            }

            byte[][][] sharedPrivateKeys = new byte[n][][];//to, from, data
            for (int i = 0; i < sharedPrivateKeys.Length; i++)
            {
                sharedPrivateKeys[i] = new byte[n][];
                for (int j = 0; j < n; j++)
                {
                    byte[][] privateKeySet = new byte[m][];
                    for (int k = 0; k < privateKeySet.Length; k++)
                    {
                        privateKeySet[k] = privateKeys[j][k];
                    }
                    sharedPrivateKeys[i][j] = aggregatePrivateKey(privateKeySet, commonWeightSet[i]);
                }
            }
            var sharedMessageHash = MessageHashes[1];
            var domain1 = Domains[1];

            //Calculate public keys
            byte[][][] publicKeysPublic = new byte[n][][];
            for (int i = 0; i < publicKeysPublic.Length; i++)
            {
                publicKeysPublic[i] = new byte[m][];
                for (int j = 0; j < m; j++)
                {
                    using var blsPublic = new BLSHerumi(new BLSParameters() { PrivateKey = privateKeys[i][j] });
                    publicKeysPublic[i][j] = new byte[BLSHerumi.PublicKeyLength];
                    _ = blsPublic.TryExportBLSPublicKey(publicKeysPublic[i][j], out var _);
                }
            }

            //Aggregate public keys
            byte[][][] publicKeysAggregated = new byte[n][][];//to, from, data
            for (int i = 0; i < publicKeysAggregated.Length; i++)
            {
                publicKeysAggregated[i] = new byte[n][];
                for (int j = 0; j < n; j++)
                {
                    byte[][] publicKeySet = new byte[m][];
                    for (int k = 0; k < publicKeySet.Length; k++)
                    {
                        publicKeySet[k] = publicKeysPublic[j][k];
                    }
                    publicKeysAggregated[i][j] = aggregatePublicKey(publicKeySet, commonWeightSet[i]);
                }
            }

            //Sign & verify sharedPrivateKeys
            for (int i = 0; i < n; i++)
            {
                for (int j = 0; j < n; j++)
                {
                    using var blsSign = new BLSHerumi(new BLSParameters() { PrivateKey = sharedPrivateKeys[i][j] });
                    var signature = new byte[BLSHerumi.SignatureLength];
                    _ = blsSign.TrySignHash(sharedMessageHash, signature.AsSpan(), out var _, domain1);

                    var aggregatePublicKeyParameters = new BLSParameters()
                    {
                        PublicKey = publicKeysAggregated[i][j]
                    };
                    using var blsVerify = new BLSHerumi(aggregatePublicKeyParameters);
                    var verifySuccess = blsVerify.VerifyHash(sharedMessageHash, signature, domain1);
                    if (verifySuccess != true)
                    {
                        throw new Exception("SharedPrivateKeys Verification failed");
                    }
                }
            }

            //getAggregatePrivateKeys
            byte[][] aggregatePrivateKeys = new byte[n][];
            for (int i = 0; i < aggregatePrivateKeys.Length; i++)
            {
                byte[][] privateKeySet = new byte[n][];
                uint[] weightSet = new uint[n];
                for (int k = 0; k < privateKeySet.Length; k++)
                {
                    privateKeySet[k] = sharedPrivateKeys[i][k];
                    weightSet[k] = 1u;
                }
                aggregatePrivateKeys[i] = aggregatePrivateKey(privateKeySet, weightSet);
            }

            //get realPublicKeysAggregated
            byte[][] realPublicKeysAggregated = new byte[n][];
            for (int i = 0; i < realPublicKeysAggregated.Length; i++)
            {
                byte[][] publicKeySet = new byte[n][];
                uint[] weightSet = new uint[n];
                for (int k = 0; k < publicKeySet.Length; k++)
                {
                    publicKeySet[k] = publicKeysAggregated[i][k];
                    weightSet[k] = 1u;
                }
                realPublicKeysAggregated[i] = aggregatePublicKey(publicKeySet, weightSet);
            }

            //Sign signatures & verify aggregatePrivateKeys
            byte[][] signatures = new byte[n][];
            for (int i = 0; i < n; i++)
            {
                using var blsSign = new BLSHerumi(new BLSParameters() { PrivateKey = aggregatePrivateKeys[i] });
                signatures[i] = new byte[BLSHerumi.SignatureLength];
                _ = blsSign.TrySignHash(sharedMessageHash, signatures[i].AsSpan(), out var _, domain1);

                var aggregatePublicKeyParameters = new BLSParameters()
                {
                    PublicKey = realPublicKeysAggregated[i]
                };
                using var blsVerify = new BLSHerumi(aggregatePublicKeyParameters);
                var verifySuccess = blsVerify.VerifyHash(sharedMessageHash, signatures[i], domain1);
                if (verifySuccess != true)
                {
                    throw new Exception("AggregatePrivateKeys Verification failed");
                }
            }

            List<Fraction[]> fractions = new List<Fraction[]>();
            //Composition
            bool[] comp = new bool[n];
            int q = 0;
            for (; q < m; q++)
            {
                comp[q] = true;
            }
            fractions.Add(getCoefficient(comp));

            while (true)
            {
                for (q = 0; q < n - 1; q++)
                {
                    if (comp[q] == true && comp[q + 1] == false) break;
                }
                if (q == n - 1) break;
                comp[q] = false;
                comp[q + 1] = true;

                int p = 0;
                while (p < q)
                {
                    while (p < n - 1 && comp[p] == true) p++;
                    while (q > 0 && comp[q] == false) q--;
                    if (p < q)
                    {
                        comp[p] = true;
                        comp[q] = false;
                    }
                }
                fractions.Add(getCoefficient(comp));
            }
            //getLCM
            int count = fractions.Count;
            uint[] LCMs = new uint[count];
            for (int i = 0; i < count; i++)
            {
                uint[] denominators = new uint[fractions[i].Length];
                for (int j = 0; j < fractions[i].Length; j++)
                {
                    denominators[j] = fractions[i][j].denominator;
                }
                LCMs[i] = getLCM(denominators);
            }
            uint overallLCM = getLCM(LCMs);

            //computer final signature
            byte[][] finalSignatures = new byte[count][];
            for (int i = 0; i < count; i++)
            {
                var rawSignatures = new Span<byte>(new byte[BLSHerumi.SignatureLength * fractions[i].Length]);
                var weights = new Span<int>(new int[fractions[i].Length]);
                for (int j = 0; j < fractions[i].Length; j++)
                {
                    signatures[fractions[i][j].id].CopyTo(rawSignatures.Slice(BLSHerumi.SignatureLength * j));
                    weights[j] = (int)(fractions[i][j].numerator * (overallLCM / fractions[i][j].denominator));
                    if (!fractions[i][j].sign) weights[j] = - weights[j];
                }
                finalSignatures[i] = new byte[BLSHerumi.SignatureLength];
                using var blsAggregate = new BLSHerumi(new BLSParameters());
                blsAggregate.TryAggregateSignatures(rawSignatures, weights, finalSignatures[i], out var _);
            }

            for (int i = 1; i < count; i++)
            {
                for (int j = 0; j < BLSHerumi.SignatureLength; j++)
                {
                    if (finalSignatures[i][j] != finalSignatures[0][j])
                    {
                        throw new Exception("Final Signature not the same");
                    }
                }
            }
        }

        public static void Main(string[] args)
        {
            AggregateSignature(7, 5);
        }
    }
}
