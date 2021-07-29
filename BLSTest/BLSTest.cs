using Cortex.Cryptography;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;

namespace BLSTest
{
    public struct Fraction
    {
        //Coefficients
        public uint numerator;
        public uint denominator;
        public bool sign;
        //ID
        public uint id;
    }

    public class BLSTest
    {
        private readonly uint n = 0;
        private readonly uint m = 0;
        private readonly uint[][] commonWeightSet;
        private byte[][][] publicKeysPublished;//node, serial, data

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

        private byte[] GeneratePrivateKey(int bits)
        {
            int bytes = bits / 8;
            int ints = bytes / sizeof(int);
            int start = ints * sizeof(int);
            int remainder = bits % 8;
            if (bytes >= BLSHerumi.PrivateKeyLength - 1)
            {
                throw new ArithmeticException("Cannot generate private key!");
            }

            Random rand = new Random();
            byte[] privateKey = new byte[ints * sizeof(int)];//In case that aggregated private keys surpass limit
            for (int i = 0; i < BLSHerumi.PrivateKeyLength / sizeof(int) - ints; i++)
            {
                privateKey = privateKey.Concat(BitConverter.GetBytes(rand.Next())).ToArray();
            }
            for (int i = start; i < bytes; i++)
            {
                privateKey[i] = 0;
            }
            privateKey[bytes] >>= remainder;
            return privateKey;
        }

        private byte[] AggregatePrivateKey(byte[][] privateKeys, uint[] weight)
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
                        if (p < 0) throw new ArithmeticException("Private key exceeds limit!");
                        flap += result[p];
                        result[p--] = (byte)flap;
                        flap /= 256;
                    }
                }
            }
            return result;
        }

        public BLSTest(uint n, uint m)
        {
            //Filter
            if (m == 0 || n == 0 || m > n)
            {
                throw new ArithmeticException("Input not valid!");
            }
            this.n = n;
            this.m = m;

            commonWeightSet = new uint[n][];
            for (int i = 0; i < this.n; i++)
            {
                commonWeightSet[i] = new uint[m];
                commonWeightSet[i][0] = 1;
                for (int j = 1; j < m; j++)
                {
                    commonWeightSet[i][j] = (uint)(commonWeightSet[i][j - 1] * (i + 1));
                }
            }
        }

        public byte[][][] GetPrivateKeys()
        {
            byte[][][] privateKeys = new byte[n][][];//node, serial, data

            int bits = Utility.GetZeroBits(n, m);

            for (int i = 0; i < this.n; i++)
            {
                privateKeys[i] = new byte[m][];
                for (int j = 0; j < m; j++)
                {
                    privateKeys[i][j] = GeneratePrivateKey(bits);
                }
            }

            return privateKeys;
        }

        public byte[][][] GetPubicKeysPublished(byte[][][] privateKeys)
        {
            //Calculate published public keys
            Console.WriteLine("\n\n-----------------------------");
            Console.WriteLine("Calculate published public keys");
            Console.WriteLine("-----------------------------\n");
            publicKeysPublished = new byte[n][][];//node, serial, data
            for (int i = 0; i < n; i++)
            {
                Console.WriteLine("\nCalculate published public keys for node " + i + " :");
                publicKeysPublished[i] = new byte[m][];

                for (int j = 0; j < m; j++)
                {
                    using var blsPublic = new BLSHerumi(new BLSParameters() { PrivateKey = privateKeys[i][j] });
                    publicKeysPublished[i][j] = new byte[BLSHerumi.PublicKeyLength];
                    _ = blsPublic.TryExportBLSPublicKey(publicKeysPublished[i][j], out var _);
                    Console.WriteLine("[" + j + "]: 0x" + BitConverter.ToString(publicKeysPublished[i][j]).Replace("-", ""));
                }
            }
            return publicKeysPublished;
            //Console.WriteLine("Published public keys calculated...");
        }

        public byte[][][] GetSharedPrivateKeys(byte[][][] privateKeys)
        {
            //Calculate shared private keys
            Console.WriteLine("\n\n-----------------------------");
            Console.WriteLine("Calculate shared private keys");
            Console.WriteLine("-----------------------------\n");
            byte[][][] sharedPrivateKeys = new byte[n][][];//to, from, data
            for (int i = 0; i < n; i++)
            {
                Console.WriteLine("\nCalculate shared private keys for node " + i + " :");
                sharedPrivateKeys[i] = new byte[n][];
                for (int j = 0; j < n; j++)
                {
                    byte[][] privateKeySet = new byte[m][];
                    for (int k = 0; k < m; k++)
                    {
                        privateKeySet[k] = privateKeys[j][k];
                    }
                    sharedPrivateKeys[i][j] = AggregatePrivateKey(privateKeySet, commonWeightSet[i]);
                    Console.WriteLine("[" + j + "]: 0x" + BitConverter.ToString(sharedPrivateKeys[i][j]).Replace("-", ""));
                }
            }
            return sharedPrivateKeys;
            //Console.WriteLine("Shared private keys calculated...");
        }

        public byte[][][] GetAggregatedPublicKeys(byte[][][] publicKeysPublished)
        {
            //Calculate public keys of shared private keys, from published public keys
            Console.WriteLine("\n\n-----------------------------");
            Console.WriteLine("Calculate public keys of shared private keys");
            Console.WriteLine("-----------------------------\n");
            byte[][][] publicKeysAggregated = new byte[n][][];//to, from, data
            for (int i = 0; i < this.n; i++)
            {
                Console.WriteLine("\nCalculate public keys of shared private keys for node " + i + " :");
                publicKeysAggregated[i] = new byte[n][];
                for (int j = 0; j < n; j++)
                {
                    var contractedPublicKeys = new Span<byte>(new byte[BLSHerumi.PublicKeyLength * m]);
                    for (int k = 0; k < m; k++)
                    {
                        publicKeysPublished[j][k].CopyTo(contractedPublicKeys.Slice(k * BLSHerumi.PublicKeyLength));
                    }
                    using var blsAggregateKeys = new BLSHerumi(new BLSParameters());
                    publicKeysAggregated[i][j] = new byte[BLSHerumi.PublicKeyLength];
                    blsAggregateKeys.TryAggregatePublicKeys(contractedPublicKeys, commonWeightSet[i], publicKeysAggregated[i][j], out var _);
                    Console.WriteLine("[" + j + "]: 0x" + BitConverter.ToString(publicKeysAggregated[i][j]).Replace("-", ""));
                }
            }
            return publicKeysAggregated;
            //Console.WriteLine("Aggregated public keys according to shared private keys...");
        }

        public void Sign(byte[][][] sharedPrivateKeys, byte[][][] publicKeysAggregated)
        {
            //Sign & verify sharedPrivateKeys
            Console.WriteLine("\n\n-----------------------------");
            Console.WriteLine("Sign & verify sharedPrivateKeys");
            Console.WriteLine("-----------------------------\n");

            for (int i = 0; i < n; i++)
            {
                for (int j = 0; j < n; j++)
                {
                    using var blsSign = new BLSHerumi(new BLSParameters() { PrivateKey = sharedPrivateKeys[i][j] });
                    var signature = new byte[BLSHerumi.SignatureLength];
                    _ = blsSign.TrySignHash(MessageHashes[1], signature.AsSpan(), out var _, Domains[3]);

                    var aggregatePublicKeyParameters = new BLSParameters()
                    {
                        PublicKey = publicKeysAggregated[i][j]
                    };
                    using var blsVerify = new BLSHerumi(aggregatePublicKeyParameters);
                    if (!blsVerify.VerifyHash(MessageHashes[1], signature, Domains[3]))
                    {
                        throw new Exception("SharedPrivateKeys verification failed!");
                    }
                }
            }
            Console.WriteLine("Shared private keys verified...");
        }

        public byte[][] GetAggregatePrivateKeys(byte[][][] sharedPrivateKeys)
        {
            //Calculate aggregated privateKeys which are used to construct signatures
            Console.WriteLine("\n\n-----------------------------");
            Console.WriteLine("Calculate aggregated privateKeys");
            Console.WriteLine("-----------------------------\n");
            byte[][] aggregatePrivateKeys = new byte[n][];
            for (int i = 0; i < n; i++)
            {
                byte[][] privateKeySet = new byte[n][];
                uint[] weightSet = new uint[n];
                for (int k = 0; k < n; k++)
                {
                    privateKeySet[k] = sharedPrivateKeys[i][k];
                    weightSet[k] = 1u;
                }
                aggregatePrivateKeys[i] = AggregatePrivateKey(privateKeySet, weightSet);
                Console.WriteLine("[" + i + "]: 0x" + BitConverter.ToString(aggregatePrivateKeys[i]).Replace("-", ""));
            }
            return aggregatePrivateKeys;
            //Console.WriteLine("Private keys used for signature aggregated...");
        }

        public byte[][] GetAggregatedPublicKeysForSignature(byte[][][] publicKeysAggregated)
        {
            //Aggregate public keys which are used to verify signatures
            Console.WriteLine("\n\n-----------------------------");
            Console.WriteLine("Aggregate public keys");
            Console.WriteLine("-----------------------------\n");
            byte[][] publicKeysAggregatedForSignature = new byte[n][];
            for (int i = 0; i < n; i++)
            {
                var contractedPublicKeys = new Span<byte>(new byte[BLSHerumi.PublicKeyLength * n]);
                uint[] weightSet = new uint[n];
                for (int k = 0; k < n; k++)
                {
                    publicKeysAggregated[i][k].CopyTo(contractedPublicKeys.Slice(k * BLSHerumi.PublicKeyLength));
                    weightSet[k] = 1u;
                }
                using var blsAggregateKeys = new BLSHerumi(new BLSParameters());
                publicKeysAggregatedForSignature[i] = new byte[BLSHerumi.PublicKeyLength];
                blsAggregateKeys.TryAggregatePublicKeys(contractedPublicKeys, weightSet, publicKeysAggregatedForSignature[i], out var _);
                Console.WriteLine("[" + i + "]: 0x" + BitConverter.ToString(publicKeysAggregatedForSignature[i]).Replace("-", ""));
            }
            return publicKeysAggregatedForSignature;
            //Console.WriteLine("Public keys used to verify signatures aggregated...");
        }

        public byte[][] GetSignatures(byte[][] aggregatePrivateKeys, byte[][] publicKeysAggregatedForSignature)
        {
            //Sign & verify signatures
            Console.WriteLine("\n\n-----------------------------");
            Console.WriteLine("Sign & verify signatures");
            Console.WriteLine("-----------------------------\n");
            byte[][] signatures = new byte[n][];
            for (int i = 0; i < n; i++)
            {
                using var blsSign = new BLSHerumi(new BLSParameters() { PrivateKey = aggregatePrivateKeys[i] });
                signatures[i] = new byte[BLSHerumi.SignatureLength];
                _ = blsSign.TrySignHash(MessageHashes[1], signatures[i].AsSpan(), out var _, Domains[3]);
                Console.WriteLine("[" + i + "]: 0x" + BitConverter.ToString(signatures[i]).Replace("-", ""));
                var aggregatePublicKeyParameters = new BLSParameters()
                {
                    PublicKey = publicKeysAggregatedForSignature[i]
                };
                using var blsVerify = new BLSHerumi(aggregatePublicKeyParameters);
                if (!blsVerify.VerifyHash(MessageHashes[1], signatures[i], Domains[3]))
                {
                    throw new Exception("AggregatePrivateKeys verification failed!");
                }
            }
            return signatures;
        }

        public byte[][] GetFinalSignatures(byte[][] signatures)
        {
            //Calculate final signature
            Console.WriteLine("\n\n-----------------------------");
            Console.WriteLine("Calculate final signature");
            Console.WriteLine("-----------------------------\n");

            //Get coefficients for all possible combinations of consensus nodes
            List<Fraction[]> fractions = Utility.GetAllFractions(n, m);
            Console.WriteLine("Coefficients for all possible consensus node combinations calculated: " + fractions.Count);

            //Get LCM
            int count = fractions.Count;
            uint[] LCMs = new uint[count];
            for (int i = 0; i < count; i++)
            {
                uint[] denominators = new uint[fractions[i].Length];
                for (int j = 0; j < fractions[i].Length; j++)
                {
                    denominators[j] = fractions[i][j].denominator;
                }
                LCMs[i] = Utility.GetLCM(denominators);
            }

            uint overallLCM = Utility.GetLCM(LCMs);

            byte[][] finalSignatures = new byte[count][];
            for (int i = 0; i < count; i++)
            {
                var rawSignatures = new Span<byte>(new byte[BLSHerumi.SignatureLength * fractions[i].Length]);
                var weights = new Span<int>(new int[fractions[i].Length]);
                for (int j = 0; j < fractions[i].Length; j++)
                {
                    signatures[fractions[i][j].id].CopyTo(rawSignatures.Slice(BLSHerumi.SignatureLength * j));
                    weights[j] = (int)(fractions[i][j].numerator * (overallLCM / fractions[i][j].denominator));
                    if (!fractions[i][j].sign) weights[j] = -weights[j];
                }
                finalSignatures[i] = new byte[BLSHerumi.SignatureLength];
                using var blsAggregate = new BLSHerumi(new BLSParameters());
                blsAggregate.TryAggregateSignatures(rawSignatures, weights, finalSignatures[i], out var _);

                Console.WriteLine("[" + i + "]: 0x" + BitConverter.ToString(finalSignatures[i]).Replace("-", ""));
            }
            VerifyFinalSignature(count, overallLCM, finalSignatures);
            return finalSignatures;
        }

        public void VerifyFinalSignature(int count, uint lcm, byte[][] finalSignatures)
        {
            //Check final signature
            for (int i = 1; i < count; i++)
            {
                for (int j = 0; j < BLSHerumi.SignatureLength; j++)
                {
                    if (finalSignatures[i][j] != finalSignatures[0][j])
                    {
                        throw new Exception("Final Signature not the same!");
                    }
                }
            }

            var rawPublicKeys = new Span<byte>(new byte[BLSHerumi.PublicKeyLength * n]);
            uint[] weightSetCheckingSignature = new uint[n];

            for (int k = 0; k < n; k++)
            {
                publicKeysPublished[k][0].CopyTo(rawPublicKeys.Slice(k * BLSHerumi.PublicKeyLength));
                weightSetCheckingSignature[k] = lcm;
            }
            using var publicKeyGenerator = new BLSHerumi(new BLSParameters());
            var publicKeyCheckingSignature = new byte[BLSHerumi.PublicKeyLength];
            publicKeyGenerator.TryAggregatePublicKeys(rawPublicKeys, weightSetCheckingSignature, publicKeyCheckingSignature, out var _);
            using var signatureChecker = new BLSHerumi(new BLSParameters()
            {
                PublicKey = publicKeyCheckingSignature
            });
            if (!signatureChecker.VerifyHash(MessageHashes[1], finalSignatures[0], Domains[3]))
            {
                throw new Exception("Final Signature verification failed!");
            }
            Console.WriteLine("Final signature verified.");
        }

        public static void Main()
        {
            var blstest = new BLSTest(7, 3); // number of dishonest node is no more than f, therefore we only need signatures from f+1 CNs
            var privateKeys = blstest.GetPrivateKeys();
            var sharedPrivateKeys = blstest.GetSharedPrivateKeys(privateKeys);
            var aggregatePrivateKeys = blstest.GetAggregatePrivateKeys(sharedPrivateKeys);

            var publicKeysPublished = blstest.GetPubicKeysPublished(privateKeys);
            var aggregatedPublicKeys = blstest.GetAggregatedPublicKeys(publicKeysPublished);

            var aggregatedPublicKeysForSignature = blstest.GetAggregatedPublicKeysForSignature(aggregatedPublicKeys);

            var signatures = blstest.GetSignatures(aggregatePrivateKeys, aggregatedPublicKeysForSignature);

            var finalSignatures = blstest.GetFinalSignatures(signatures);
        }
    }
}
