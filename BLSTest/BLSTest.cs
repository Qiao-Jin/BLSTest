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
        private readonly List<BLS_Node> nodes = new List<BLS_Node>();
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

                nodes.Add(new BLS_Node(i, Domains[3], n, m));
            }
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


        public void KeyDistribute()
        {
            foreach (var node in nodes)
            {
                var pri_keys = node.GenerateSharedPrivateKeys(commonWeightSet);
                var pub_keys = node.GetSharedPublicKeys(commonWeightSet);
                for (int i = 0; i < n; i++)
                {
                    nodes[i].CollectSharedKeyPair(node.Index, pri_keys[i], pub_keys[i]);
                }
            }
            return;
        }

        public void AggretateKeyPair()
        {
            foreach (var node in nodes)
            {
                var pub_key = node.GetAggregatedPublicKeyForSignature();
                Console.WriteLine("PubKey [" + node.Index + "]: 0x" + BitConverter.ToString(pub_key).Replace("-", ""));
            }
        }

        public byte[][] GetSignatures()
        {
            List<byte[]> sigs = new List<byte[]>();
            Console.WriteLine("\n\nSignatures:");
            foreach (var node in nodes)
            {
                var sig = node.GetSignature(MessageHashes[0]);
                Console.WriteLine("Sig [" + node.Index + "]: 0x" + BitConverter.ToString(sig).Replace("-", ""));
                sigs.Add(sig);
            }
            Console.WriteLine("\n");
            return sigs.ToArray();
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

            //var rawPublicKeys = new Span<byte>(new byte[BLSHerumi.PublicKeyLength * n]);
            //uint[] weightSetCheckingSignature = new uint[n];

            //for (int k = 0; k < n; k++)
            //{
            //    publicKeysPublished[k][0].CopyTo(rawPublicKeys.Slice(k * BLSHerumi.PublicKeyLength));
            //    weightSetCheckingSignature[k] = lcm;
            //}
            //using var publicKeyGenerator = new BLSHerumi(new BLSParameters());
            //var publicKeyCheckingSignature = new byte[BLSHerumi.PublicKeyLength];
            //publicKeyGenerator.TryAggregatePublicKeys(rawPublicKeys, weightSetCheckingSignature, publicKeyCheckingSignature, out var _);
            //using var signatureChecker = new BLSHerumi(new BLSParameters()
            //{
            //    PublicKey = publicKeyCheckingSignature
            //});
            //if (!signatureChecker.VerifyHash(MessageHashes[1], finalSignatures[0], Domains[3]))
            //{
            //    throw new Exception("Final Signature verification failed!");
            //}
            Console.WriteLine("Final signature verified.");
        }

        public static void Main()
        {
            var blstest = new BLSTest(7, 3); // number of dishonest node is no more than f, therefore we only need signatures from f+1 CNs

            blstest.KeyDistribute();
            blstest.AggretateKeyPair();
            var sigs = blstest.GetSignatures();
            blstest.GetFinalSignatures(sigs);
        }
    }
}
