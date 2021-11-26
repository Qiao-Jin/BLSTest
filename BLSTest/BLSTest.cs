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

    public class BLS_N3
    {
        private readonly uint n = 0;
        private readonly uint m = 0;
        private readonly uint[][] commonWeightSet;
        private readonly List<BLS_Node> nodes = new List<BLS_Node>();

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

        public BLS_N3(uint n, uint m)
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


        public void KeyDistribution()
        {

            foreach (var node in nodes)
            {
                //Console.WriteLine("Distribute shared key pairs for node " + node.Index + " :");
                var pri_keys = node.GenerateSharedPrivateKeys(commonWeightSet);
                var pub_keys = node.GetSharedPublicKeys(commonWeightSet);
                for (int i = 0; i < n; i++)
                {
                    nodes[i].CollectSharedKeyPair(node.Index, pri_keys[i], pub_keys[i]);
                    nodes[i].CheckKeyPair(MessageHashes[1], pri_keys[i], pub_keys[i]);
                    //Console.WriteLine("- pri [" + i + "]: 0x" + BitConverter.ToString(pri_keys[i]).Replace("-", ""));
                    //Console.WriteLine("* pub [" + i + "]: 0x" + BitConverter.ToString(pub_keys[i]).Replace("-", ""));
                }
            }
            return;
        }

        /// <summary>
        /// Simulate the process of aggreatated public keys for signature distribution in a p2p network
        /// </summary>
        public void PublicKeysforSignatureDistribution()
        {
            foreach (var node in nodes)
            {
                var pub_key = node.GetAggregatedPublicKey();
                for (int i = 0; i < n; i++)
                {
                    nodes[i].CollectPublicKeyFromPeerForSignature(node.Index, pub_key);
                }
            }
        }

        /// <summary>
        /// Simulate the signature synchronization
        /// </summary>
        /// <returns>BLS signatures from each node</returns>
        public byte[][] GetSignatures()
        {
            List<byte[]> sigs = new List<byte[]>();
            //Console.WriteLine("\n\nSignatures of Each Node:");
            foreach (var node in nodes)
            {
                var timestamp = DateTime.Now.ToFileTime();
                var sig = node.GetSignature(MessageHashes[0]);
                 timestamp = DateTime.Now.ToFileTime()- timestamp;
                //Console.WriteLine("[" + node.Index + "]: 0x" + BitConverter.ToString(sig).Replace("-", "") + " Takes: "+timestamp);

                sigs.Add(sig);
            }
            //Console.WriteLine("\n");
            return sigs.ToArray();
        }

        /// <summary>
        /// Calculate the final signature
        /// </summary>
        /// <param name="signatures"> BLS signatures from each node</param>
        /// <returns></returns>
        public void GetFinalSignatures(byte[][] signatures)
        {
            //Get coefficients for all possible combinations of consensus nodes
            List<Fraction[]> fractions = Utility.GetAllFractions(n, m);
            //Console.WriteLine("Coefficients for all possible consensus node combinations calculated: " + fractions.Count);

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

            //for (int i = 0; i < count; i++)
            //{
            {
                int i = 0;
                //var timestamp = DateTime.Now.Ticks / TimeSpan.TicksPerMillisecond;
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
            } 
           
              

                //Console.WriteLine("[" + i + "]: 0x" + BitConverter.ToString(finalSignatures[i]).Replace("-", ""));
                //Console.WriteLine(DateTime.Now.Ticks / TimeSpan.TicksPerMillisecond - timestamp);
            //}
            
            //Console.WriteLine(" Takes: " + timestamp/count);
            //VerifyFinalSignature(count, overallLCM, finalSignatures);
            //return finalSignatures;
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
            //if (!signatureChecker.VerifyHash(MessageHashes[2], finalSignatures[0], Domains[3]))
            //{
            //    throw new Exception("Final Signature verification failed!");
            //}
            //Console.WriteLine("Final signature verified.");
        }


        void Block21(){ }
        void Block22() { }
        void Block23() { }
        void Block24() { }
        void Block25() { }
        void Block26() { }
        void Block27() { }
        void Block28() { }
        void Block29() { }
        void Block30() { }
        void Block31() { }
        void Block32() { }
        void Block33() { }
        void Block34() { }
        void Block35() { }
        void Block36() { }
        void Block37() { }
        void Block38() { }
        void Block39() { }
        void Block40() { }
        void Block41() { }
        void Block42() { }
        public static void Main()
        {
            //    var blstest = new BLS_N3(12, 5); // number of dishonest node is no more than f, therefore we only need signatures from f+1 CNs

            //    blstest.KeyDistribution();

            //    blstest.PublicKeysforSignatureDistribution();

            //    var sigs = blstest.GetSignatures();

            //    //Calculate final signature
            //    Console.WriteLine("\n\n-----------------------------");
            //    Console.WriteLine("Calculate final signature");
            //    Console.WriteLine("-----------------------------\n");

            //    blstest.GetFinalSignatures(sigs);
        }
    }
}

// security base... longer to process
// wake security, but more efficient