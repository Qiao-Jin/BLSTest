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
        //Get coefficients for all possible combinations of consensus nodes
        public static IList<byte[]> Domains => new List<byte[]>
        {
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
            new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 },
            new byte[] { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
            new byte[] { 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
            new byte[] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef },
            new byte[] { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
        };

        public static IList<byte[]> MessageHashes => new List<byte[]>
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
        public void BLSSignaturesDistribution()
        {
            List<byte[]> sigs = new List<byte[]>();
            //Console.WriteLine("\n\nSignatures of Each Node:");
            foreach (var node in nodes)
            {
                var sig = node.GetSignature(MessageHashes[0]);
                //Console.WriteLine("[" + node.Index + "]: 0x" + BitConverter.ToString(sig).Replace("-", "") + " Takes: "+timestamp);
                sigs.Add(sig);

                for (int i = 0; i < n; i++)
                {
                    nodes[i].blsSignaturesFromPeer.Add(sig);
                }
            }
        }

        /// <summary>
        /// Calculate the final signature
        /// </summary>
        /// <param name="signatures"> BLS signatures from each node</param>
        /// <returns></returns>
        public void GetFinalSignatures()=> nodes[0].GetAggregatedSignature();


        public void VerifyFinalSignature()=>nodes[0].VerifAggregatedSignature(MessageHashes[2], Domains[3]);


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