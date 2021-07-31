using Cortex.Cryptography;
using System;
using System.Collections.Generic;
using System.Linq;

namespace BLSTest
{
    class BLS_Node
    {
        private readonly uint n = 0;
        private readonly uint m = 0;
        private readonly int index = -1;
        private readonly byte[] domain;
        public List<byte[]> sharedPrivateKeys = new List<byte[]>();
        public List<byte[]> sharedPublicKeys = new List<byte[]>();
        public byte[][] collectedSharedPrivateKeys;
        public byte[][] collectedSharedPublicKeys;
        private List<byte[]> blsSecretKeys = new List<byte[]>();
        private List<byte[]> blsPublicKeys = new List<byte[]>();
        private byte[] aggrattedPrivateKey;
        private byte[] aggrattedPublicKey;

        public int Index
        {
            get { return index; }
        }
        public BLS_Node(int index, byte[] domain, uint n, uint m)
        {
            this.index = index;
            this.n = n;
            this.m = m;
            this.domain = domain;
            var keys = GeneratePrivateKeys(n, m);

            foreach (var key in keys)
            {
                blsSecretKeys.Add(key);
            }
            collectedSharedPrivateKeys = new byte[n][];
            collectedSharedPublicKeys = new byte[n][];
        }

        private byte[] GeneratePrivateKeyFromRandom(int bits)
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

        private byte[][] GeneratePrivateKeys(uint n, uint m)
        {
            byte[][] privateKeys = new byte[m][];//serial, data

            int bits = Utility.GetZeroBits(n, m);
            for (int j = 0; j < m; j++)
            {
                privateKeys[j] = GeneratePrivateKeyFromRandom(bits);
            }
            return privateKeys;
        }

        public void CollectSharedKeyPair(int index, byte[] sharedPrivateKey, byte[] sharedPublicKey)
        {
            //if (this.collectedSharedPrivateKeys. != null) return;
            this.collectedSharedPrivateKeys[index] = sharedPrivateKey;
            this.collectedSharedPublicKeys[index] = sharedPublicKey;
        }

        public byte[][] GenerateSharedPrivateKeys(uint[][] commonWeightSet)
        {
            //Calculate shared private keys
            for (int i = 0; i < n; i++)
            {
                Console.WriteLine("\nCalculate shared private keys for node " + i + " :");
                sharedPrivateKeys.Add(AggregatePrivateKey(this.blsSecretKeys.ToArray(), commonWeightSet[i]));
                Console.WriteLine("[" + i + "]: 0x" + BitConverter.ToString(sharedPrivateKeys[i]).Replace("-", ""));
            }
            return sharedPrivateKeys.ToArray();
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

        private byte[] GetAggregatePrivateKey()
        {
            //Calculate aggregated privateKeys which are used to construct signatures
            uint[] weightSet = new uint[n];
            for (int k = 0; k < n; k++)
            {
                weightSet[k] = 1u;
            }
            aggrattedPrivateKey = AggregatePrivateKey(collectedSharedPrivateKeys.ToArray(), weightSet);
            Console.WriteLine("[" + this.index + "]: 0x" + BitConverter.ToString(aggrattedPrivateKey).Replace("-", ""));
            return aggrattedPrivateKey;
        }

        private byte[][] GetPublishedPubicKeys()
        {
            Console.WriteLine("\nCalculate published public keys for node " + this.index + " :");

            for (int i = 0; i < m; i++)
            {
                using var blsPublic = new BLSHerumi(new BLSParameters() { PrivateKey = blsSecretKeys[i] });
                var pub_key = new byte[BLSHerumi.PublicKeyLength];

                _ = blsPublic.TryExportBLSPublicKey(pub_key, out var _);
                blsPublicKeys.Add(pub_key);
                Console.WriteLine("[" + i + "]: 0x" + BitConverter.ToString(blsPublicKeys[i]).Replace("-", ""));
            }
            return blsPublicKeys.ToArray();
        }

        public byte[][] GetSharedPublicKeys(uint[][] commonWeightSet)
        {
            Console.WriteLine("\nCalculate public keys of shared private keys for node " + this.index + " :");
            GetPublishedPubicKeys();
            for (int i = 0; i < n; i++)
            {
                var contractedPublicKeys = new Span<byte>(new byte[BLSHerumi.PublicKeyLength * m]);
                for (int k = 0; k < m; k++)
                {
                    blsPublicKeys.ToArray()[k].CopyTo(contractedPublicKeys.Slice(k * BLSHerumi.PublicKeyLength));
                }
                using var blsAggregateKeys = new BLSHerumi(new BLSParameters());
                sharedPublicKeys.Add(new byte[BLSHerumi.PublicKeyLength]);
                blsAggregateKeys.TryAggregatePublicKeys(contractedPublicKeys, commonWeightSet[i], sharedPublicKeys[i], out var _);
                Console.WriteLine("[" + i + "]: 0x" + BitConverter.ToString(sharedPublicKeys[i]).Replace("-", ""));
            }
            return sharedPublicKeys.ToArray();
        }

        public byte[] GetAggregatedPublicKeyForSignature()
        {
            var contractedPublicKeys = new Span<byte>(new byte[BLSHerumi.PublicKeyLength * n]);
            uint[] weightSet = new uint[n];
            for (int k = 0; k < n; k++)
            {
                this.collectedSharedPublicKeys[k].CopyTo(contractedPublicKeys.Slice(k * BLSHerumi.PublicKeyLength));
                weightSet[k] = 1u;
            }
            using var blsAggregateKeys = new BLSHerumi(new BLSParameters());
            aggrattedPublicKey = new byte[BLSHerumi.PublicKeyLength];
            blsAggregateKeys.TryAggregatePublicKeys(contractedPublicKeys, weightSet, aggrattedPublicKey, out var _);
            Console.WriteLine("[" + this.index + "]: 0x" + BitConverter.ToString(aggrattedPublicKey).Replace("-", ""));
            return aggrattedPublicKey;
        }

        public byte[] GetSignature(byte[] msg)
        {
            using var blsSign = new BLSHerumi(new BLSParameters() { PrivateKey = GetAggregatePrivateKey() });
            var signature = new byte[BLSHerumi.SignatureLength];

            _ = blsSign.TrySignHash(msg, signature.AsSpan(), out var _, this.domain);

            Console.WriteLine("[" + this.index + "]: 0x" + BitConverter.ToString(signature).Replace("-", ""));

            var aggregatePublicKeyParameters = new BLSParameters()
            {
                PublicKey = GetAggregatedPublicKeyForSignature()
            };
            using var blsVerify = new BLSHerumi(aggregatePublicKeyParameters);
            if (!blsVerify.VerifyHash(msg, signature, domain))
            {
                throw new Exception("AggregatePrivateKeys verification failed!");
            }
            return signature;
        }
    }
}
