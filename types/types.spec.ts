import crypto, {
  HashType,
  CipherType,
  randomBytes,
  CurveType
} from "libp2p-crypto";

crypto.keys.generateKeyPair("RSA", 512).then(key => {
  key = key;
  const key2 = crypto.keys.unmarshalPublicKey(
    crypto.keys.marshalPublicKey(key.public)
  );

  // true
  key2.equals(key.public);

  crypto.keys
    .unmarshalPrivateKey(crypto.keys.marshalPrivateKey(key))
    .then(key2 => {
      // true
      key2.equals(key);
      // true
      key2.public.equals(key.public);
    });

  const seed = randomBytes(32);

  crypto.keys.generateKeyPairFromSeed("RSA", seed, 512).then(key2 => {
    console.log(key2);
  });

  crypto.keys
    .unmarshalPrivateKey(crypto.keys.marshalPrivateKey(key))
    .then(privKey => {
      privKey.hash().then(digest => {
        console.log(digest);
      });
    });

  const pubKey = crypto.keys.unmarshalPublicKey(
    crypto.keys.marshalPublicKey(key.public)
  );
  pubKey.hash().then(digest => {
    console.log(digest);
  });
});

const p1 = crypto.pbkdf2(
  "password",
  "at least 16 character salt",
  500,
  512 / 8,
  "sha1"
);

const buf1 = randomBytes(10);

const hashes: HashType[] = ["SHA1", "SHA256", "SHA512"];

(async () => {
  for (const hash of hashes) {
    const hmac = await crypto.hmac.create(hash, Buffer.from("secret"));
    const sig = await hmac.digest(Buffer.from("hello world"));
    console.log(sig);
  }
})();

const ciphers: CipherType[] = ["AES-128", "AES-256", "Blowfish"];

(async () => {
  const res = await crypto.keys.generateEphemeralKeyPair("P-256");
  const secret = await res.genSharedKey(res.key);

  for (const cipher of ciphers) {
    for (const hash of hashes) {
      const keys = await crypto.keys.keyStretcher(cipher, hash, secret);
      console.log(keys);
    }
  }
})();

const secp256k1 = crypto.keys.supportedKeys.secp256k1;

(async () => {
  const key = await secp256k1.generateKeyPair();
  const digest = await key.hash();
  const keyMarshal = crypto.keys.marshalPrivateKey(key);
  const key2 = await secp256k1.unmarshalSecp256k1PrivateKey(keyMarshal);
  const keyMarshal2 = crypto.keys.marshalPrivateKey(key2);

  const pk = key.public;
  const pkMarshal = crypto.keys.marshalPublicKey(pk);
  const pk2 = secp256k1.unmarshalSecp256k1PublicKey(pkMarshal);
  const pkMarshal2 = crypto.keys.marshalPublicKey(pk2);
})();

const rsa = crypto.keys.supportedKeys.rsa;

(async () => {
  const key = await rsa.generateKeyPair(512);
  const digest = await key.hash();
  const pk = key.public;
  const pkMarshal = crypto.keys.marshalPublicKey(pk);
  const pk2 = rsa.unmarshalRsaPublicKey(pkMarshal);
  const pkMarshal2 = crypto.keys.marshalPublicKey(pk2);
})();

const curves: CurveType[] = ["P-256", "P-384"]; // 'P-521' fails in tests :( no clue why
const lengths: Record<CurveType, number> = {
  "P-256": 65,
  "P-384": 97,
  "P-521": 133
};
const secretLengths: Record<CurveType, number> = {
  "P-256": 32,
  "P-384": 48,
  "P-521": 66
};

curves.forEach(curve => {
  Promise.all([
    crypto.keys.generateEphemeralKeyPair(curve),
    crypto.keys.generateEphemeralKeyPair(curve)
  ]).then(keys => {
    keys[0].genSharedKey(keys[1].key).then(console.log);
  });
});

const curve = curves[0];

Promise.all([
  crypto.keys.generateEphemeralKeyPair(curve),
  crypto.keys.generateEphemeralKeyPair(curve)
]).then(keys => {
  const alice = keys[0];
  const bob = keys[1];

  Promise.all([
    alice.genSharedKey(bob.key),
    bob.genSharedKey(alice.key, false)
  ]).then(console.log);
});

const bytes: { [key: number]: CipherType } = {
  16: "AES-128",
  32: "AES-256"
};

Object.keys(bytes).forEach(byte => {
  const key = Buffer.alloc(parseInt(byte, 10));
  key.fill(5);

  const iv = Buffer.alloc(16);
  iv.fill(1);

  crypto.aes.create(key, iv).then(cipher => {
    const data = Buffer.alloc(100);
    data.fill(Math.ceil(Math.random() * 100));

    cipher.encrypt(data).then(encrypted => {
      cipher.decrypt(encrypted).then(decrypted => {
        console.log(decrypted);
      });
    });
  });
});

const ed25519 = crypto.keys.supportedKeys.ed25519;

(async () => {
  const key = await crypto.keys.generateKeyPair("Ed25519", 512);

  let digest = await key.hash();

  const seed = crypto.randomBytes(32);
  const seededkey = await crypto.keys.generateKeyPairFromSeed(
    "Ed25519",
    seed,
    512
  );
  digest = await seededkey.hash();

  let seededkey1 = await crypto.keys.generateKeyPairFromSeed(
    "Ed25519",
    seed,
    512
  );
  let seededkey2 = await crypto.keys.generateKeyPairFromSeed(
    "Ed25519",
    seed,
    512
  );

  const seed1 = crypto.randomBytes(32);
  seededkey1 = await crypto.keys.generateKeyPairFromSeed("Ed25519", seed1, 512);
  const seed2 = crypto.randomBytes(32);
  seededkey2 = await crypto.keys.generateKeyPairFromSeed("Ed25519", seed2, 512);

  const text = crypto.randomBytes(512);
  let sig = await key.sign(text);
  const res = await key.public.verify(text, sig);

  const keyMarshal = key.marshal();
  const key2 = await ed25519.unmarshalEd25519PrivateKey(keyMarshal);
  const keyMarshal2 = key2.marshal();

  const pk = key.public;
  const pkMarshal = pk.marshal();
  const pk2 = ed25519.unmarshalEd25519PublicKey(pkMarshal);
  const pkMarshal2 = pk2.marshal();

  const id = await key.id();

  key.equals(key);
  key.public.equals(key.public);

  const key3 = await crypto.keys.generateKeyPair("Ed25519", 512);
  key.equals(key3); // false
  key3.equals(key); // false
  key.public.equals(key3.public); // false
  key3.public.equals(key.public); // false

  let data = Buffer.from("hello world");
  sig = await key.sign(data);
  let valid = await key.public.verify(data, sig);

  data = Buffer.from("hello world");
  sig = await key.sign(data);
  valid = await key.public.verify(Buffer.from("hello"), sig);
})();

(async () => {
  const key = await rsa.generateKeyPair(512);
  const digest = await key.hash();

  const text = key.genSecret();
  const sig = await key.sign(text);
  const res = await key.public.verify(text, sig);

  const keyMarshal = key.marshal();
  const key2 = await rsa.unmarshalRsaPrivateKey(keyMarshal);
  const keyMarshal2 = key2.marshal();

  const pk = key.public;
  const pkMarshal = pk.marshal();
  const pk2 = rsa.unmarshalRsaPublicKey(pkMarshal);
  const pkMarshal2 = pk2.marshal();

  const id = await key.id();

  key.equals(key); // true

  key.public.equals(key.public);
})();

(async () => {
  const key = await rsa.generateKeyPair(512);
  const key2 = await crypto.keys.generateKeyPair("RSA", 512);
  key.equals(key2); // false
  key2.equals(key); // false

  const data = Buffer.from("hello world");
  const sig = await key.sign(data);
  const valid = await key.public.verify(data, sig);
  const data2 = Buffer.from("hello world");
  const enc = key.public.encrypt(data2);
  const dec = key.decrypt(enc);
})();

(async () => {
  const key = await rsa.generateKeyPair(512);
  let pem = await key.export("my secret", "pkcs-8");

  let clone = await crypto.keys.import(pem, "my secret");

  pem = await key.export("another secret");

  clone = await crypto.keys.import(pem, "another secret");

  pem = `-----BEGIN PRIVATE KEY-----
MIIG/wIBADANBgkqhkiG9w0BAQEFAASCBukwggblAgEAAoIBgQDp0Whyqa8KmdvK
...
4pMwXeXP+LO8NIfRXV8mgrm86g==
-----END PRIVATE KEY-----
`;
  const newKey = await crypto.keys.import(pem, "");

  const id = await newKey.id();

  pem = `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIICzzBJBgkqhkiG9w0BBQ0wPDAbBgkqhkiG9w0BBQwwDgQIP5QK2RfqUl4CAggA
...
nPyn
-----END ENCRYPTED PRIVATE KEY-----
`;
  const anotherKey = await crypto.keys.import(pem, "mypassword");
})();
