# Stats

## Size

|       | non-minified | minified |
|-------|--------------|----------|
|before | `1.55M`      | `789K`   |
|after  | `461K`       | `291K`   |

## Performance

### RSA

#### Before Node

```
```

#### After Node

```
generateKeyPair 1024bits x 36.80 ops/sec ±9.70% (41 runs sampled)
generateKeyPair 2048bits x 7.36 ops/sec ±18.90% (28 runs sampled)
generateKeyPair 4096bits x 0.82 ops/sec ±54.57% (10 runs sampled)
sign and verify x 611 ops/sec ±4.91% (62 runs sampled)
```

### Key Stretcher


#### Before Node

```
```

#### After Node

```
keyStretcher AES-128 SHA1 x 5,538 ops/sec ±5.60% (63 runs sampled)
keyStretcher AES-128 SHA256 x 8,035 ops/sec ±5.40% (59 runs sampled)
keyStretcher AES-128 SHA512 x 12,320 ops/sec ±5.10% (61 runs sampled)
keyStretcher AES-256 SHA1 x 5,231 ops/sec ±5.49% (66 runs sampled)
keyStretcher AES-256 SHA256 x 6,895 ops/sec ±5.65% (68 runs sampled)
keyStretcher AES-256 SHA512 x 7,836 ops/sec ±3.95% (52 runs sampled)
keyStretcher Blowfish SHA1 x 27,774 ops/sec ±6.83% (61 runs sampled)
keyStretcher Blowfish SHA256 x 27,960 ops/sec ±3.06% (42 runs sampled)
keyStretcher Blowfish SHA512 x 27,891 ops/sec ±2.81% (53 runs sampled)
```

### Ephemeral Keys

#### Before Node

```
ephemeral key with secrect P-256 x 54.85 ops/sec ±43.37% (76 runs sampled)
ephemeral key with secrect P-384 x 67.92 ops/sec ±2.23% (73 runs sampled)
ephemeral key with secrect P-521 x 65.91 ops/sec ±6.93% (74 runs sampled)
```

#### After Node

```
ephemeral key with secrect P-256 x 555 ops/sec ±1.61% (75 runs sampled)
ephemeral key with secrect P-384 x 547 ops/sec ±4.40% (68 runs sampled)
ephemeral key with secrect P-521 x 583 ops/sec ±4.84% (72 runs sampled)
```
