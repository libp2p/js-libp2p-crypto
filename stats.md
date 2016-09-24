# Stats

## Size

|       | non-minified | minified |
|-------|--------------|----------|
|before | `1.7M`       | `949K`   |
|after  | `461K`       | `291K`   |

## Performance

### RSA

#### Before

##### Node `6.6.0`

```
generateKeyPair 1024bits x 3.51 ops/sec ±29.45% (22 runs sampled)
generateKeyPair 2048bits x 0.17 ops/sec ±145.40% (5 runs sampled)
generateKeyPair 4096bits x 0.02 ops/sec ±96.53% (5 runs sampled)
sign and verify x 95.98 ops/sec ±1.51% (71 runs sampled)
```

##### Browser (Chrome `53.0.2785.116`)

```
generateKeyPair 1024bits x 3.56 ops/sec ±27.16% (23 runs sampled)
generateKeyPair 2048bits x 0.49 ops/sec ±69.32% (8 runs sampled)
generateKeyPair 4096bits x 0.03 ops/sec ±77.11% (5 runs sampled)
sign and verify x 109 ops/sec ±2.00% (53 runs sampled)
```

#### After

##### Node `6.6.0`

```
generateKeyPair 1024bits x 36.80 ops/sec ±9.70% (41 runs sampled)n
generateKeyPair 2048bits x 7.36 ops/sec ±18.90% (28 runs sampled)
generateKeyPair 4096bits x 0.82 ops/sec ±54.57% (10 runs sampled)
sign and verify x 611 ops/sec ±4.91% (62 runs sampled)
```

##### Browser (Chrome `53.0.2785.116`)

```
generateKeyPair 1024bits x 5.89 ops/sec ±18.94% (19 runs sampled)
generateKeyPair 2048bits x 1.32 ops/sec ±36.84% (10 runs sampled)
generateKeyPair 4096bits x 0.20 ops/sec ±62.49% (5 runs sampled)
sign and verify x 608 ops/sec ±6.75% (56 runs sampled)
```

### Key Stretcher


#### Before

##### Node `6.6.0`

```
keyStretcher AES-128 SHA1 x 3,863 ops/sec ±3.80% (70 runs sampled)
keyStretcher AES-128 SHA256 x 3,862 ops/sec ±5.33% (64 runs sampled)
keyStretcher AES-128 SHA512 x 3,369 ops/sec ±1.73% (73 runs sampled)
keyStretcher AES-256 SHA1 x 3,008 ops/sec ±4.81% (67 runs sampled)
keyStretcher AES-256 SHA256 x 2,900 ops/sec ±7.01% (64 runs sampled)
keyStretcher AES-256 SHA512 x 2,553 ops/sec ±4.45% (73 runs sampled)
keyStretcher Blowfish SHA1 x 28,045 ops/sec ±7.32% (61 runs sampled)
keyStretcher Blowfish SHA256 x 18,860 ops/sec ±5.36% (67 runs sampled)
keyStretcher Blowfish SHA512 x 12,142 ops/sec ±12.44% (72 runs sampled)
```

##### Browser (Chrome `53.0.2785.116`)

```
keyStretcher AES-128 SHA1 x 4,168 ops/sec ±4.08% (49 runs sampled)
keyStretcher AES-128 SHA256 x 4,239 ops/sec ±6.36% (48 runs sampled)
keyStretcher AES-128 SHA512 x 3,600 ops/sec ±5.15% (51 runs sampled)
keyStretcher AES-256 SHA1 x 3,009 ops/sec ±6.82% (48 runs sampled)
keyStretcher AES-256 SHA256 x 3,086 ops/sec ±9.56% (19 runs sampled)
keyStretcher AES-256 SHA512 x 2,470 ops/sec ±2.22% (54 runs sampled)
keyStretcher Blowfish SHA1 x 7,143 ops/sec ±15.17% (9 runs sampled)
keyStretcher Blowfish SHA256 x 17,846 ops/sec ±4.74% (46 runs sampled)
keyStretcher Blowfish SHA512 x 7,726 ops/sec ±1.81% (50 runs sampled)
```

#### After

##### Node `6.6.0`

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

##### Browser (Chrome `53.0.2785.116`)

```
keyStretcher AES-128 SHA1 x 479 ops/sec ±2.12% (54 runs sampled)
keyStretcher AES-128 SHA256 x 668 ops/sec ±2.02% (53 runs sampled)
keyStretcher AES-128 SHA512 x 1,112 ops/sec ±1.61% (54 runs sampled)
keyStretcher AES-256 SHA1 x 460 ops/sec ±1.37% (54 runs sampled)
keyStretcher AES-256 SHA256 x 596 ops/sec ±1.56% (54 runs sampled)
keyStretcher AES-256 SHA512 x 808 ops/sec ±3.27% (52 runs sampled)
keyStretcher Blowfish SHA1 x 3,015 ops/sec ±3.51% (52 runs sampled)
keyStretcher Blowfish SHA256 x 2,755 ops/sec ±3.82% (53 runs sampled)
keyStretcher Blowfish SHA512 x 2,955 ops/sec ±5.35% (51 runs sampled)
```

### Ephemeral Keys

#### Before

##### Node `6.6.0`

```
ephemeral key with secrect P-256 x 89.93 ops/sec ±39.45% (72 runs sampled)
ephemeral key with secrect P-384 x 110 ops/sec ±1.28% (71 runs sampled)
ephemeral key with secrect P-521 x 112 ops/sec ±1.70% (72 runs sampled)
```

##### Browser (Chrome `53.0.2785.116`)

```
ephemeral key with secrect P-256 x 6.27 ops/sec ±15.89% (35 runs sampled)
ephemeral key with secrect P-384 x 6.84 ops/sec ±1.21% (35 runs sampled)
ephemeral key with secrect P-521 x 6.60 ops/sec ±1.84% (34 runs sampled)
```

#### After

##### Node `6.6.0`

```
ephemeral key with secrect P-256 x 555 ops/sec ±1.61% (75 runs sampled)
ephemeral key with secrect P-384 x 547 ops/sec ±4.40% (68 runs sampled)
ephemeral key with secrect P-521 x 583 ops/sec ±4.84% (72 runs sampled)
```

##### Browser (Chrome `53.0.2785.116`)

```
ephemeral key with secrect P-256 x 796 ops/sec ±2.36% (53 runs sampled)
ephemeral key with secrect P-384 x 788 ops/sec ±2.66% (53 runs sampled)
ephemeral key with secrect P-521 x 808 ops/sec ±1.83% (54 runs sampled)
```