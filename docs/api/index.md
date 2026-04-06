**threshold-elgamal**

***

# threshold-elgamal

## Classes

### IndexOutOfRangeError

#### Extends

- `ThresholdElgamalError`

#### Constructors

##### Constructor

> **new IndexOutOfRangeError**(`message`): [`IndexOutOfRangeError`](#indexoutofrangeerror)

###### Parameters

###### message

`string`

###### Returns

[`IndexOutOfRangeError`](#indexoutofrangeerror)

###### Inherited from

`ThresholdElgamalError.constructor`

***

### InvalidCiphertextError

#### Extends

- `ThresholdElgamalError`

#### Constructors

##### Constructor

> **new InvalidCiphertextError**(`message`): [`InvalidCiphertextError`](#invalidciphertexterror)

###### Parameters

###### message

`string`

###### Returns

[`InvalidCiphertextError`](#invalidciphertexterror)

###### Inherited from

`ThresholdElgamalError.constructor`

***

### InvalidGroupElementError

#### Extends

- `ThresholdElgamalError`

#### Constructors

##### Constructor

> **new InvalidGroupElementError**(`message`): [`InvalidGroupElementError`](#invalidgroupelementerror)

###### Parameters

###### message

`string`

###### Returns

[`InvalidGroupElementError`](#invalidgroupelementerror)

###### Inherited from

`ThresholdElgamalError.constructor`

***

### InvalidPayloadError

#### Extends

- `ThresholdElgamalError`

#### Constructors

##### Constructor

> **new InvalidPayloadError**(`message`): [`InvalidPayloadError`](#invalidpayloaderror)

###### Parameters

###### message

`string`

###### Returns

[`InvalidPayloadError`](#invalidpayloaderror)

###### Inherited from

`ThresholdElgamalError.constructor`

***

### InvalidProofError

#### Extends

- `ThresholdElgamalError`

#### Constructors

##### Constructor

> **new InvalidProofError**(`message`): [`InvalidProofError`](#invalidprooferror)

###### Parameters

###### message

`string`

###### Returns

[`InvalidProofError`](#invalidprooferror)

###### Inherited from

`ThresholdElgamalError.constructor`

***

### InvalidScalarError

#### Extends

- `ThresholdElgamalError`

#### Constructors

##### Constructor

> **new InvalidScalarError**(`message`): [`InvalidScalarError`](#invalidscalarerror)

###### Parameters

###### message

`string`

###### Returns

[`InvalidScalarError`](#invalidscalarerror)

###### Inherited from

`ThresholdElgamalError.constructor`

***

### InvalidShareError

#### Extends

- `ThresholdElgamalError`

#### Constructors

##### Constructor

> **new InvalidShareError**(`message`): [`InvalidShareError`](#invalidshareerror)

###### Parameters

###### message

`string`

###### Returns

[`InvalidShareError`](#invalidshareerror)

###### Inherited from

`ThresholdElgamalError.constructor`

***

### PhaseViolationError

#### Extends

- `ThresholdElgamalError`

#### Constructors

##### Constructor

> **new PhaseViolationError**(`message`): [`PhaseViolationError`](#phaseviolationerror)

###### Parameters

###### message

`string`

###### Returns

[`PhaseViolationError`](#phaseviolationerror)

###### Inherited from

`ThresholdElgamalError.constructor`

***

### PlaintextDomainError

#### Extends

- `ThresholdElgamalError`

#### Constructors

##### Constructor

> **new PlaintextDomainError**(`message`): [`PlaintextDomainError`](#plaintextdomainerror)

###### Parameters

###### message

`string`

###### Returns

[`PlaintextDomainError`](#plaintextdomainerror)

###### Inherited from

`ThresholdElgamalError.constructor`

***

### ThresholdViolationError

#### Extends

- `ThresholdElgamalError`

#### Constructors

##### Constructor

> **new ThresholdViolationError**(`message`): [`ThresholdViolationError`](#thresholdviolationerror)

###### Parameters

###### message

`string`

###### Returns

[`ThresholdViolationError`](#thresholdviolationerror)

###### Inherited from

`ThresholdElgamalError.constructor`

***

### TranscriptMismatchError

#### Extends

- `ThresholdElgamalError`

#### Constructors

##### Constructor

> **new TranscriptMismatchError**(`message`): [`TranscriptMismatchError`](#transcriptmismatcherror)

###### Parameters

###### message

`string`

###### Returns

[`TranscriptMismatchError`](#transcriptmismatcherror)

###### Inherited from

`ThresholdElgamalError.constructor`

***

### UnsupportedSuiteError

#### Extends

- `ThresholdElgamalError`

#### Constructors

##### Constructor

> **new UnsupportedSuiteError**(`message`): [`UnsupportedSuiteError`](#unsupportedsuiteerror)

###### Parameters

###### message

`string`

###### Returns

[`UnsupportedSuiteError`](#unsupportedsuiteerror)

###### Inherited from

`ThresholdElgamalError.constructor`

## Type aliases

### Brand

> **Brand**\<`T`, `TBrand`\> = `T` & `object`

#### Type declaration

##### \_\_brand

> `readonly` **\_\_brand**: `TBrand`

#### Type parameters

##### T

`T`

##### TBrand

`TBrand` *extends* `string`

***

### CryptoGroup

> **CryptoGroup** = `object`

#### Properties

##### bits

> `readonly` **bits**: [`PrimeBits`](#primebits)

##### byteLength

> `readonly` **byteLength**: `number`

##### g

> `readonly` **g**: `bigint`

##### h

> `readonly` **h**: `bigint`

##### name

> `readonly` **name**: [`GroupName`](#groupname)

##### p

> `readonly` **p**: `bigint`

##### q

> `readonly` **q**: `bigint`

##### securityEstimate

> `readonly` **securityEstimate**: `number`

***

### ElgamalCiphertext

> **ElgamalCiphertext** = `object`

#### Properties

##### c1

> `readonly` **c1**: `bigint`

##### c2

> `readonly` **c2**: `bigint`

***

### ElgamalGroupInput

> **ElgamalGroupInput** = [`GroupName`](#groupname) \| [`PrimeBits`](#primebits)

***

### ElgamalKeyPair

> **ElgamalKeyPair** = `object`

#### Properties

##### privateKey

> `readonly` **privateKey**: `bigint`

##### publicKey

> `readonly` **publicKey**: `bigint`

***

### ElgamalParameters

> **ElgamalParameters** = [`ElgamalKeyPair`](#elgamalkeypair) & `object`

#### Type declaration

##### group

> `readonly` **group**: [`CryptoGroup`](#cryptogroup)

***

### GroupElement

> **GroupElement** = [`Brand`](#brand)\<`bigint`, `"GroupElement"`\>

***

### GroupName

> **GroupName** = `"ffdhe2048"` \| `"ffdhe3072"` \| `"ffdhe4096"`

***

### ParticipantIndex

> **ParticipantIndex** = [`Brand`](#brand)\<`number`, `"ParticipantIndex"`\>

***

### PrimeBits

> **PrimeBits** = `2048` \| `3072` \| `4096`

***

### RandomBytesSource

> **RandomBytesSource** = (`length`) => `Uint8Array`

#### Parameters

##### length

`number`

#### Returns

`Uint8Array`

***

### ScalarQ

> **ScalarQ** = [`Brand`](#brand)\<`bigint`, `"ScalarQ"`\>

***

### SubgroupElement

> **SubgroupElement** = [`Brand`](#brand)\<`bigint`, `"SubgroupElement"`\>

***

### ValidatedPublicKey

> **ValidatedPublicKey** = [`Brand`](#brand)\<[`SubgroupElement`](#subgroupelement), `"ValidatedPublicKey"`\>

## Functions

### addEncryptedValues()

> **addEncryptedValues**(`left`, `right`, `group`): [`ElgamalCiphertext`](#elgamalciphertext)

#### Parameters

##### left

[`ElgamalCiphertext`](#elgamalciphertext)

##### right

[`ElgamalCiphertext`](#elgamalciphertext)

##### group

[`ElgamalGroupInput`](#elgamalgroupinput)

#### Returns

[`ElgamalCiphertext`](#elgamalciphertext)

***

### assertInSubgroup()

> **assertInSubgroup**(`value`, `p`, `q`): `void`

#### Parameters

##### value

`bigint`

##### p

`bigint`

##### q

`bigint`

#### Returns

`void`

***

### assertInSubgroupOrIdentity()

> **assertInSubgroupOrIdentity**(`value`, `p`, `q`): `void`

#### Parameters

##### value

`bigint`

##### p

`bigint`

##### q

`bigint`

#### Returns

`void`

***

### assertPlaintextAdditive()

> **assertPlaintextAdditive**(`value`, `bound`, `q`): `void`

#### Parameters

##### value

`bigint`

##### bound

`bigint`

##### q

`bigint`

#### Returns

`void`

***

### assertPlaintextMultiplicative()

> **assertPlaintextMultiplicative**(`value`, `p`): `void`

#### Parameters

##### value

`bigint`

##### p

`bigint`

#### Returns

`void`

***

### assertScalarInZq()

> **assertScalarInZq**(`value`, `q`): `void`

#### Parameters

##### value

`bigint`

##### q

`bigint`

#### Returns

`void`

***

### assertThreshold()

> **assertThreshold**(`threshold`, `participantCount`): `void`

#### Parameters

##### threshold

`number`

##### participantCount

`number`

#### Returns

`void`

***

### assertValidAdditiveCiphertext()

> **assertValidAdditiveCiphertext**(`ciphertext`, `group`): `void`

#### Parameters

##### ciphertext

[`ElgamalCiphertext`](#elgamalciphertext)

##### group

[`CryptoGroup`](#cryptogroup)

#### Returns

`void`

***

### assertValidAdditivePlaintext()

> **assertValidAdditivePlaintext**(`value`, `bound`, `group`): `void`

#### Parameters

##### value

`bigint`

##### bound

`bigint`

##### group

[`CryptoGroup`](#cryptogroup)

#### Returns

`void`

***

### assertValidAdditivePublicKey()

> **assertValidAdditivePublicKey**(`publicKey`, `group`): `void`

#### Parameters

##### publicKey

`bigint`

##### group

[`CryptoGroup`](#cryptogroup)

#### Returns

`void`

***

### assertValidFreshAdditiveCiphertext()

> **assertValidFreshAdditiveCiphertext**(`ciphertext`, `group`): `void`

#### Parameters

##### ciphertext

[`ElgamalCiphertext`](#elgamalciphertext)

##### group

[`CryptoGroup`](#cryptogroup)

#### Returns

`void`

***

### assertValidParticipantIndex()

> **assertValidParticipantIndex**(`index`, `participantCount`): `void`

#### Parameters

##### index

`number`

##### participantCount

`number`

#### Returns

`void`

***

### assertValidPrivateKey()

> **assertValidPrivateKey**(`privateKey`, `group`): `void`

#### Parameters

##### privateKey

`bigint`

##### group

[`CryptoGroup`](#cryptogroup)

#### Returns

`void`

***

### assertValidPublicKey()

> **assertValidPublicKey**(`value`, `p`, `q`): `void`

#### Parameters

##### value

`bigint`

##### p

`bigint`

##### q

`bigint`

#### Returns

`void`

***

### babyStepGiantStep()

> **babyStepGiantStep**(`target`, `base`, `p`, `bound`): `bigint` \| `null`

#### Parameters

##### target

`bigint`

##### base

`bigint`

##### p

`bigint`

##### bound

`bigint`

#### Returns

`bigint` \| `null`

***

### bigintToFixedHex()

> **bigintToFixedHex**(`value`, `byteLength`): `string`

#### Parameters

##### value

`bigint`

##### byteLength

`number`

#### Returns

`string`

***

### bytesToHex()

> **bytesToHex**(`bytes`): `string`

#### Parameters

##### bytes

`Uint8Array`

#### Returns

`string`

***

### concatBytes()

> **concatBytes**(...`arrays`): `Uint8Array`

#### Parameters

##### arrays

...`Uint8Array`\<`ArrayBufferLike`\>[]

#### Returns

`Uint8Array`

***

### decryptAdditive()

> **decryptAdditive**(`ciphertext`, `privateKey`, `group`, `bound`): `bigint`

#### Parameters

##### ciphertext

[`ElgamalCiphertext`](#elgamalciphertext)

##### privateKey

`bigint`

##### group

[`ElgamalGroupInput`](#elgamalgroupinput)

##### bound

`bigint`

#### Returns

`bigint`

***

### deriveH()

> **deriveH**(`input`): `Promise`\<`bigint`\>

#### Parameters

##### input

[`PrimeBits`](#primebits) \| [`GroupName`](#groupname)

#### Returns

`Promise`\<`bigint`\>

***

### domainSeparator()

> **domainSeparator**(`tag`): `Uint8Array`

#### Parameters

##### tag

`string`

#### Returns

`Uint8Array`

***

### encodeForChallenge()

> **encodeForChallenge**(...`elements`): `Uint8Array`

#### Parameters

##### elements

...(`string` \| `bigint` \| `Uint8Array`\<`ArrayBufferLike`\>)[]

#### Returns

`Uint8Array`

***

### encryptAdditive()

> **encryptAdditive**(`message`, `publicKey`, `group`, `bound`): [`ElgamalCiphertext`](#elgamalciphertext)

#### Parameters

##### message

`bigint`

##### publicKey

`bigint`

##### group

[`ElgamalGroupInput`](#elgamalgroupinput)

##### bound

`bigint`

#### Returns

[`ElgamalCiphertext`](#elgamalciphertext)

***

### encryptAdditiveWithRandomness()

> **encryptAdditiveWithRandomness**(`message`, `publicKey`, `randomness`, `bound`, `group`): [`ElgamalCiphertext`](#elgamalciphertext)

#### Parameters

##### message

`bigint`

##### publicKey

`bigint`

##### randomness

`bigint`

##### bound

`bigint`

##### group

[`ElgamalGroupInput`](#elgamalgroupinput)

#### Returns

[`ElgamalCiphertext`](#elgamalciphertext)

***

### fixedHexToBigint()

> **fixedHexToBigint**(`hex`): `bigint`

#### Parameters

##### hex

`string`

#### Returns

`bigint`

***

### generateParameters()

> **generateParameters**(`group`): [`ElgamalParameters`](#elgamalparameters)

#### Parameters

##### group

[`ElgamalGroupInput`](#elgamalgroupinput)

#### Returns

[`ElgamalParameters`](#elgamalparameters)

***

### generateParametersWithPrivateKey()

> **generateParametersWithPrivateKey**(`privateKey`, `group`): [`ElgamalParameters`](#elgamalparameters)

#### Parameters

##### privateKey

`bigint`

##### group

[`ElgamalGroupInput`](#elgamalgroupinput)

#### Returns

[`ElgamalParameters`](#elgamalparameters)

***

### getGroup()

> **getGroup**(`identifier`): [`CryptoGroup`](#cryptogroup)

#### Parameters

##### identifier

[`PrimeBits`](#primebits) \| [`GroupName`](#groupname)

#### Returns

[`CryptoGroup`](#cryptogroup)

***

### getWebCrypto()

> **getWebCrypto**(): `Crypto`

#### Returns

`Crypto`

***

### hexToBytes()

> **hexToBytes**(`hex`): `Uint8Array`

#### Parameters

##### hex

`string`

#### Returns

`Uint8Array`

***

### hkdfSha256()

> **hkdfSha256**(`ikm`, `salt`, `info`, `length`): `Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

#### Parameters

##### ikm

`Uint8Array`

##### salt

`Uint8Array`

##### info

`Uint8Array`

##### length

`number`

#### Returns

`Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

***

### isInSubgroup()

> **isInSubgroup**(`value`, `p`, `q`): `boolean`

#### Parameters

##### value

`bigint`

##### p

`bigint`

##### q

`bigint`

#### Returns

`boolean`

***

### isInSubgroupOrIdentity()

> **isInSubgroupOrIdentity**(`value`, `p`, `q`): `boolean`

#### Parameters

##### value

`bigint`

##### p

`bigint`

##### q

`bigint`

#### Returns

`boolean`

***

### listGroups()

> **listGroups**(): readonly [`CryptoGroup`](#cryptogroup)[]

#### Returns

readonly [`CryptoGroup`](#cryptogroup)[]

***

### mod()

> **mod**(`value`, `modulus`): `bigint`

#### Parameters

##### value

`bigint`

##### modulus

`bigint`

#### Returns

`bigint`

***

### modInvP()

> **modInvP**(`value`, `p`): `bigint`

#### Parameters

##### value

`bigint`

##### p

`bigint`

#### Returns

`bigint`

***

### modInvQ()

> **modInvQ**(`value`, `q`): `bigint`

#### Parameters

##### value

`bigint`

##### q

`bigint`

#### Returns

`bigint`

***

### modP()

> **modP**(`value`, `p`): `bigint`

#### Parameters

##### value

`bigint`

##### p

`bigint`

#### Returns

`bigint`

***

### modPowP()

> **modPowP**(`base`, `exponent`, `p`): `bigint`

#### Parameters

##### base

`bigint`

##### exponent

`bigint`

##### p

`bigint`

#### Returns

`bigint`

***

### modQ()

> **modQ**(`value`, `q`): `bigint`

#### Parameters

##### value

`bigint`

##### q

`bigint`

#### Returns

`bigint`

***

### randomBytes()

> **randomBytes**(`length`, `randomSource?`): `Uint8Array`

#### Parameters

##### length

`number`

##### randomSource?

[`RandomBytesSource`](#randombytessource) = `secureRandomBytesSource`

#### Returns

`Uint8Array`

***

### randomScalarBelow()

> **randomScalarBelow**(`maxExclusive`, `randomSource?`): `bigint`

#### Parameters

##### maxExclusive

`bigint`

##### randomSource?

[`RandomBytesSource`](#randombytessource) = `secureRandomBytesSource`

#### Returns

`bigint`

***

### randomScalarInRange()

> **randomScalarInRange**(`minInclusive`, `maxExclusive`, `randomSource?`): `bigint`

#### Parameters

##### minInclusive

`bigint`

##### maxExclusive

`bigint`

##### randomSource?

[`RandomBytesSource`](#randombytessource) = `secureRandomBytesSource`

#### Returns

`bigint`

***

### sha256()

> **sha256**(`data`): `Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

#### Parameters

##### data

`Uint8Array`

#### Returns

`Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

***

### utf8ToBytes()

> **utf8ToBytes**(`value`): `Uint8Array`

#### Parameters

##### value

`string`

#### Returns

`Uint8Array`
