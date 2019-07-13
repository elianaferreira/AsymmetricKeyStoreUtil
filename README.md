# AsymmetricKeyStoreUtil
Util class for encrypt and decrypt data using Asymmetric Encryption for Android apps.

## Compatibility
Asymmetric Encryption is compatible with Android API 18 and up, see [Android Keystore documentation](https://developer.android.com/training/articles/keystore).

## Instalation
Just copy this file into your project.

## Usage
Once the file is into your project, create an instance of `KeyStoreUtil` calling its constructor, then call the `init()` method to initialize the KeyStore and the Cipher, and that's all.
Then just call the `encrypt` and `decrypt` methods when you need.
