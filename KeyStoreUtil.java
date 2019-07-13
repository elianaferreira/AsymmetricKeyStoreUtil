
import android.annotation.TargetApi;
import android.os.Build;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Calendar;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.security.auth.x500.X500Principal;

public class KeyStoreUtil {

    private static final String KEYSTORE_PROVIDER_ANDROID_KEYSTORE = "AndroidKeyStore";
    private static final String KEYSTORE_ALIAS = ":alias:asymmetricKeyPair";
    private static final String ALGORITHM = "RSA";
    private static final String TRANSFORMATION_ASYMMETRIC = "RSA/ECB/PKCS1Padding";

    public KeyStore keyStore;
    public Cipher cipher;


    public KeyStoreUtil() {}


    public void init() throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException,
            NoSuchPaddingException, NoSuchProviderException, InvalidAlgorithmParameterException {
        this.keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER_ANDROID_KEYSTORE);
        this.keyStore.load(null);
        this.cipher = Cipher.getInstance(TRANSFORMATION_ASYMMETRIC);
    }


    private KeyPair createKeyStoreAsymmetricKey() throws NoSuchAlgorithmException,
            NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGORITHM,
                KEYSTORE_PROVIDER_ANDROID_KEYSTORE);

        if(Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            initGeneratorWithKeyGenParamSpec(generator);
        } else {
            initGeneratorWithKeyPairGenSpec(generator);
        }

        return generator.generateKeyPair();
    }


    private void initGeneratorWithKeyPairGenSpec(KeyPairGenerator generator)
            throws InvalidAlgorithmParameterException {
        Calendar start = Calendar.getInstance();
        Calendar end = Calendar.getInstance();
        end.add(Calendar.YEAR, 3);
        KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec
                .Builder(MPOSApp.getApplication().getApplicationContext())
                .setAlias(KEYSTORE_ALIAS)
                .setSubject(new X500Principal("CN=${"+KEYSTORE_ALIAS+"} CA Certificate"))
                .setSerialNumber(BigInteger.ONE)
                .setStartDate(start.getTime())
                .setEndDate(end.getTime())
                .build();
        generator.initialize(spec);
    }


    @TargetApi(Build.VERSION_CODES.M)
    private void initGeneratorWithKeyGenParamSpec(KeyPairGenerator generator)
            throws InvalidAlgorithmParameterException {
        generator.initialize(new KeyGenParameterSpec.Builder(
                KEYSTORE_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_ECB)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                .setRandomizedEncryptionRequired(false)
                .build());
    }


    public KeyPair getAsymmetricKeyPair() throws NoSuchAlgorithmException,
            KeyStoreException, UnrecoverableKeyException {
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(KEYSTORE_ALIAS, null);
        PublicKey publicKey = keyStore.getCertificate(KEYSTORE_ALIAS).getPublicKey();

        if(privateKey != null && publicKey != null) {
            return new KeyPair(publicKey, privateKey);
        } else {
            return null;
        }
    }


    public void deleteAsymmetricKeyPair() throws KeyStoreException {
        keyStore.deleteEntry(KEYSTORE_ALIAS);
    }


    public String encrypt(String data) throws InvalidKeyException, BadPaddingException,
            IllegalBlockSizeException, NoSuchAlgorithmException, NoSuchProviderException,
            InvalidAlgorithmParameterException, UnrecoverableKeyException, KeyStoreException {
        createKeyStoreAsymmetricKey();
        KeyPair keyPair = getAsymmetricKeyPair();
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        byte[] bytes = cipher.doFinal(data.getBytes());
        return Base64.encodeToString(bytes, Base64.DEFAULT);
    }


    public String decypt(String data, Key key) throws BadPaddingException, IllegalBlockSizeException,
            InvalidKeyException{
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] encryptedData = Base64.decode(data, Base64.DEFAULT);
        byte[] decryptedData = cipher.doFinal(encryptedData);
        return new String(decryptedData);
    }
}
