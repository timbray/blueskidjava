package com.textuality.blueskid;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Contains static methods for converting between java.security.PublicKey instances and text-string representations
 *  of Ed25519 (EdDSA) public keys.
 */
public class Ed25519 {

    /**
     * Generate a base64-encoded textual representation of an ed25519 public key.
     *
     * The representation is the base64 version of the ASN.1 serialization of the
     *  public key per X509/PKIX rules. In the case of Ed25519 key, which is just
     *  an unstructured 32-byte array, there's a case to be made that for
     *  applications that don't require Algorithm Agility, we should bypass the
     *  PKIX/ASN.1 stuff and just base64 the bytes of the key. For the
     *  Blueskid project, I don't believe we need Algorithm Agility, but
     *  unfortunately so far I can't find a way to get at the actual raw
     *  key bytes inside the java.security.PublicKey object.  Even reflection
     *  APIs are now impeded by the new Modules stuff.
     *
     * @param key the ed25519 public key to be converted to text
     * @return the base64-encoded string representation of the key
     * @throws Exception if the key's algorithm is not ed25519
     */
    public static String keyToString(final PublicKey key) throws Exception {
        if (!key.getAlgorithm().equals("EdDSA")) {
            throw new Exception("Key type is " + key.getAlgorithm() + ", should be EdDSA.");
        }

        // you could make non-static methods that re-use an encoder and are thus more efficient, but it's
        // hard to imagine an app that needs to do this at high frequency
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    /**
     * Parse a base64 string, optionally ASCII-armored, and return the ed25519 public key it represents
     *
     * @param s base64-encoded text representing a public key, optionally ASCII-armored
     * @return a java.security.PublicKey suitable for verifying signatures
     * @throws Exception if the string represents a non-ed25119 key
     */
    public static PublicKey stringToKey(String s) throws Exception {
        // strip ASCII armor if any
        if (s.contains("----BEGIN")) {
            s = s.replace("-----BEGIN PUBLIC KEY-----", "")
                    .replaceAll(System.lineSeparator(), "")
                    .replace("-----END PUBLIC KEY-----", "");
        }

        // you could make non-static methods that re-use an encoder and are thus more efficient, but it's
        // hard to imagine an app that needs to do this at high frequency
        final byte[] serializedKey = Base64.getDecoder().decode(s);

        // same comment, could keep a KeyFactory around if thought worthwhile
        final KeyFactory kf = KeyFactory.getInstance("Ed25519");
        final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(serializedKey);
        final PublicKey key = kf.generatePublic(keySpec);
        if (!key.getAlgorithm().equals("EdDSA")) {
            throw new Exception("Key type is " + key.getAlgorithm() + ", should be EdDSA.");
        }

        return key;
    }
}
