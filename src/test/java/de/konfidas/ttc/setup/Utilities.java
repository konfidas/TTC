package de.konfidas.ttc.setup;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Random;

public class Utilities {

    static void exportKeyPairToKeystoreFile(KeyPair keyPair, java.security.cert.Certificate certificate, String alias, String fileName, String storeType, String storePass) throws Exception {
        KeyStore sslKeyStore = KeyStore.getInstance(storeType, BouncyCastleProvider.PROVIDER_NAME);
        sslKeyStore.load(null, null);
        sslKeyStore.setKeyEntry(alias, keyPair.getPrivate(),null, new java.security.cert.Certificate[]{certificate});
        FileOutputStream keyStoreOs = new FileOutputStream(fileName);
        sslKeyStore.store(keyStoreOs, storePass.toCharArray());
    }

    static void writeCertToFileBase64Encoded(Certificate certificate, String fileName) throws Exception {
        PrintWriter certificateOut = new PrintWriter(new FileOutputStream(fileName));
        certificateOut.write("-----BEGIN CERTIFICATE-----");
        byte[] base64EncodedCert = Base64.encode(certificate.getEncoded());
        String outString = new String (base64EncodedCert);
        outString = outString.replaceAll("(.{64})", "$1\n");
        certificateOut.write(System.lineSeparator());
        certificateOut.write(outString);
        certificateOut.write(System.lineSeparator());
        certificateOut.write("-----END CERTIFICATE-----");
        certificateOut.flush();
        certificateOut.close();
    }

    public static int getEncodedLength(ASN1Primitive element) throws IOException, ExtendLengthValueExceedsInteger {
        byte[] elementContent = element.getEncoded();

        if ((byte) elementContent[1] == (byte) 0b10000000) {
            //indefinte length encoding
            return 0;
        }

        else if ((elementContent[1] & 0b10000000) == 0) {
            //Case: Definite length encocding, one byte
            return Integer.valueOf(elementContent[1]);
        }

        else {
            //Extended length encoding (limitiert auf max 4 bytes für die Länge)
            int elementNumberOfLengthBytes = (elementContent[1] & 0b01111111);
            if (elementNumberOfLengthBytes > 4) {
                throw new ExtendLengthValueExceedsInteger("Der Wert der extended length überschreitet einen Integer", null);
            }
            byte[] lengthBytes = Arrays.copyOfRange(elementContent, 1, elementNumberOfLengthBytes + 1);
            return ByteBuffer.wrap(lengthBytes).getInt();
        }

    }

    public static byte[] getEncodedValue(ASN1Primitive element) throws IOException, ExtendLengthValueExceedsInteger {
        byte[] elementContent = element.getEncoded();
        int elementLength = getEncodedLength(element);
        return Arrays.copyOfRange(elementContent, elementContent.length - elementLength, elementContent.length + 1);
    }

    public static class ExtendLengthValueExceedsInteger extends Exception {
        public ExtendLengthValueExceedsInteger(String message, Exception reason) {
            super(message, reason);
        }
    }

}
