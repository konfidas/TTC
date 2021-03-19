package de.konfidas.ttc.setup;

import org.bouncycastle.util.encoders.Base64;

import java.io.FileOutputStream;
import java.io.PrintWriter;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.Certificate;

public class Utilities {

    static void exportKeyPairToKeystoreFile(KeyPair keyPair, java.security.cert.Certificate certificate, String alias, String fileName, String storeType, String storePass) throws Exception {
        KeyStore sslKeyStore = KeyStore.getInstance(storeType, "BC");
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

}
