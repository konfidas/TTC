package de.konfidas.ttc.cert;

import de.konfidas.ttc.exceptions.CertificateInconsistentToFilenameException;
import de.konfidas.ttc.utilities.CertificateHelper;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.encoders.Base64;
import org.junit.Test;

import java.io.FileOutputStream;
import java.math.BigInteger;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.Calendar;
import java.util.Date;
import java.nio.file.Path;

//In Anlehnung an https://gist.github.com/vivekkr12/c74f7ee08593a8c606ed96f4b62a208a

public class TestCA {
    private static final String BC_PROVIDER = "BC";
    private static final String KEY_ALGORITHM = "EC";
    private static final String SIGNATURE_ALGORITHM = "SHA256withECDSA";
    private static final String EXPORT_FOLDER = "/Users/nils/temp";

    @Test
    public void setupGoodCaseCA() throws Exception{

        /*****************************
         ** Erst wird die CA erzeugt *
         *****************************/

        String testst = EXPORT_FOLDER;
        // Add the BouncyCastle Provider
        Security.addProvider(new BouncyCastleProvider());

        // Initialize a new KeyPair generator
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM, BC_PROVIDER);
        keyPairGenerator.initialize(384);

        // Setup start date to yesterday and end date for 1 year validity
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.DATE, -1);
        Date startDate = calendar.getTime();

        calendar.add(Calendar.YEAR, 1);
        Date endDate = calendar.getTime();

        // First step is to create a root certificate
        // First Generate a KeyPair,
        // then a random serial number
        // then generate a certificate using the KeyPair
        KeyPair rootKeyPair = keyPairGenerator.generateKeyPair();
        BigInteger rootSerialNum = new BigInteger(Long.toString(new SecureRandom().nextLong()));

        // Issued By and Issued To same for root certificate
        X500Name rootCertIssuer = new X500Name("CN=root-cert");
        X500Name rootCertSubject = rootCertIssuer;
        ContentSigner rootCertContentSigner = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(BC_PROVIDER).build(rootKeyPair.getPrivate());
        X509v3CertificateBuilder rootCertBuilder = new JcaX509v3CertificateBuilder(rootCertIssuer, rootSerialNum, startDate, endDate, rootCertSubject, rootKeyPair.getPublic());

        // Add Extensions
        // A BasicConstraint to mark root certificate as CA certificate
        JcaX509ExtensionUtils rootCertExtUtils = new JcaX509ExtensionUtils();
        rootCertBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        rootCertBuilder.addExtension(Extension.subjectKeyIdentifier, false, rootCertExtUtils.createSubjectKeyIdentifier(rootKeyPair.getPublic()));

        // Create a cert holder and export to X509Certificate
        X509CertificateHolder rootCertHolder = rootCertBuilder.build(rootCertContentSigner);
        X509Certificate rootCert = new JcaX509CertificateConverter().setProvider(BC_PROVIDER).getCertificate(rootCertHolder);

        writeCertToFileBase64Encoded(rootCert, Paths.get(EXPORT_FOLDER,"root-cert.cer").toString());
        exportKeyPairToKeystoreFile(rootKeyPair, rootCert, "root-cert", Paths.get(EXPORT_FOLDER,"root-cert.pfx").toString(), "PKCS12", "pass");


        /*********************************
         ** Dann wird die Sub-CA erzeugt *
         *********************************/
        // Generate a new KeyPair and sign it using the Root Cert Private Key
        // by generating a CSR (Certificate Signing Request)
        X500Name subCACertIssuer = new X500Name("CN=subCA-cert");
        X500Name subCACertSubject = new X500Name("CN=subCA-cert");
        BigInteger subCASerialNum = new BigInteger(Long.toString(new SecureRandom().nextLong()));
        KeyPair subCAKeyPair = keyPairGenerator.generateKeyPair();


        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(subCACertSubject, subCAKeyPair.getPublic());
        JcaContentSignerBuilder csrBuilder = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(BC_PROVIDER);

        // Sign the new KeyPair with the root cert Private Key
        ContentSigner csrContentSigner = csrBuilder.build(rootKeyPair.getPrivate());
        PKCS10CertificationRequest csr = p10Builder.build(csrContentSigner);

        // Use the Signed KeyPair and CSR to generate an issued Certificate
        // Here serial number is randomly generated. In general, CAs use
        // a sequence to generate Serial number and avoid collisions
        X509v3CertificateBuilder subCACertBuilder = new X509v3CertificateBuilder(rootCertIssuer, subCASerialNum, startDate, endDate, csr.getSubject(), csr.getSubjectPublicKeyInfo());
        JcaX509ExtensionUtils subCACertExtUtils = new JcaX509ExtensionUtils();


        // Add Extensions
        // A BasicConstraint to mark root certificate as CA certificate
        subCACertBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        subCACertBuilder.addExtension(Extension.subjectKeyIdentifier, false, rootCertExtUtils.createSubjectKeyIdentifier(subCAKeyPair.getPublic()));


        // Add intended key usage extension if needed
        subCACertBuilder.addExtension(Extension.keyUsage, false, new KeyUsage(KeyUsage.keyCertSign));

        X509CertificateHolder subCACertHolder = subCACertBuilder.build(csrContentSigner);
        X509Certificate subCACert  = new JcaX509CertificateConverter().setProvider(BC_PROVIDER).getCertificate(subCACertHolder);

        // Verify the issued cert signature against the root (issuer) cert
        subCACert.verify(rootCert.getPublicKey(), BC_PROVIDER);

        writeCertToFileBase64Encoded(subCACert, Paths.get(EXPORT_FOLDER,"subCA-cert.cer").toString());
        exportKeyPairToKeystoreFile(subCAKeyPair, subCACert, "subCA-cert", Paths.get(EXPORT_FOLDER,"subCA-cert.pfx").toString() , "PKCS12", "pass");


        /**************************************
         ** Dann wird das Client Zert erzeugt *
         **************************************/

        // Generate a new KeyPair and sign it using the SubCA Cert Private Key
        // by generating a CSR (Certificate Signing Request)
        BigInteger issuedCertSerialNum = new BigInteger(Long.toString(new SecureRandom().nextLong()));
        KeyPair issuedCertKeyPair = keyPairGenerator.generateKeyPair();
        byte[] encodedCertPublicKey = CertificateHelper.publicKeyToUncompressedPoint((ECPublicKey) issuedCertKeyPair.getPublic());

        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new CertificateInconsistentToFilenameException(String.format("Fehler bei der Erzeugung der Test-CA. Der Hash-Agorithmus wurde nicht gefunden"),e);
        }

        byte[] hash = digest.digest(encodedCertPublicKey);
        String sha256HexString = Hex.encodeHexString(hash).toUpperCase();

        X500Name issuedCertSubject = new X500Name("CN="+"addon"+sha256HexString);



        p10Builder = new JcaPKCS10CertificationRequestBuilder(issuedCertSubject, issuedCertKeyPair.getPublic());
         csrBuilder = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(BC_PROVIDER);

        // Sign the new KeyPair with the root cert Private Key
         csrContentSigner = csrBuilder.build(subCAKeyPair.getPrivate());
         csr = p10Builder.build(csrContentSigner);


        // Use the Signed KeyPair and CSR to generate an issued Certificate
        // Here serial number is randomly generated. In general, CAs use
        // a sequence to generate Serial number and avoid collisions
        X509v3CertificateBuilder issuedCertBuilder = new X509v3CertificateBuilder(subCACertIssuer, issuedCertSerialNum, startDate, endDate, csr.getSubject(), csr.getSubjectPublicKeyInfo());

        JcaX509ExtensionUtils issuedCertExtUtils = new JcaX509ExtensionUtils();

        // Add Extensions
        // Use BasicConstraints to say that this Cert is not a CA
        issuedCertBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

        // Add Issuer cert identifier as Extension
        issuedCertBuilder.addExtension(Extension.authorityKeyIdentifier, false, issuedCertExtUtils.createAuthorityKeyIdentifier(rootCert));
        issuedCertBuilder.addExtension(Extension.subjectKeyIdentifier, false, issuedCertExtUtils.createSubjectKeyIdentifier(csr.getSubjectPublicKeyInfo()));

        // Add intended key usage extension if needed
        issuedCertBuilder.addExtension(Extension.keyUsage, false, new KeyUsage(KeyUsage.keyEncipherment));

        X509CertificateHolder issuedCertHolder = issuedCertBuilder.build(csrContentSigner);
        X509Certificate issuedCert  = new JcaX509CertificateConverter().setProvider(BC_PROVIDER).getCertificate(issuedCertHolder);

        // Verify the issued cert signature against the root (issuer) cert
        issuedCert.verify(subCACert.getPublicKey(), BC_PROVIDER);

        writeCertToFileBase64Encoded(issuedCert, Paths.get(EXPORT_FOLDER,sha256HexString +".cer").toString());
        exportKeyPairToKeystoreFile(issuedCertKeyPair, issuedCert, "issued-cert", Paths.get(EXPORT_FOLDER,sha256HexString+".pfx").toString() , "PKCS12", "pass");

    }

    static void exportKeyPairToKeystoreFile(KeyPair keyPair, Certificate certificate, String alias, String fileName, String storeType, String storePass) throws Exception {
        KeyStore sslKeyStore = KeyStore.getInstance(storeType, BC_PROVIDER);
        sslKeyStore.load(null, null);
        sslKeyStore.setKeyEntry(alias, keyPair.getPrivate(),null, new Certificate[]{certificate});
        FileOutputStream keyStoreOs = new FileOutputStream(fileName);
        sslKeyStore.store(keyStoreOs, storePass.toCharArray());
    }

    static void writeCertToFileBase64Encoded(Certificate certificate, String fileName) throws Exception {
        FileOutputStream certificateOut = new FileOutputStream(fileName);
        certificateOut.write("-----BEGIN CERTIFICATE-----".getBytes());
        certificateOut.write(Base64.encode(certificate.getEncoded()));
        certificateOut.write("-----END CERTIFICATE-----".getBytes());
        certificateOut.close();
    }


}
