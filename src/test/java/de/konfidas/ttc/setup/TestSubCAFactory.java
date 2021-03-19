package de.konfidas.ttc.setup;

import de.konfidas.ttc.exceptions.TtcException;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import java.math.BigInteger;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

import static de.konfidas.ttc.setup.Utilities.exportKeyPairToKeystoreFile;
import static de.konfidas.ttc.setup.Utilities.writeCertToFileBase64Encoded;

//In Anlehnung an https://gist.github.com/vivekkr12/c74f7ee08593a8c606ed96f4b62a208a

public class TestSubCAFactory {
    private static final String BC_PROVIDER = "BC";
    public X509Certificate getSubCACert() {
        //FIXME: clone
        return subCACert;
    }

    public KeyPair getSubCAKeyPair() {
  //FIXME: clone
        return subCAKeyPair;
    }


    Date startDate = new Date(new Date().getTime());
    Date endDate = new Date(new Date().getTime() + 1000 * 60 * 60 * 24);  //Today + 1000 days
    private String signatureAlgorithm = "SHA256withECDSA";
    private int keySize = 384;
    private X509Certificate rootCert;
    private BigInteger subCASerialNum = new BigInteger(Long.toString(new SecureRandom().nextLong()));
    private KeyPair rootKeyPair;
    private String keyAlgorithm = "EC";
    private String commonName = "subca-cert";
    X509Certificate subCACert  = null;
    X509Certificate rootCertificate  = null;
    KeyPair subCAKeyPair = null;


    public TestSubCAFactory(X509Certificate _rootCertificate, KeyPair _rootKeyPair){
        Security.addProvider(new BouncyCastleProvider());
        rootKeyPair = _rootKeyPair;
        rootCert = _rootCertificate;
    }

    public void build() throws SubCACreationException, OperatorCreationException {
        /****************************************
         ** Erst wird ein Schlüsselpaar erzeugt *
         ****************************************/

        KeyPairGenerator keyPairGenerator = null;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance(keyAlgorithm, BC_PROVIDER);
        }
        catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new SubCACreationException("Fehler bei der Erzeugung des Schlüsselpaars für die Sub-CA", e);
        }
        keyPairGenerator.initialize(this.keySize);
        subCAKeyPair = keyPairGenerator.generateKeyPair();

        /**************************************************************************************************************************************************
         ** Dann wird das Zertifkat erzeugt und die Extensions ergänzt, das Zertifikat wird in einer Holder Struktur gehalten und anschließend extrahiert *
         ***************************************************************************************************************************************************/
        X500Name subCACertIssuer = new X500Name(rootCert.getSubjectX500Principal().getName());
        X500Name subCACertSubject = new X500Name("CN="+ commonName);

        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(subCACertSubject, subCAKeyPair.getPublic());
        JcaContentSignerBuilder csrBuilder = new JcaContentSignerBuilder(signatureAlgorithm).setProvider(BC_PROVIDER);

        ContentSigner csrContentSigner = csrBuilder.build(rootKeyPair.getPrivate());
        PKCS10CertificationRequest csr = p10Builder.build(csrContentSigner);

        X509v3CertificateBuilder subCACertBuilder = new X509v3CertificateBuilder(subCACertIssuer, subCASerialNum, startDate, endDate, csr.getSubject(), csr.getSubjectPublicKeyInfo());
        JcaX509ExtensionUtils subCACertExtUtils;
        try {
             subCACertExtUtils = new JcaX509ExtensionUtils();
        }
        catch (NoSuchAlgorithmException e) {
            throw new SubCACreationException("Fehler bei der Erzeugung der Sub-CA", e);
        }

        try {
            subCACertBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            subCACertBuilder.addExtension(Extension.subjectKeyIdentifier, false, subCACertExtUtils.createSubjectKeyIdentifier(subCAKeyPair.getPublic()));
            // Add intended key usage extension if needed
            subCACertBuilder.addExtension(Extension.keyUsage, false, new KeyUsage(KeyUsage.keyCertSign));
        }
        catch (CertIOException e) {
            throw new SubCACreationException("Fehler bei der Erzeugung der Sub-CA", e);
        }

        X509CertificateHolder subCACertHolder = subCACertBuilder.build(csrContentSigner);

        try {
            subCACert = new JcaX509CertificateConverter().setProvider(BC_PROVIDER).getCertificate(subCACertHolder);
        }
        catch (CertificateException e) {
            throw new SubCACreationException("Fehler bei der Erzeugung der Sub-CA", e);
        }

        /******************************************************************
         ** Das Zertifikat wird mit dem Schlüssel des Ausstellers geprüft *
         ******************************************************************/
        try {
            subCACert.verify(rootCert.getPublicKey(), BC_PROVIDER);
        }

        catch (NoSuchAlgorithmException |InvalidKeyException|SignatureException|NoSuchProviderException|CertificateException e) {
            throw new SubCACreationException("Fehler bei der Erzeugung der Sub-CA. Das Sub-CA Zertifikat wurde erstellt, konnte aber nicht gegen den CA-key verifiziert werden", e);

        }

    }
    public void exportSubCAToFile(String exportPathCertificate, String exportPathKeypair) throws SubCANotYetCreatedException, SubCAExportException {
        if ((rootCert == null) || (rootKeyPair == null)){throw new SubCANotYetCreatedException();}

        try {
            writeCertToFileBase64Encoded(subCACert, Paths.get(exportPathCertificate).toString());
            exportKeyPairToKeystoreFile(subCAKeyPair, subCACert, "subCA-cert", Paths.get(exportPathKeypair).toString() , "PKCS12", "pass");

        }
        catch (Exception e) {
            throw new SubCAExportException();

        }
    }


    public static class SubCACreationException extends TtcException {
        public SubCACreationException(String expected, Throwable cause) {
            super("Fehler bei der Erstellug der Sub-CA", cause);
        }
    }

    public static class SubCANotYetCreatedException extends TtcException {
        public SubCANotYetCreatedException() {
            super("Die Sub-CA kann nicht exportiert werden weil sie noch nicht erstellt wurde", null);
        }
    }

    public static class SubCAExportException extends TtcException {
        public SubCAExportException() {
            super("Die Sub-CA kann nicht exportiert werden.", null);
        }
    }





}
