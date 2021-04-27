package de.konfidas.ttc.setup;

import de.konfidas.ttc.exceptions.TtcException;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import java.math.BigInteger;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import static de.konfidas.ttc.setup.Utilities.exportKeyPairToKeystoreFile;
import static de.konfidas.ttc.setup.Utilities.writeCertToFileBase64Encoded;


//In Anlehnung an https://gist.github.com/vivekkr12/c74f7ee08593a8c606ed96f4b62a208a

public class TestCAFactory {

    final Date startDate = new Date(new Date().getTime());
    final Date endDate = new Date(new Date().getTime() + 1000 * 60 * 60 * 24);  //Today + 1000 days
    final String signatureAlgorithm = "SHA256withECDSA";
    final int keySize = 384;
     X509Certificate rootCert;
    final BigInteger rootSerialNum = new BigInteger(Long.toString(new SecureRandom().nextLong()));
     KeyPair rootKeyPair;
    final String keyAlgorithm = "EC";
    final String commonName = "root-cert";


    public TestCAFactory(){
        Security.addProvider(new BouncyCastleProvider());
    }

    public void build() throws CACreationException, OperatorCreationException {
        /****************************************
         ** Erst wird ein Schlüsselpaar erzeugt *
         ****************************************/
        KeyPairGenerator keyPairGenerator;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance(keyAlgorithm, BouncyCastleProvider.PROVIDER_NAME);
        }
        catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new CACreationException("Fehler bei der Erzeugung des Schlüsselpaars für die CA", e);
        }
        keyPairGenerator.initialize(this.keySize);
        rootKeyPair = keyPairGenerator.generateKeyPair();

        /**************************************************************************************************************************************************
         ** Dann wird das Zertifkat erzeugt und die Extensions ergänzt, das Zertifikat wird in einer Holder Struktur gehalten und anschließend extrahiert *
         ***************************************************************************************************************************************************/
        X500Name rootCertIssuer = new X500Name("CN=" + commonName);
        X500Name rootCertSubject = rootCertIssuer;
        ContentSigner rootCertContentSigner = new JcaContentSignerBuilder(signatureAlgorithm).setProvider(BouncyCastleProvider.PROVIDER_NAME).build(rootKeyPair.getPrivate());
        X509v3CertificateBuilder rootCertBuilder = new JcaX509v3CertificateBuilder(rootCertIssuer, rootSerialNum, startDate, endDate, rootCertSubject, rootKeyPair.getPublic());

        try {
            JcaX509ExtensionUtils rootCertExtUtils = new JcaX509ExtensionUtils();
            rootCertBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            rootCertBuilder.addExtension(Extension.subjectKeyIdentifier, false, rootCertExtUtils.createSubjectKeyIdentifier(rootKeyPair.getPublic()));
        }
        catch (CertIOException | NoSuchAlgorithmException e) {
            throw new CACreationException("Fehler bei der Erzeugung des CA Zertifikats. Fehler beim Hinzufügen der Extensions.", e);
        }

        X509CertificateHolder rootCertHolder = rootCertBuilder.build(rootCertContentSigner);
        try {
            rootCert = new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(rootCertHolder);
        }
        catch (CertificateException e) {
            throw new CACreationException("Fehler bei der Erzeugung des CA Zertifikats", e);
        }


    }
    public void exportCAToFile(String exportPathCertificate, String exportPathKeypair) throws CANotYetCreatedException, CAExportException {
        if ((rootCert == null) || (rootKeyPair == null)){throw new CANotYetCreatedException();}

        try {
            writeCertToFileBase64Encoded(rootCert, Paths.get(exportPathCertificate).toString());
            exportKeyPairToKeystoreFile(rootKeyPair, rootCert, "root-cert", Paths.get(exportPathKeypair).toString(), "PKCS12", "pass");

        }
        catch (Exception e) {
            throw new CAExportException();
        }
    }

    public X509Certificate getRootCert() {
       //FIXME: clone
        return rootCert;
//        return new X509Certificate(rootCert);

    }

    public KeyPair getRootKeyPair() {
        //FIXME: clone
        return rootKeyPair;
    }


    public static class CACreationException extends TtcException {
        public CACreationException(String expected, Throwable cause) {
            super("Fehler bei der Erstellung der CA", cause);
        }
    }

    public static class CANotYetCreatedException extends TtcException {
        public CANotYetCreatedException() {
            super("Die CA kann nicht exportiert werden weil sie noch nicht erstellt wurde", null);
        }
    }

    public static class CAExportException extends TtcException {
        public CAExportException() {
            super("Die CA kann nicht exportiert werden.", null);
        }
    }





}
