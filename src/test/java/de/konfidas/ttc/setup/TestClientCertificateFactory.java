package de.konfidas.ttc.setup;

import de.konfidas.ttc.exceptions.TtcException;
import de.konfidas.ttc.utilities.CertificateHelper;
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
import java.security.interfaces.ECPublicKey;
import java.util.Date;

import org.apache.commons.codec.binary.Hex;

import static de.konfidas.ttc.setup.Utilities.exportKeyPairToKeystoreFile;
import static de.konfidas.ttc.setup.Utilities.writeCertToFileBase64Encoded;


//In Anlehnung an https://gist.github.com/vivekkr12/c74f7ee08593a8c606ed96f4b62a208a

public class TestClientCertificateFactory {

    private static final String BC_PROVIDER = "BC";
    Date startDate = new Date(new Date().getTime());
    Date endDate = new Date(new Date().getTime() + 1000 * 60 * 60 * 24);  //Today + 1000 days
    String signatureAlgorithm = "SHA256withECDSA";
    int keySize = 384;
    X509Certificate rootCert;
    BigInteger clientCertSerialNum = new BigInteger(Long.toString(new SecureRandom().nextLong()));
    KeyPair signingKeyPair;
    String keyAlgorithm = "EC";
    X509Certificate clientCert;
    X509Certificate signingCertificate;
    KeyPair clientKeyPair;


    public TestClientCertificateFactory(X509Certificate _signingCertificate, KeyPair _signingKeyPair) {
        Security.addProvider(new BouncyCastleProvider());
        signingKeyPair = _signingKeyPair;
        signingCertificate = _signingCertificate;
    }

    public void build() throws OperatorCreationException, ClientCertificateCreationException {

        /**********************************************************
         ** Schlüsselpaar erzeugen, Hash des privateKey ermitteln *
         **********************************************************/

        KeyPairGenerator keyPairGenerator = null;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance(keyAlgorithm, BC_PROVIDER);
        }
        catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new ClientCertificateCreationException("Fehler bei der Erzeugung des Schlüsselpaars für die Sub-CA", e);
        }
        keyPairGenerator.initialize(this.keySize);
        clientKeyPair = keyPairGenerator.generateKeyPair();
        byte[] encodedCertPublicKey = CertificateHelper.publicKeyToUncompressedPoint((ECPublicKey) clientKeyPair.getPublic());

        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        }
        catch (NoSuchAlgorithmException e) {
            throw new ClientCertificateCreationException(String.format("Fehler bei der Erzeugung der Test-CA. Der Hash-Algorithmus wurde nicht gefunden"), e);
        }

        byte[] hash = digest.digest(encodedCertPublicKey);
        String clientKeyHash = Hex.encodeHexString(hash).toUpperCase();



        /******************************************************************
         ** Issuer und Subject erzeugen, CSR Builder aus der Fab erzeugen *
         ******************************************************************/
        X500Name clientCertSubject = new X500Name("CN=" + clientKeyHash);
        X500Name clientCertIssuer = new X500Name(signingCertificate.getSubjectX500Principal().getName());

        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(clientCertSubject, clientKeyPair.getPublic());
        JcaContentSignerBuilder csrBuilder = new JcaContentSignerBuilder(signatureAlgorithm).setProvider(BC_PROVIDER);

        ContentSigner csrContentSigner = csrBuilder.build(signingKeyPair.getPrivate());
        PKCS10CertificationRequest csr = p10Builder.build(csrContentSigner);


        /****************************************************************************************************************************************
         ** Das Zertifikat wird zusammgengestellt, Extensions werden hinzugefügt. Es wird in einer Holder-Struktur erzeugt und dann extrahiert  *
         ****************************************************************************************************************************************/
        X509v3CertificateBuilder clientCertBuilder = new X509v3CertificateBuilder(clientCertIssuer, clientCertSerialNum, startDate, endDate, csr.getSubject(), csr.getSubjectPublicKeyInfo());


        JcaX509ExtensionUtils clientCertExtUtils = null;
        try {
            clientCertExtUtils = new JcaX509ExtensionUtils();
        }
        catch (NoSuchAlgorithmException e) {
            throw new ClientCertificateCreationException(String.format("Fehler bei der Erzeugung des ClientCert."), e);
        }

        try {
            clientCertBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            clientCertBuilder.addExtension(Extension.authorityKeyIdentifier, false, clientCertExtUtils.createAuthorityKeyIdentifier(signingCertificate));
            clientCertBuilder.addExtension(Extension.subjectKeyIdentifier, false, clientCertExtUtils.createSubjectKeyIdentifier(csr.getSubjectPublicKeyInfo()));

            // Add intended key usage extension if needed
            clientCertBuilder.addExtension(Extension.keyUsage, false, new KeyUsage(KeyUsage.keyEncipherment));
        }
        catch (CertIOException | CertificateException e) {
            throw new ClientCertificateCreationException(String.format("Fehler bei der Erzeugung des ClientCert. Fehler beim Hinzufügen von Extensions."), e);
        }

        X509CertificateHolder clientCertHolder = clientCertBuilder.build(csrContentSigner);
        try {
            clientCert = new JcaX509CertificateConverter().setProvider(BC_PROVIDER).getCertificate(clientCertHolder);
        }
        catch (CertificateException e) {
            throw new ClientCertificateCreationException(String.format("Fehler bei der Erzeugung des ClientCert. Fehler beim Extrahieren des Zertifikats"), e);
        }

        /******************************************************************
         ** Das Zertifikat wird mit dem Schlüssel des Ausstellers geprüft *
         ******************************************************************/
        try {
            clientCert.verify(signingCertificate.getPublicKey(), BC_PROVIDER);
        }
        catch (CertificateException | NoSuchAlgorithmException | InvalidKeyException | NoSuchProviderException | SignatureException e) {
            throw new ClientCertificateCreationException(String.format("Fehler bei der Erzeugung des ClientCert. Das erzeugte Zertifikat konnte nicht verifziert werden."), e);
        }
    }

    public void exportClientCertToFile(String exportPathCertificate, String exportPathKeypair) throws ClientCertificateNotYetCreatedException, clientCertExportException {

        if ((clientCert == null) || (clientKeyPair == null)) { throw new ClientCertificateNotYetCreatedException();}

        try {
            writeCertToFileBase64Encoded(clientCert, Paths.get(exportPathCertificate).toString());
            exportKeyPairToKeystoreFile(clientKeyPair, clientCert, "client-cert", Paths.get(exportPathKeypair).toString(), "PKCS12", "pass");
        }
        catch (Exception e) {
            throw new clientCertExportException();

        }
    }


    public static class ClientCertificateCreationException extends TtcException {
        public ClientCertificateCreationException(String expected, Throwable cause) {
            super("Fehler bei der Erstellung des Client-Zertifikats", cause);
        }
    }

    public static class ClientCertificateNotYetCreatedException extends TtcException {
        public ClientCertificateNotYetCreatedException() {
            super("Das Client-Zertifikat kann nicht exportiert werden weil es noch nicht erstellt wurde.", null);
        }
    }

    public static class clientCertExportException extends TtcException {
        public clientCertExportException() {
            super("Das Client-Zertifikat kann nicht erstellt werden.", null);
        }
    }
}

