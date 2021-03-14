package de.konfidas.ttc.tars;

import de.konfidas.ttc.exceptions.CertificateInconsistentToFilenameException;
import de.konfidas.ttc.utilities.CertificateHelper;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

import java.security.*;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.List;

public class CertificateValidator {

    public static void validateCertificateAgainstFilename(X509Certificate cert, String filename) throws CertificateInconsistentToFilenameException {
        X500Name certSubject = null;
        try {
            certSubject = new JcaX509CertificateHolder(cert).getSubject();
        } catch (CertificateEncodingException e) {
            throw new CertificateInconsistentToFilenameException(String.format("Fehler bei der Konsistenzprüfung des Zertifikats %s", filename),e);
        }

        RDN cn = certSubject.getRDNs(BCStyle.CN)[0];

        String certSubjectClean = IETFUtils.valueToString(cn.getFirst().getValue()).toUpperCase();

        String keyHashFromFilename = filename.split("_")[0].toUpperCase();

        if (!(certSubjectClean.equals(keyHashFromFilename))){
            throw new FilenameToSubjectMismatchException(filename, keyHashFromFilename);
        }

        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new CertificateInconsistentToFilenameException(String.format("Fehler bei der Konsistenzprüfung des Zertifikats %s", filename),e);
        }

        byte[] encodedCertPublicKey = CertificateHelper.publicKeyToUncompressedPoint((ECPublicKey) cert.getPublicKey());

        byte[] hash = digest.digest(encodedCertPublicKey);
        String sha256HexString = Hex.encodeHexString(hash).toUpperCase();

        if (!(sha256HexString.equals(keyHashFromFilename))){
            throw new FilenameToPubKeyMismatchException(filename, sha256HexString);
        }

    }

    public static class FilenameToSubjectMismatchException extends CertificateInconsistentToFilenameException {
        public FilenameToSubjectMismatchException(String expected, String found) {
            super("FileName to Subject mismatch: got "+found+", but expected "+expected, null);
        }
    }

    public static class FilenameToPubKeyMismatchException extends CertificateInconsistentToFilenameException{
        public FilenameToPubKeyMismatchException(String expected, String found) {
            super("FileName to Public Key mismatch: got "+found+", but expected "+expected, null);
        }
    }





    /**
     * @param certToCheck       Das Zertifikat, dessen Gültigkeit geprüft werden soll
     * @param trustedCert        Ein TrustStore, der das Root-Zertifikat enthält
     * @param intermediateCerts Die Liste der Intermediate-Zertifikate, die für eine Chain zwischen certToCheck und dem Zertifikat im TrustStore benötigt werden.
     * @return
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchProviderException
     * @throws CertPathValidatorException
     * @throws CertificateException
     */
    public static boolean checkCert(X509Certificate certToCheck, X509Certificate
            trustedCert, List<X509Certificate> intermediateCerts) throws
            NoSuchAlgorithmException, KeyStoreException, InvalidAlgorithmParameterException, NoSuchProviderException, CertPathValidatorException, CertificateException {
//FIXME: Noch nicht implementiert
        //        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
//        CertPath path = cf.generateCertPath(intermediateCerts);
//        CertPathValidator validator = CertPathValidator.getInstance("PKIX");

//        Collection<? extends CRL> crls;
//        try (InputStream is = Files.newInputStream(Paths.get("crls.p7c"))) {
//            crls = cf.generateCRLs(is);
//        }
//        PKIXParameters params = new PKIXParameters(trustStore);
//        CertStore store = CertStore.getInstance("Collection",new CollectionCertStoreParameters(), "BC");
////        CertStore store = CertStore.getInstance("Collection", new CollectionCertStoreParameters(crls));
//        /* If necessary, specify the certificate policy or other requirements
//         * with the appropriate params.setXXX() method. */
//        params.addCertStore(store);
//        /* Validate will throw an exception on invalid chains. */
//        PKIXCertPathValidatorResult r = (PKIXCertPathValidatorResult) validator.validate(path, params);
        return true;
    }

}
