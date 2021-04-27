package de.konfidas.ttc.validation;

import de.konfidas.ttc.exceptions.ValidationException;
import de.konfidas.ttc.tars.LogMessageArchive;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.*;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;

public class CertificateValidator implements Validator {
    final static Logger logger = LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
    final Collection<X509Certificate> trustedCerts;

    public CertificateValidator(Collection<X509Certificate> trustedCerts){
        this.trustedCerts = trustedCerts;
    }

    @Override
    public Collection<ValidationException> validate(LogMessageArchive tar) {
        LinkedList<ValidationException> errors = new LinkedList<>();

        for (X509Certificate cert : tar.getClientCertificates().values()) {
            try {
                logger.debug("Prüfe das Zertifikat mit Seriennummer {} auf Korrektheit und prüfe die zugehörige Zertifikatskette.", cert.getSerialNumber());
                checkCert(cert, trustedCerts, new ArrayList<>(tar.getIntermediateCertificates().values()));
            }catch (Exception e) {
                errors.add(new CertificateValidationException(cert, e));
            }
        }

        return errors;
    }

    public static void checkCert(X509Certificate certToCheck, Collection<X509Certificate>
            trustedCerts, List<X509Certificate> intermediateCerts) throws
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
    }


    public static class CertificateValidationException extends ValidationException{
        final X509Certificate cert;
        final Throwable e;

        CertificateValidationException(X509Certificate cert, Throwable e) {
            super("Validation certificate "+ cert.getSerialNumber() +" failed.", null);
            this.cert = cert;
            this.e = e;
        }

        public X509Certificate getCert(){return cert;}
        public Throwable getError(){return e;}
    }
}
