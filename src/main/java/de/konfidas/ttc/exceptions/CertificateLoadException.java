package de.konfidas.ttc.exceptions;

/**
 * Diese Exception wird aus der Methode loadCertificate geworfen. Sie zeigt an,
 * dass beim Laden des Zertifikats ein Fehler aufgetreten ist. Die Exception enthält
 * eine message mit weitere Infos und eine innerException, die auf die Ursache des Fehlers zeigt
 */

public class CertificateLoadException extends TtcException{
    public CertificateLoadException(String message, Throwable cause){
        super(message,cause);

    }
}
