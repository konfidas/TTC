package de.konfidas.ttc.exceptions;

/**
 * Diese Exception wird aus der Methode parse in LogMessageArchiove geworfen. Sie zeigt an,
 * dass beim Laden des Zertifikats ein Fehler aufgetreten ist.  Der Fehler zeigt an, dasa der
 * subject Name des Zertifikats nicht zum im Dateinamen kodierten Hash des PublicKey oder zum
 * Hash des PublicKey selbst passt. Die Exception enthält
 * eine message mit weitere Infos und eine innerException, die auf die Ursache des Fehlers zeigt
 */

public class CertificateInconsistentToFilenameException extends TtcException{
    public CertificateInconsistentToFilenameException(String message, Throwable cause){
        super(message,cause);

    }
}
