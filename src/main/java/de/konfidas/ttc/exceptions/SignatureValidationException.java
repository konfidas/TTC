package de.konfidas.ttc.exceptions;

/**
 * Diese Exception wird aus der Methode assertSignatureOfLogMessageIsValid geworfen. Sie zeigt an,
 * dass bei der Prüfung der Signatur einer LogMessage ein Fehler aufgegtreten ist. Die Exception enthält
 * eine message mit weitere Infos und eine innerException, die auf die Ursache des Fehlers zeigt
 */
public class SignatureValidationException extends TtcException {
    public SignatureValidationException(String message, Exception reason){
        super(message,reason);
    }
}
