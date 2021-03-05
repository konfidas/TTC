/**
 * Diese Exception wird aus der Methode assertSignatureOfLogMessageIsValid geworfen. Sie zeigt an,
 * dass bei der Prüfung der Signatur einer LogMessage ein Fehler aufgegtreten ist. Die Exception enthält
 * eine message mit weitere Infos und eine innerException, die auf die Ursache des Fehlers zeigt
 */
public class SignatureValidationException extends Exception
{

    private String message;
    private Exception innerExcpetion;

    public SignatureValidationException(String message, Exception innerExcpetion){
        this.message = message;
        this.innerExcpetion = innerExcpetion;
    }
    public Exception getInnerExcpetion() {
        return innerExcpetion;
    }

    @Override
    public String getMessage() {
        return message;
    }

}
