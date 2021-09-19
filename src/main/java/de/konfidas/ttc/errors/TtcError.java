package de.konfidas.ttc.errors;

import java.text.MessageFormat;
import java.util.Locale;
import java.util.ResourceBundle;

public class TtcError extends Exception{
    protected TtcError(String message, Throwable cause){
        super(message, cause);
    }

    static Locale locale = new Locale("de", "DE"); //NON-NLS
    static ResourceBundle properties = ResourceBundle.getBundle("ttc",locale);//NON-NLS

    @Override
    public String toString(){
        if(this.getCause() != null) {
            return MessageFormat.format(properties.getString("de.konfidas.ttc.exceptions.cause"), getMessage(),getCause().toString());
        }else{
            return getMessage();
        }
    }
}
