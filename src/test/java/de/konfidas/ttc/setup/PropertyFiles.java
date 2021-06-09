package de.konfidas.ttc.setup;

import de.konfidas.ttc.exceptions.BadFormatForLogMessageException;
import de.konfidas.ttc.exceptions.LogMessageVerificationException;
import de.konfidas.ttc.messages.*;
import org.bouncycastle.asn1.ASN1Integer;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;
import java.util.*;

import static junit.framework.TestCase.fail;

public  class PropertyFiles {

    @Test
    public   void testContentOfPropertyFilesIsExisting() throws IOException{
    // List Of Properties can be created by
    // grep -RE "properties.getString.*" . | grep -oE "de\.konfidas.*\"" >

        File file = new File(System.getProperty("user.dir") + "/src/main/resources/");
        URL[] urls = {file.toURI().toURL()};
        ClassLoader loader = new URLClassLoader(urls);
        Locale locale = new Locale("de", "DE");//NON-NLS

        ResourceBundle properties = ResourceBundle.getBundle("ttc", Locale.getDefault(), loader);


//          ResourceBundle properties = ResourceBundle.getBundle("ttc",locale);//NON-NLS

        List<String> listOfProperties = Collections.emptyList();
        String inputFile= System.getProperty("user.dir") + "/testdata/"+"listOfProperties.txt";
        try { listOfProperties = Files.readAllLines(Paths.get(inputFile), StandardCharsets.UTF_8); } catch (IOException e) { throw new IOException(); }

            for (String property: listOfProperties){
                properties.getString(property);
            }




    }

}
