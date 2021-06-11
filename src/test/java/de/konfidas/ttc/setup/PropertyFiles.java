package de.konfidas.ttc.setup;

import org.junit.Test;
import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;


public  class PropertyFiles {

    @Test
    public   void testContentOfPropertyFilesIsExistingDE() throws IOException{
    // List Of Properties can be created by
    // grep -RE "properties.getString.*" . | grep -oE "de\.konfidas.*\"" | cut -d '=' -f 2 | sed 's/\"$//' > listOfProperties.txt

        File file = new File(System.getProperty("user.dir") + "/src/main/resources/");
        URL[] urls = {file.toURI().toURL()};
        ClassLoader loader = new URLClassLoader(urls);
        Locale locale = new Locale("de", "DE");//NON-NLS

        ResourceBundle properties = ResourceBundle.getBundle("ttc", locale, loader);

        List<String> listOfProperties = Collections.emptyList();
        String inputFile= System.getProperty("user.dir") + "/testdata/"+"listOfProperties.txt";
        try { listOfProperties = Files.readAllLines(Paths.get(inputFile), StandardCharsets.UTF_8); } catch (IOException e) { throw new IOException(); }

            for (String property: listOfProperties){
                String a = properties.getString(property);
                int aaa=0;
            }

    }

    @Test
    public   void testContentOfPropertyFilesIsExistingEN() throws IOException{
        // List Of Properties can be created by
        // grep -RE "properties.getString.*" . | grep -oE "de\.konfidas.*\"" | cut -d '=' -f 2 | sed 's/\"$//' > listOfProperties.txt

        File file = new File(System.getProperty("user.dir") + "/src/main/resources/");
        URL[] urls = {file.toURI().toURL()};
        ClassLoader loader = new URLClassLoader(urls);
        Locale locale = new Locale("en", "US");//NON-NLS

        ResourceBundle properties = ResourceBundle.getBundle("ttc", locale, loader);

        List<String> listOfProperties = Collections.emptyList();
        String inputFile= System.getProperty("user.dir") + "/testdata/"+"listOfProperties.txt";
        try { listOfProperties = Files.readAllLines(Paths.get(inputFile), StandardCharsets.UTF_8); } catch (IOException e) { throw new IOException(); }

        for (String property: listOfProperties){
            properties.getString(property);
        }

    }

}
