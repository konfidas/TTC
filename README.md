# TTC
----

Der (T)SE (T)ar File (C)hecker ist eine Java-Applikation für die Kommandozeile (in Form einer JAR Datei) zur Prüfung von Tar Dateien aus dem Export einer Technischen Sicherheitseinrichtung (TSE)

## Was kann TTC
- TAR Dateien aus dem Export einer TSE parsen
- Log-Messages aus der TAR Datei einlesen und auf Konformität zur ASN.1 Struktur prüfen, die in der [BSI TR-03151](https://www.bsi.bund.de/DE/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Technische-Richtlinien/TR-nach-Thema-sortiert/tr03151/tr03151_node.html) definiert wird
- Log-Messages auf ihre Inhaltsdaten prüfen (z.B. dass in einem Audit-Log das Feld seAuditData enthalten ist) 
- Die Signatur der Log-Messages prüfen (noch buggy)
- Zertifikate des TAR Archivs prüfen 

## Was kann TTC nicht
- Prüfung der Konsistenz des Verlaufs des Transaktionszählers (vielleicht später)
- Prüfung der Inhaltsdaten von Transaktionen 

## Das Ziel von TTC ist es
- ein einheitliches Verständnis zum Aufbau der Log-Messages gemäß [BSI TR-03151](https://www.bsi.bund.de/DE/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Technische-Richtlinien/TR-nach-Thema-sortiert/tr03151/tr03151_node.html) zu gewinnen,
- Spass an der Entwicklung zu haben,
- Als Framework und Building-Block für weitere Entwicklungen zu dienen

## Lizenz 
TTC steht unter der MIT Lizenz. 

## Parameter 

Erforderliche Parameter beim Aufruf 
```
 -i --inputTAR 	        Das zu prüfende TAR-Archiv

```

Optionale Parameter:

| Parameter               | Bedeutung                                                                                                                   |
|-------------------------|-----------------------------------------------------------------------------------------------------------------------------|
| -t --trustAnker         | Zertifikat der Root-Datei als .cer Datei. Wenn diese Parameter nicht angegeben wird, MUSS der Parameter -o verwendet werden |
| -o --overwriteCertCheck | Wenn dieser Parameter gesetzt wird, werden die Zertifikate in der TAR-Datei nicht auf die Root-CA zurückgeführt.            |
|                         |                                                                                                                             |

## Beispiele zur Verwendung

### Prüfe das tar-Archiv test.tar. Verwende die Datei trust.cer als Zertifikat der Root-CA
```
java -jar TTC.tar -i test.tar -t trust.cer
```

## Das JAR selbst bauen 
```
mvn package 
```
## Übersicht über die wichtigsten Klassen 
