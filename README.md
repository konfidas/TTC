# TTC
----
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![Maven Build](https://github.com/konfidas/TTC/actions/workflows/maven.yml/badge.svg)


Der (T)SE (T)ar File (C)hecker ist eine Java-Applikation für die Kommandozeile (in Form einer JAR Datei) zur Prüfung von Tar Dateien aus dem Export einer Technischen Sicherheitseinrichtung (TSE).

TTC konzentriert sich dabei auf die Prüfung von Aspekten, die in der Technischen Richtlinie BSI TR03153 definiert werden. Die Prüfung der eigentlichen Daten, die mit Hilfe der TSE gesichert werden (i.e. processData) liegen aktuell außerhalb des Fokus (Aber Unterstützung in diesem Bereich ist sicherlich willkommen). 

Die Motivation zu TTC entstammt der Arbeit mit verschiedenen TSE verschiedenere Hersteller. 

## Was kann TTC
- TAR Dateien aus dem Export einer TSE parsen
- Log-Messages aus der TAR Datei einlesen und auf Konformität zur ASN.1 Struktur prüfen, die in der [BSI TR-03151](https://www.bsi.bund.de/DE/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Technische-Richtlinien/TR-nach-Thema-sortiert/tr03151/tr03151_node.html) definiert wird
- Log-Messages auf ihre Inhaltsdaten prüfen (z.B. dass in einem Audit-Log das Feld seAuditData enthalten ist) 
- Die Signatur der Log-Messages prüfen (noch buggy)
- Zertifikate des TAR Archivs prüfen 

## Was kann TTC nicht
- Prüfung der Inhaltsdaten von Transaktionen 

## Das Ziel von TTC ist es
- ein einheitliches Verständnis zum Aufbau der Log-Messages gemäß [BSI TR-03151](https://www.bsi.bund.de/DE/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Technische-Richtlinien/TR-nach-Thema-sortiert/tr03151/tr03151_node.html) zu gewinnen,
- Spass an der Entwicklung zu haben,
- Als Framework und Building-Block für weitere Entwicklungen zu dienen

## Stand der Entwicklung
TTC liegt aktuell als Alpha-Version vor. Die geplanten Funktionen sind noch nicht vollständig implementiert. 

## Lizenz 
TTC steht unter der MIT Lizenz. 

## Argumente 

Erforderliche Argumente beim Aufruf 
```
Das zu prüfende TAR-Archiv. Es können auch mehrer TAR-Archive übergeben werden. Diese werden dann als ein Export behandelt. 

```

## Parameter:

| Parameter               | Bedeutung                                                                                                                   |
|-------------------------|-----------------------------------------------------------------------------------------------------------------------------|
| -t --trustAnker         | Zertifikat der Root-Datei als .cer Datei. Wenn diese Parameter nicht angegeben wird, MUSS der Parameter -n verwendet werden |
| -d --debug. .           | Wenn dieser Parameter gesetzt wird, wird das Logging-Level erhöht.                                                          |
| -n --noCertCheck.       | Wenn dieser Parameter gesetzt wird, werden die Zertifikate in der TAR-Datei nicht auf die Root-CA zurückgeführt.            |
| -h --help.              | Drucke Informationen zum Programm"                                                                                          |
| -e --errorsOnly.        | Wenn diese Option gesetzt wird, gibt TTC ausschließlich Informationen  über fehlerhafte Messages aus. Informationen über korrekte LogMessages werden unterdrückt.  |
| -g --generateHtmlReport.    | Generiere einen HTML Output. Bei der Verwendung dieses Parameters muss ein Dateiname für den Report mit angegeben werden |

| -v --validator.        | Benutze einen oder mehrere ausgewählte Validatoren. Mehrere Validatoren können durch Kommata getrennt angegeben werden. Die folgenden Validatoren stehen zur Verfügung: de.konfidas.ttc.validation.CertificateFileNameValidator, de.konfidas.ttc.validation.TimeStampValidator, de.konfidas.ttc.validation.SignatureCounterValidator, de.konfidas.ttc.validation.LogMessageSignatureValidator.    |





## Beispiele zur Verwendung

### Prüfe das tar-Archiv test.tar. Verwende die Datei trust.cer als Zertifikat der Root-CA
```
java -jar TTC.tar -i test.tar -t trust.cer
```

## Das JAR selbst bauen 
```
mvn package 
```
