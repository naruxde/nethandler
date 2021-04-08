# Protokoll definition
Der Client sendet wie folgt an den Server.

## Header
Der Kommunikationsheader besteht aus je einem Start- und Stopbyte (b),
welche den Header kapseln.

    Startbyte: 0x01 = Start of Heading
    Stopbyte:  0x17 = End of Transmission Block

Die Bytes 1-2 (CM) definieren den Befehl oder Typen, welcher die
Verarbeitung des Headers und ggf. der Nutzlast auf dem Server lenken. Es gibt
reservierte Befehle, die nicht mehr verwendet werden dürfen.

Darauf folgt ein nicht signierter 4 Byte langer Integerwert (IIII), der immer
die Länge der Nutzlast definiert, diese kann natürlich auch 0 sein.

Die folgenden 8 Bytes (00000000) sind frei für die jeweiligen
Befehle/Nachrichtentypen als Steuerflags oder Parameter verwendbar. In dem Fall
müsste kein Payload verwendet werden.

      b  |   CM     |       IIII       |             00000000             |   b  = 16 Byte

    \x01 | \x06\x4f | \x00\x00\x00\x00 | \x00\x00\x00\x00\x00\x00\x00\x00 | \x17 = 16 Byte

## Definierte Befehle / Typen (CM)

### Disconnect
Dies ist die letzte Nachricht eines Clients, welche dem Server erklärt, dass
die Verbindung geschlossen werden soll.
Es gibt keine Rückantwort, der Socket wird geschlossen.

    CM:       b'\x06\x04'
    IIII:     0
    00000000: b'\x00\x00\x00\x00\x00\x00\x00\x00'
    Nutzlast: -

    Antwort:  -


### Set timeout
Diese Nachricht konfiguriert den Timeout der Verbindung. Dieser ist auf dem
Server in der Standardeinstellung 5 Sekunden. Innerhalb des eingestellten
Timeouts muss mindestens eine "Reset timeout" Nachricht ausgetauscht werden.

    CM:       b'\x06\x43'
    IIII:     Anzahl der Millesekunden auf das der Timeout gestellt wird
    00000000: b'\x00\x00\x00\x00\x00\x00\x00\x00'
    Nutzlast: -

    Antwort:  b'\x01\x06\x4f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x17'


### Reset timeout (PING)
Diese Nachricht dient der Rücksetzung des Timeouts, wenn momentan keine anderen
Daten übertragen werden.

    CM:       b'\x06\x16'
    IIII:     0
    00000000: b'\x00\x00\x00\x00\x00\x00\x00\x00'
    Nutzlast: -

    Antwort:  b'\x01\x06\x4f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x17'


### Authentifizierung verwenden
Mit dieser Nachricht kann sich ein Client beim Server an und abmelden. Dabei
wird das Passwort als 32 Byte sha256 zusammen mit dem Benutzernamen im Klartext
als Payload übertragen.

#### Anmelden

    CM:       b'\x06\x41'
    IIII:     Länge von sha256 Passwort und UTF-8 Benutzernamen im Payload
    00000000:
              0:   b'\x01\'
              1-7: b'x00\x00\x00\x00\x00\x00\x00'
    Nutzlast: 32 Byte sha256 Passwort + UTF-8 Benutzername

    Serverantwort:
    CM:       b'\x06\x41'
    IIII:     0
    00000000:
              0:   b'\x01', wenn Benutzerdaten gültig, sonst b'\x00'
              1-7: b'\x00\x00\x00\x00\x00\x00\x00'
    Nutzlast: -

#### Abmelden

    CM:       b'\x06\x41'
    IIII:     0
    00000000: 
              0:   b'\x00'
              1-7: b'\x00\x00\x00\x00\x00\x00\x00'
    Nutzlast: -

    Serverantwort:
    CM:       b'\x06\x41'
    IIII:     0
    00000000:
              0:   b'\x00'
              1-7: b'\x00\x00\x00\x00\x00\x00\x00'
    Nutzlast: -


### Funktionsliste von Server anfordern
Diese Nachricht fordert die Liste aller möglichen Funktionen vom Server ab. Sie
können alle über "Funktion aufrufen" verwendet werden.

    CM:       b'\x06\x4c'
    IIII:     0
    00000000: b'\x00\x00\x00\x00\x00\x00\x00\x00'
    Nutzlast: -

    Serverantwort:
    CM:       b'\x06\x4f'
    IIII:     Länge der Nutzlast
    00000000: b'\x00\x00\x00\x00\x00\x00\x00\x00'
    Nutzlast: Pickled Python list with strings


### Funktion auf Server ausführen
Diese Nachricht führt eine registrierte Serverfunktion aus. Dabei wird sowohl
der Funktionsname, als auch die Positionsargumente und Schlüsselwortargumente
im Payload übertragen. Die Längen werden über IIII und 0000|0000 angegeben.

> ACHTUNG: Dieser Befehl ist zweistufig!
> Vor dem Versand der Nutzlast, sendet der Server eine Bestätigung. Nur wenn
> diese positiv ist, darf die Nutzlast übertragen werden.

Die Antwort ist das `pickled` Python-Objekt, welches die Funktion zurückgibt oder eine
`pickled` Exception.

    CM:       b'\x06\x46'
    IIII:     Länge des Funktionsnames, der als ASCII im Payload ist
    00000000:
              0-3: UINT Länge der pickled Positionsargumente <class 'tuple'>
              4-7: UINT Länge der pickled Schlüsselwortargumente <class 'dict'>
    Nutzlast: Noch nicht übertragen, sondern Serverantwort abwarten

    WENN b'\x01\x06\x4f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x17'
        Jetzt direkt die Nutzlast senden.
        Nutzlast: ASCII-Funktionsname
                  Pickled Positionsargumente <class 'tuple>
                  Pickled Schlüsselwortargumente <class 'dict'>

        Serverantwort ohne Exception:
        CM:       b'\x06\x4f'
        IIII:     Länge des pickled Rückgabeobjekt
        00000000: b'\x00\x00\x00\x00\x00\x00\x00\x00'
        Nutzlast: Pickled Python return value

    Serverantwort bei Exception:
        CM:       b'\x06\x45'
        IIII:     Länge der pickled Exception <class 'Exception>
        00000000: b'\x00\x00\x00\x00\x00\x00\x00\x00'
        Nutzlast: Pickled Python <class 'Exception>


### RAW Befehl an server senden
Mit dieser Funktion kann das Verhalten auf dem Server durch eigene Funktionen
überschrieben werden. Die Kommunikation von blob und payload passiert rein in
<class 'bytes'>.

Der CM kann frei gewählt werden von aa-zz / AA-ZZ. Für jeden CM muss eine
entsprechende Funktion auf dem Server registriert sein. Diese Funktion
erhählt die reinen Parameter (00000000) und den Payload als <class 'byte'>.
Die Rückgabewerte der Serverfunktion bestimmen ebenfalls die Parameter und
den Payload selbstständig.

    CM:       b'aa' - b'zz' und b'AA' - b'ZZ'
    IIII:     Länge des zu ledenen Payloads nach dem Heder
    00000000: Frei, wird direkt an die Serverfunktion übergeben
    Nutzlast: Frei, wird direkt an die Serverfunktion übergeben

    Serverantwort ohne Exception:
        CM:       b'\x06\x52'
        IIII:     Länge der Bytes des Payloads, die geladen werden müssen
        00000000: Zurückgegebener blob der eigenen Serverfunktion
        Nutzlast: Zurückgegebene bytes der eigenen Serverfunktion

    Serverantwort bei Exception:
        CM:       b'\x06\x58'
        IIII:     0
        00000000: b'\x00\x00\x00\x00\x00\x00\x00\x00'
        Nutzlast: -
