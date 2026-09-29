# CS2/PPPP-Kamera (EEE-…, CY365/365Cam) – Analyse

## Ursache: falscher Schlüssel

Der effektive 4-Byte-Schlüssel im alten Skript war `3c c4 66 2e` (aus
`SESSION_KEY 3103331d2f1a340635`). Richtig ist **`3c c4 68 0a`**. Ermittelt habe
ich ihn aus den im Skript eingebetteten App-Paketen: Für jedes Schlüsselbyte `j`
gibt es nur einen Wert, bei dem alle Bytes, deren vorheriges Chiffrat-Byte
`& 3 == j` ist, zu lesbarem JSON werden.

Mit dem falschen Schlüssel wird ungefähr jedes zweite Byte falsch ver- und
entschlüsselt. Daraus erklären sich alle bisher beobachteten „Eigenheiten“:

| Beobachtung im alten Skript | Tatsächlich (richtiger Schlüssel) |
|---|---|
| cmd `0xDE` / `0xDF` / `0xEE` / `0x4C` / `0xFE`, „Offset 0x0E“ | Standard-PPPP `0xD0` Drw, `0xD1` DrwAck, `0xE0` Alive, `0x42` P2pRdy, `0xF0` Close |
| Längenfeld „unzuverlässig“ (158, 20756) | Längenfeld stimmt immer (`f1 e0 00 00`) |
| keine H.264-Startcodes, unklare Fragment-Header | Nutzdaten waren teilweise falsch entschlüsselt |
| selbst gebaute JSON-/ACK-Pakete ohne Wirkung | kamen bei der Kamera als Datenmüll an |
| `LAN_SEARCH` unverschlüsselt, daher Port-Scan nötig | muss ebenfalls verschlüsselt gesendet werden |
| Replays funktionieren „manchmal“ | Replays tragen alte `cmd_idx`-Werte, frische Befehle mit gleichem idx wurden als Duplikat verworfen |

## Entschlüsselte App-Pakete (Login-Ablauf der App)

```
idx 0  {"pro":"check_user","cmd":100,"devmac":"0000","user":"admin","pwd":"6666"}
idx 1  {"pro":"set_datetime","cmd":126,...,"time":1790250653,"tz":-3600}
idx 2  get_attribute(103) + set_cypush(1)   (Cloud-Push, für Live-View unnötig)
idx 3  {"pro":"dev_control","cmd":102,"heart":1}
idx 4  {"pro":"stream","cmd":111,"video":1,"camsmode":0} + get_vol(134) + get_parms(101)
idx 5  {"pro":"get_cloudsupport","cmd":9000}
```
Hinweis: `set_cypush` enthält einen Cloud-Token (`cyToken`) und Push-Server-Daten.

Das ehemals rätselhafte „d10a“-ACK ist ein normales DrwAck:
`f1 d1 0008 | d1 01 0002 0652 0653` = Kanal 1 (Video), 2 Indizes.

## Neues Skript `cs2_live.py`

* korrekter Schlüssel, `--selftest` prüft ihn offline gegen die App-Pakete
* Discovery: verschlüsseltes LAN_SEARCH → PunchPkt → P2pRdy (kein Port-Scan)
* frische JSON-Befehle mit fortlaufendem `cmd_idx`, Wiederholung bis DrwAck
* jedes Drw der Kamera wird (gebündelt) per DrwAck bestätigt, Alive → AliveAck
* Video: Kanal 1, Frame beginnt mit `55 aa 15 a8` + 32-Byte-Header, Rest in
  aufeinanderfolgenden idx; 16-Bit-Überlauf wird korrekt behandelt
* Codec-Erkennung am ersten Frame (H.264 Annex-B oder MJPEG), ffplay startet
  mit passendem `-f`, Rohdaten zusätzlich in `stream_dump.h264|mjpeg`

Aufruf: `python3 cs2_live.py` (optional `--ip 192.168.10.1`).

## Noch offen / beim ersten echten Test prüfen

1. Die ersten 3 Frame-Header werden geloggt. Beginnen die Daten nach 32 Bytes
   nicht mit `00 00 00 01` bzw. `ff d8`, stimmt `VIDEO_HEADER_LEN` für dieses
   Modell nicht. Dann den Offset des Startcodes im Log ablesen.
2. Falls `detect_codec` „unknown“ meldet, verwendet die Kamera AVCC
   (Längenpräfix statt Startcodes). Den geloggten Hex-Dump prüfen.
3. `dev_control/heart` wird alle 10 s wiederholt. Ob das nötig ist, ist
   unbestätigt (`HEART_INTERVAL`).

## Steuerbefehle (LED, Infrarot) und Motion

Die Befehlsnummern stammen aus devbis/aiopppp (`JsonCommands`, `JsonSession`),
das dieselbe Kamerafamilie unterstützt:

| Eingabe während des Streams | gesendetes JSON |
|---|---|
| `led on` / `led off` | `{"pro":"dev_control","cmd":102,"lamp":1/0}` |
| `ir on` / `ir off` / `ir toggle` | `{"pro":"dev_control","cmd":102,"icut":1/0}` |
| `light on` / `light off` | `{"pro":"set_whiteLight","cmd":304,"status":1/0}` |
| `parms` | `get_parms` (101), enthält u. a. `lamp`, `icut`, `isShowIcutAuto` |
| `alarm` | `get_alarm` (107): Bewegungsalarm-Einstellungen |
| `raw {...}` | beliebiges JSON zum Ausprobieren |

Beim Start per Kommandozeile: `python3 cs2_live.py --led off --ir on`.

`ir toggle` nimmt den letzten bekannten `icut`-Wert aus `get_parms`.
`lamp` ist laut Feldname die Status-LED. aiopppp verknüpft seinen
„toggle-lamp“-Knopf allerdings mit `set_whiteLight`. Wenn `led off` die LED
nicht ausschaltet, `light off` probieren.

### Motion-Meldungen

Über die P2P-Verbindung ist keine Motion-Meldung dokumentiert. Die App
richtet mit `set_cypush` (Server `47.236.56.179:9093`, `isPushPic:1`) einen
Cloud-Push ein, darüber laufen die Alarme. Zwei Wege sind eingebaut:

1. **Unaufgeforderte Nachrichten:** Jede JSON-Nachricht auf Kanal 0, die keine
   Antwort auf eine eigene Anfrage ist, wird als `*** EVENT from camera`
   ausgegeben. Falls die Kamera Alarme auch an verbundene Clients schickt,
   erscheinen sie hier.
2. **`--push-listen` (experimentell):** schickt `set_cypush` mit der IP dieses
   PCs und lauscht auf TCP/UDP 9093. Alles, was ankommt, wird geloggt,
   enthaltene JPEGs landen als `motion_*.jpg`. Die App sendet bei jedem
   Verbinden wieder ihren eigenen `set_cypush`. Dadurch werden die
   App-Benachrichtigungen wiederhergestellt, und dieser Modus muss neu
   aktiviert werden.

Ob Bewegungserkennung eingeschaltet ist, sollte `alarm` (`get_alarm`, 107)
zeigen. **Auf der EEE-304142 antwortet die Kamera darauf nicht.** Das Skript
meldet das jetzt nach 3 s mit `no reply to 'get_alarm'`. Die Alarm-Befehle
dieses Modells sind also andere oder haben andere Nummern.

### Echte Befehle aus der App herausfinden

1. PCAPdroid auf dem Handy starten, die Kamera-App öffnen.
2. In der App die Bewegungserkennung aus- und wieder einschalten, die
   Empfindlichkeit ändern und die LED- bzw. IR-Einstellung umschalten.
3. Den Mitschnitt als `.pcap` exportieren und entschlüsseln:
   `python3 cs2_live.py --decode mitschnitt.pcap`

Der Decoder gibt jeden JSON-Befehl der App und jede Antwort der Kamera im
Klartext aus. Das sind genau die Befehle, die dann mit `raw {...}` gesendet
oder fest eingebaut werden können.

Mit `DEBUG_CMD_CHANNEL = True` im Skript wird zusätzlich jedes rohe Paket
auf dem Befehlskanal geloggt.
