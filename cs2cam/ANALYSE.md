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
| `rotate 0/1/2/3` | `{"pro":"dev_control","cmd":102,"rotmir":n}`: 0 normal, 1 gespiegelt, 2 gekippt, 3 beides (= 180°) |
| `set <feld> <wert>` | beliebiges `dev_control`-Feld, z. B. `set bright 5`, `set contrast 3` |
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

   Falls nichts ankommt:
   * Windows-Firewall: Python für „Private Netzwerke“ zulassen, sonst wird
     Port 9093 blockiert.
   * Die Antwort auf `set_cypush` prüfen: `<- JSON {'cmd': 1, 'result': 0}`
     bedeutet, dass die Kamera die Einstellung übernommen hat.
   * `*** PUSH: camera opened TCP connection` zeigt, ob die Kamera überhaupt
     Kontakt aufnimmt.
   * Akkukameras (diese meldet `power`/`charging`) lösen per PIR aus und
     pushen eventuell nur, wenn gerade niemand streamt. Zum Test den Stream
     schließen, das Skript mit `--push-listen` aber laufen lassen.

**Wichtig zur Befehlsreihenfolge:** Die Kamera führt Befehle auf Kanal 0
streng nach idx aus. Ein Paket, das nie ankommt, blockiert alle späteren
Befehle. Das Skript sendet deshalb unbestätigte Pakete so lange erneut, bis
die Kamera sie bestätigt, auch wenn sie ~40 s lang beschäftigt ist.

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

## Hänger der Kamera (EEE-304142, Firmware CYCAM_T99_v32_0226)

Beobachtet an der echten Kamera:

* Sie streamt MJPEG **sofort nach dem Verbindungsaufbau**, ohne `stream`-Befehl.
* Nach einem `stream` (111), während das Video schon läuft, beantwortet sie
  keine Befehle mehr. Einmal war das nach ~44 s vorbei, einmal hat sie sich
  ganz aufgehängt (Video stoppt, danach nicht mehr auffindbar). Alle danach
  gesendeten Befehle (`ir on`, …) wurden deshalb nie ausgeführt.
* Antworten beginnen mit `06 0a a1 80` statt `06 0a a0 80`. Das alte Skript hat
  deshalb die Antwort auf `check_user` verworfen.

Änderungen:

* Beim Vorspann werden nur `06 0a` geprüft, wie in aiopppp.
* Es ist immer nur ein Befehl unterwegs. Der nächste folgt erst, wenn der
  vorige bestätigt und beantwortet ist oder 3 s vergangen sind (wie aiopppp).
* `stream` wird nur gesendet, wenn 2 s nach dem Login noch kein Video da ist
  oder das Video 5 s ausbleibt. Manuell geht es mit `stream`.
* Kein periodisches `heart` mehr (`HEART_INTERVAL = 0`). Die App sendet es
  nur einmal.

`icut` beschreibt vermutlich den IR-Sperrfilter: `1` = Filter drin
(Tagbetrieb, IR-LEDs aus), `0` = Nachtbetrieb. Ob `ir on` die IR-LEDs
ein- oder ausschaltet, muss an der Kamera geprüft werden. Mit `ir 0`, `ir 1`
und `ir 2` probieren und jeweils `parms` abfragen.

**Korrektur (Log 13:41):** Nicht `stream`, sondern `get_parms` (101) blockiert
die Befehlsverarbeitung. `check_user`, `set_datetime` und `heart` werden sofort
beantwortet. Nach `get_parms` werden alle folgenden Befehle (`ir 0/1/2`,
`alarm`, `parms`) zwar per DrwAck bestätigt, aber nie beantwortet. Im 12:48-Log
kam die `get_parms`-Antwort nach 44 s, danach lief wieder alles.
Vermutung: Für `server_ver`/`upgrade` fragt die Kamera einen Update-Server im
Internet an und wartet im Kamera-WLAN (ohne Internet) auf den Timeout.
`get_parms` wird deshalb nicht mehr automatisch gesendet, nur noch mit `parms`
(mit Warnhinweis).

## Bild drehen

`get_parms` meldet `rotmir` (Rotation/Spiegelung). Bei `lamp` und `icut` ließ
sich ein Feld aus `get_parms` per `dev_control` mit gleichem Namen setzen. Nach
diesem Muster sendet `rotate n` den Wert `dev_control rotmir=n`. Die Werte 0–3
entsprechen aiopppps `VideoRotate` (normal / H / V / H+V). Ob die Firmware sie
genauso auslegt, ist an der Kamera zu prüfen. 90° kann der Sensor nicht.

Unabhängig davon dreht `--view-rotate 90|180|270` nur die Anzeige in ffplay.
Das funktioniert immer, ändert aber nicht die Bilder in der App oder in
`stream_dump.mjpeg`.

Nach einem Neustart der Kamera waren die langen Verzögerungen bei `icut` und
`get_parms` verschwunden. Die Kamera war vorher offenbar in einem gestörten
Zustand.

## Abbruch nach ~10 Minuten (Log 14:41–14:51)

Nach ~10 min stabilem Stream war die Kamera komplett stumm: keine Frames,
keine Keepalives, nicht einmal eine Bestätigung (DrwAck) für den neuen
`stream`-Befehl. Es kam auch kein Close-Paket. Mögliche Ursachen: Zeitlimit
für die Live-Ansicht einer Akkukamera, Schlafmodus, Absturz oder WLAN-Abbruch.
In diesem Lauf war das periodische `heart` abgeschaltet.

Änderungen:

* `heart` wird wieder alle 30 s gesendet (`HEART_INTERVAL = 30`). Die Kamera
  beantwortet es sofort.
* Kommt `CAMERA_SILENT` (10 s) lang kein Paket von der Kamera, baut das Skript
  die Verbindung komplett neu auf (neues Socket, LAN-Suche, Login). Das
  ffplay-Fenster bleibt offen, `--led`, `--ir` und `--rotate` werden erneut
  angewendet.
* `stream`-Anforderungen stapeln sich nicht mehr in der Warteschlange.
