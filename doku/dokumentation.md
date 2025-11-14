# Dokumentation Schulung Linux Nov 2025

## Benutzerkonten

### Root Acount

Der Benutzer `root` ist der *SuperUser* eines Linux Systems. Er ist der einzige Benutzer, welcher volle Rechte auf das System hat, also alles darf. Er muss auf jedem System existieren, damit dieses lauffähig ist, beispielsweise um während des Bootvorgangs einzelne Dienste zu starten usw.

### Reguläre Benutzer

Alle *regulären* Benutzer haben **eingeschränkte** Rechte. Sie dürfen z.B. nicht alle Kommandos ausführen oder generell irgendwelche Änderungen am System vornehmen. 

Im Hintergrund wird das mehr oder weniger alles über die Berechtigungen an Dateien geregelt.

Reguläre Benutzer können sich am System anmelden und interaktiv Kommandos ausführen. Dazu haben sie in der `/etc/passwd` eine *Login Shell* zugewiesen.

### Systembenutzer / Servicenutzer / Pseudobenutzer

Es gibt eine weitere Bentuzergruppe mit eingeschränkten Rechten. Das fällt uns auf, wenn wir die Datei `/etc/passwd` inspizieren. Die Mehrzahl der Benutzer haben wir gar nicht selbst angelegt, sie wurden automatisch vom System erzeugt, als bestimmte Dienste/Services installiert wurden.

Genau das ist der Sinn dieser Benutzer: So können bestimmte Dienste bzw. Prozesse mit deren Berechtigungen ausgeführt werden um die Sicherheit des Systems zu erhöhen. Ein kompromittierter Dienst erhält so also nicht direkt Zugriff auf das gesamte System.

Beispiel: `www-data` für Webserver wie *Apache oder Nginx* - selbst wenn ein Angreifer den Webserver übernimmt, kann er nicht auf andere Systemdateien zugreifen.

Pseudobenutzer haben keine Login-Shell, ihnen wird `/usr/sbin/nologin` zugewiesen. Sie können sich also nicht am System anmelden und Kommandos ausführen.

### Benutzer anlegen mit `useradd`

Mit `useradd` (auf allen Linux Systemen verfügbar) können wir Benutzer anlegen.

Obwohl ein Eintrag für ein Home-Verzeichnis in der `/etc/passwd` erzeugt wird, wird dies **nicht** angelegt
```bash
useradd <user>
```
Die Option `-m` bewirkt, dass unterhalb von `/home` ein Verzeichnis mit dem Namen des Benutzers erzeugt und alle Dateien aus `/etc/skel` dorthin kopiert werden.
```bash
useradd -m <user>
useradd --create-home <user>
```
Benutzer eine Login-Shell zuweisen
```bash
useradd -s /bin/bash <user>
useradd --shell /bin/bash <user>
```
Kommentarfeld für den vollen Namen des Benutzers und weitere Informationen
```bash
useradd -c "Voller Name des Benutzers" <user>
useradd --comment "Voller Name des Benutzers" <user>
```
Neuen User eine bestimmte Primäre Gruppe zuordnen:
```bash
useradd -g <primary-group> <user>
```
Neuen User einer Liste von zusätzlichen Gruppen zuordnen:
```bash
useradd -G <supplementary-group-1>,<supplementary-group-2> <user>
```
Standarbeispiel zum Anlegen eines Benutzers:
```bash
useradd -m -c "Tux Tuxedo" -s /bin/bash tux
```

useradd -p 
### Passwörter
Passwörter werden nicht in der `/etc/passwd` gespeichert, sondern in der Datei `/etc/shadow`. Dafür gibt es mindestens zwei Gründe:

1. Die Datei `/etc/passwd` muss von allen Usern auf dem System lesbar sein, wir wollen aber vermeiden, dass die Passwort-Hashes auslesbar sind
2. In der Datei `/etc/passwd` werden Informationen über die User gespeichert, in der `/etc/shadow` Informationen über Passwörter (*Separation of Concern*)

Passwörter liegen sind immer gehasht und zusätzlich gesaltet, d.h. dass vor dem Hashen des Passworts eine bestimmte zufällig generierte Zeichenkette vor das Passwort geschrieben und dann der kommplette String (Salt + Passwort) gehasht wird.

So wird zum einen vermieden, dass zwei gleiche Klartextpasswörter den gleichen Hash erhalten, zum anderen werden Attacken über *Rainbow Tables* (riesige Tabellen mit Hash-Werten und den dazugehörigen Klartextpasswörtern) vermieden.

Das Kommando `useradd` kann selbst keine Passwörter generieren! Wir rufen dazu nach dem Erstellen eines neuen Users das Kommando `passwd` auf.

>[!NOTE] 
> Wir können dem Benutzer auch bereits beim Erzeugen ein Passwort mitgeben. 

**Wichtig:** Hier muss ein für das System passender *gesaltener* HASH angegeben werden. Der Eintrag wird exakt so in die `/etc/shadow` eingetragen.
```bash
useradd -p "PASSWORDHASH" <user>
useradd --password "PASSWORDHASH" <user>
```
Schwer ist das nicht wirklich - wir können dazu das Kommando `openssl` verweden:
```bash
openssl passwd -6 PASSWORT
```
Die Option `-6` weist `openssl` an, den für Linux empfohlenen sicheren *SHA-512* Algorithmus zu verwenden.

In einem Rutsch sähe das folgendermassen aus:
```bash
useradd -m -c "User mit Passwort" -p $(openssl passwd -6 'My!Secret#Password') -s /bin/bash userwithpass
```
#### Relevante Dateien
Beim Anlegen von Benutzern passiert übrigens nur folgendes:

- Ein Eintrag in der `/etc/passwd` mit den Benutzerinformationen wird erzeugt
- Das Passwort wird in die `/etc/shadow` eingetragen
- Die primäre Gruppe wird zur `/etc/group` hinzugefügt (und eventuell andere Gruppenzugehörigkeiten angepasst)
- In der `/etc/gshadow` wird ein Eintrag ohne Passwort erzeugt (diese Datei bzw. Gruppenpasswörter werden eh nicht genutzt)

Nutzen wir die Option `-m` zum Anlegen eines Heimatverzeichnisses mit Standarddateien wird diese noch zusätzlich erstellt, alle Dateien aus `/etc/skel` dorhinein kopiert und die Berechtigungen angepasst.

Das war's. Nichts weiter. Keine Magie, nichts im Hintergrund. Nur Veränderung von Textdateien. Das ist ein gutes Beispiel dafür, wie die Konfiguration eines Linux System generell funktioniert. 

### passwd
Das Kommando ermöglicht die Änderung von Passwörtern. Mit Root-Rechten können so die Passwörter aller Benutzer geändert werden:
```bash
passwd <user>
```
Als regulärer Benutzer kann man damit sein eigenes Paswsort ändern:
```bash
passwd
```
Nutzen wir `useradd`, führen wir in der Regel dieses Kommando direkt im Anschluss aus, ansonsten hat der User kein Paswsort und kann sich nicht am System anmelden!

### chsh
Mit `chsh` kann ein Benutzer seine Login Shell selbst ändern bzw. kann `root` die Login Shells jedes Users ändern.
```bash
chsh -s /bin/bash
```
### Benutzerkonfiguration ändern

Mit dem Kommando `usermod` können wir die Benutzerkonfiguration nachträglich wieder ändern. Die Optionen sind denen von `useradd` sehr ähnlich. 

Ändern der Login Shell von `korni` zur `ksh`:

```bash
usermod -s /usr/bin/ksh korni
```
### adduser

`adduser` ist ein Perl-Skript, welches u.a. die Kommandos  `useradd` und `passwd` ausführt. Es ist *interaktiv*, wir brauchen keine Optionen zu übergeben, bestimmte Einstellungen werden abgefragt, vor allem fragt `adduser` direkt nach einem Passwort für den neuen Benutzer. Es sind andere Default-Werte gesetzt als bei `useradd`, z.B. die `bash` als Login-Shell.

Dieses Kommando ist aber standardmässig nur auf Debian-basierten Distributionen vorinstalliert.

#### Relevante Dateien
Beim Anlegen von Benutzern passiert übrigens nur folgendes:

- Ein Eintrag in der `/etc/passwd` mit den Benutzerinformationen wird erzeugt
- Das Passwort wird in die `/etc/shadow` eingetragen
- Die primäre Gruppe wird zur `/etc/group` hinzugefügt (und eventuell andere Gruppenzugehörigkeiten angepasst)
- In der `/etc/gshadow` wird ein Eintrag ohne Passwort erzeugt (diese Datei bzw. Gruppenpasswörter werden eh nicht genutzt)

Das war's. Nichts weiter. Keine Magie, nichts im Hintergrund. Nur Veränderung von Textdateien. Das ist ein gutes Beispiel dafür, wie die Konfiguration eines Linux System generell funktioniert. 

## Gruppen
Mit Gruppen können mehrere Benutzer zusammengefasst und ihnen gemeinsame Berechtigungen auf Dateien und Verzeichnisse gegeben werden.

Im Unterschied zu Windows können Gruppen nur einzelne Benutzer enthalten, keine weiteren Gruppen.

Für die Anzeige der Gruppenzugehörigkeiten kann man die Kommandos `groups` oder `id` benutzen.

#### Primäre Gruppe
Jeder Benutzer hat genau eine primäre Gruppe. Diese ist in `/etc/passwd` eingetragen. In der Regel hat sie den gleichen Namen wie der Benutzer. Sie ist nötig, da z.B. beim Erstellen von Dateien diese einem Benutzer und einer Gruppe zugewiesen werden.

#### Sekundäre Gruppen
Ein Benutzer kann aber auch mehreren zusätzlichen Gruppen angehören. Die Zugehörigkeiten sind in der `/etc/group` eingetragen.

### Gruppe erstellen:
Auf allen Linux Systemen existiert das Kommando `groupadd`
```bash
groupadd <gruppe>
```
### Benutzer einer Gruppe hinzufügen:
Auch die Gruppenzugehörigkeiten passen wir mit dem Kommando `usermod` an:
```bash
usermod -g <primary-group> <user>
usermod -G <absolute-list-of-supplementary-groups> <user>
usermod -G <group1>,<group2>,<group3>,<newgroup> <user>
usermod -aG <newgroup> <user>
```
Vorsicht mit der Option `-G`, diese erwartet eine absolute Liste von Gruppen, die der User angehören soll. Gehört der User einer Gruppe an, die hier nicht genannt ist, wird er aus dieser Gruppen entfernt.

Möchten wir einen User einer Gruppe hinzufügen, die bestehenden Gruppenzugehörigkeiten aber nicht verändern, nutzen wir zusätzlich die Opione `-a` (steht für `--append`).

Damit Gruppenzugehörigkeiten gültig werden, muss die Datei `/etc/group` neu eingelesen werden. Dies geschieht z.B. wenn der Benutzer muss sich neu anmeldet bzw. eine neue Login-Shell startet. 

Um die Gruppenzugehörigkeit in der aktuellen Shell zu aktualisieren, kann auch das Kommando `newgrp <gruppe>` genutzt werden.

## sudo

Mittels `sudo` (*Superuser do*) können Kommandos als ein anderer Benutzer ausgeführt werden. Standardmässig wird es genutzt, um als normaler Benutzer Root-Rechte zu erlangen, ohne sich als `root` anmelden zu müssen.

#### Vorteile von `sudo`

- Benutzer gibt sein **eigenes** Passwort ein, nicht das von `root`
- Passwort von `root` muss nicht geteilt werden (sehr sinnvoll bei mehreren Administratoren)
- sehr fein granulare Rechtevergabe möglich: z.B. als ein bestimmter Bentuzer nur bestimmte Kommandos ausführen etc.
- kann auch so konfiuriert werden, dass gar kein Passwort eingegeben werden muss (nur unter ganz bestimmten Bedingungen sinnvoll)
- das eingegebene Passwort wird für eine gewisse Zeit (15 min) gespeichert und muss nicht immer wieder eingegeben werden und muss nicht immer wieder eingegeben werden
- alle `sudo` Kommandos werden in `/var/log/auth.log` protokolliert und sind zusätzlich in der History der jeweiligen Benutzer
- es wird vermieden, dass Benutzer aus Faulheit dauerhaft eine Root-Shell offen haben

#### Nachteile von `sudo`
- `sudo` ist Software und Software ist **nie fehlerfrei**
- Sicherheitslücken in `sudo` könnten ausgenutzt werden
- könnte falsch/unsicher konfiguriert werden

#### Konfiguration
Generell erfolgt die Konfiguration in der Datei `/etc/sudoers`. Diese sollte **nie direkt** sondern **immer** mit dem Kommando `visudo` bearbeitet werden.

Best-Practice wäre es, eine weiter Config-Datei für z.B. weitere User oder Gruppen im Verzeichnis `/etc/sudoers.d` anzulegen.

Der einfachste Weg, einem User Root-Rechte mittels `sudo` zu gewähren, besteht darin, diesen User der Gruppe `sudo` bzw. `wheel` (je nach Distribution) hinzuzufügen.

Von einem Eintrag des/der User in die `/etc/sudoers` ist abzuraten, es sei denn, `sudo` soll feiner konfiuriert werden

Beispielkonfiguration für einen User, der nur den Webserver ohne Eingabe seines Passworts neu starten darf:
```bash
webbi   ALL = NOPASSWD: /usr/bin/systemctl reload apache2
```
>[!NOTE] 
> Falls man das vorherige Kommando erneut mit Root-Rechten ausführen will ist das Kommando `sudo !!` sehr nützlich. 
> 
> Das erste `!` steht für die History Expansion, das zweite für das vorherige Kommando.

## Cron

Cron ist ein Dienst, der Aufgaben (`cronjobs`) zu einem bestimmmten Zeitpunkt oder Zeitintervall automatisch ausführt. Cron wacht selbständig jede Minute auf, prüft bestimmte Dateien nach anstehenden Aufgaben und führt diese ggf. dann aus.

- `cronjobs` werden **nicht** nachgeholt, sollte der Rechner zu dem angegebenen Zeitpunkt aus sein, eignen sich also eher für Server als für Desktop Systeme
- Aufgaben werden in sog. `crontabs` festgelegt
- es gibt User `crontabs` für jeden Benutzer (auch für `root`) und eine systemweite `crontab` unter `/etc/crontab`
- diese unterscheidet sich von den User-crontabs (nur) dadurch, dass es eine zusätzliche Spalte für den auszuführeden Benutzer gibt
- in den Verzeichnissen `/etc/cron.hourly`, `/etc/cron.daily` usw. können Skripte abgelegt werden, die dann periodisch ausgeführt werden
- je nach Distribution können die Verzeichnisse auch `/etc/cron.d/daily` etc. heissen
- User crontabs liegen z.B. unter `/var/spool/cron/crontabs` (distributionsabhängig)
- die User crontab Dateien werden nicht direkt editiert, sondern mit dem Kommando `crontab -e`
- `crontab -r` löscht die crontab des aufrufenden Benutzers
- `crontab -l` zeigt den Inhalt der crontab an
- `root` kann eine User crontab mit dem Kommando `crontab -u <user> -e / -l / -r` editieren, auflisten oder löschen
- Informationen über den Aufbau und die Angabe von Zeiten/Intervallen sind in der Manpage zu finden: `man 5 crontab`, Informationen über das Kommando `crontab` unter `man crontab`
- in den Dateien `/etc/cron.allow` und `/etc/cron.deny` koenne Zugriffe auf den cron Daemon geregelt werden
- existiert die Datei `/etc/cron.allow` können _ausschliesslich_ die darin gelisteten Benutzer (einer pro Zeile) `cron` benutzen
- existiert die Datei `/etc/cron.deny` und *keine* `/etc/cron.allow` können alle *nicht* darin gelisteten Benutzer (einer pro Zeile) `cron` benutzen
- existieren beide Dateien, wird nur `/etc/cron.allow` ausgelesen

Format Angabe Zeitintervalle:
```
 .---------------- minute (0 - 59)
 |  .------------- hour (0 - 23)
 |  |  .---------- day of month (1 - 31)
 |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
 |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
 |  |  |  |  |
 *  *  *  *  * command to be executed
```
- Es können spezifische Zeitpunkte, Listen von Zeitpunkten (durch Komma getrennt), Bereiche (durch Minuszeichen getrennt) oder Intervalle (Angabe mit Slash `/`) angegebenen werden. Beispiele:

- `mon,tue,thu`    -> Montag, Dienstag und Donnerstag
- `mon-sat`        -> Montag bis Samstag
- `9-16`           -> 9 bis 16 Uhr
- `*/5`          -> alle fünf (z.B. Minuten)

## Systemd Timer

Systemd Timer sind eine moderne Alternative zu Cron-Jobs unter Systemd. Sie ermöglichen das zeitgesteuerte Ausführen von Diensten (Services). Ein Timer ist dabei ein spezieller Systemd-Unit, der einen zugehörigen Service zu bestimmten Zeitpunkten oder in definierten Intervallen aktiviert.

Ein grosser Unterschied ist hier, dass Timer über Systemd Unit Files konfiguriert werden. Diese sind einmal Unit Files mit der Endung `.timer`, in denen das Zeitintervall festgelegt wird.Für jeden Timer muss zusätzlich ein Service File vorliegen (`.service`), welches den Service beschreibt, der zu den im Timer angegebenen Zeitpunkt gestartet wird.

Timer und Service Files müssen den gleichen Namen (bis auf die Endung) haben.

**Beispiel:** 

Starte den Service `/etc/systemd/system/foobar.service` um 05:30 Uhr am ersten Montag jeden Monats. Falls der Rechner zu diesem Zeitpunkt nicht an sein sollte wird der Timer nachgeholt sobald der Rechner wieder startet (`Persistent=true`):
```
[Unit]
Description=Run the foobar service

[Timer]
OnCalendar=Mon *-*-1..7 05:30:00
Persistent=true

[Install]
WantedBy=timers.target
```
- Syntax bzw. Aufbau der `OnCalendar=` Einträge sind etwas anders als in Crontabs:
```
# DayOfWeek Year-Month-Day  Hour:Minute:Second

  Mon       *   - *    1..7 05:30:00

# Alternative Angaben:

  hourly
  daily
  weekly
  monthly
  yearly
```

generelle Syntax zu Zeitangaben in `systemd` in Manpage `man systemd.time`, spezifischer für Timer unter `CALENDAR EVENTS` bzw. ganz unten in der Manpage zu finden.

- Angabe der Spalte `DayOfWeek` ist optional
- `*`, `/` und `,` wie in crontabs
- mit `..` kann eine Range angegeben werden (wie `-` in crontabs)
- `timer` müssen wie `services` aktiviert bzw. gestartet werden:
```
systemctl enable foobar.timer
systemctl start foobar.timer

# Alternativ, aktiveren und starten in einem Kommando:
systemctl enable --now foobar.timer
```
- nach einer Änderung an den Unit Files muss noch das Kommando `systemctl daemon-reload` ausgeführt werden
- es können auch sog. _Monotonic Timers_ verwendet werden (`systemd-run`)
- diese werden nach Ablauf einer gewissen Zeit aktiviert (ähnlich wie `at`)

### Jobs einamlig zu einam bestimmten Zeitpunkt ausführen

#### at

Genau wie bei `cron` gibt es die Dateien `/etc/at.allow` und `/etc/at.deny` zur Steuerung der Zugansberechtigungen.

Die Angabe der Zeiten ist etwas anders als in Crontabs. 

Wir können `at` interaktiv nutzen, geben also nur den Zeitpunkt an und spezifiziern das Kommando anschliessend über eine Eingabeaufforderung.
```bash
at now +5min
at 9:00am
at 20251112
at 20251112 10:30am
at tomorrow 10am
```

Interaktiver Modus:
```bash
tux@debian-703:~$ at now +1min
warning: commands will be executed using /bin/sh
at Wed Nov 12 08:16:00 2025
at> date
at> <EOT>   # CTRL+D
job 4 at Wed Nov 12 08:16:00 2025
```
Möchten wir direkt ein Kommando oder Skript übergeben, nutzen wir die Option `-f`:
```bash
at -f ./some-script.sh now +5min
at -f /usr/bin/some-command now +5min
```
Anstehende Jobs anzeigen:
```bash
atq
at -l
```
Anstehenden Job wieder löschen:
```bash
atrm
at -d
at -r
```
Wollen wir sicherstellen, dass ein gewisser Job nur dann ausgeführt wird, wenn die Systemlast gering ist, können wir das Kommando `batch` nutzen.

#### systemd-run

Skript oder Kommanod in 2 Sekungen ausführen:
```bash
systemd-run --on-active 2 some-script-or-command
```

Skript oder Kommanod zu einem bestimmten Zeitpunkt ausführen:
```bash
systemd-run --on-calendar '2025-11-12 10:33:15` some-script-or-command
```

Skript oder Kommanod 10 Minuten nach dem Booten ausführen:
```bash
systemd-run --on-boot 10min some-script-or-command
```
>[!NOTE]
> Im Gegensatz zu `at` brauchen wir für `systemd-run` Root-Rechte.

## Logging

#### Programme zur Protokollierung

- `syslogd`: ältester Logging Dienst, heute so gut wie nicht mehr in Gebrauch
- `syslog-ng`: Nachfolger von `syslogd`
- `rsyslog`: lange Zeit Standard der meisten Distribution
- `journald`: bei Verwendung von `systemd`, unterscheidet sich technisch
  erheblich von den anderen

### Klassisches Logging mit rsyslog

- Konfiguration in Datei `/etc/rsyslog.conf` (nicht `/etc/rsyslogd.conf`)oder Dateien unterhalb von `/etc/rsyslog.d/`
- Dateien enthalten Regeln
- jede Zeile besteht aus den drei Komponenten: `facility.level action`:
  - `facility`: Einrichtung, die zu protokollierenden Eintrag erstellt
  - typisch sind: `auth, authpriv, cron, daemon, kern, lpr, mail, mark, news, syslog, user, uucp, local0` bis `local7`
  - Asterisk (`*`): alle Einträge
  - `local0` bis `local7`: wenn `Syslog` für eigene Programme verwendet werden soll
- `level`/`priority`: legt Protokollierungsgrad fest
  - `debug`: externer, in der Regel unnötiger Protokollierungsgrad
  - `info`: harmlose Informatinen
  - `notice`: ungefährliche Hinweise
  - `warning, warn`: normalerweise harmlos
  - `err, error`: z.B. Authentifizierungsfehler, I/O-Fehler ...
  - `crit`: Kritischer Fehler, sorgt immer für Probleme
  - `alert`: Alarm:> schwerwiegendes Problem
  - `emerg, panic`: (wenn überhaupt noch) als letzter Eintrag vor Systemcrash
  - `error, warn, panic` sind veraltet
- `action`: Bezeichnung etwas irreführend: ZIEL, in das das Facility protokollieren soll (normalerweise Datei, kann aber auch anderer Rechner, Benutzerliste)

Auszug aus `rsyslog.conf` (Sektion `RULES`):

```conf
###############
#### RULES ####
###############

# First some standard log files.  Log by facility.
#
auth,authpriv.*                 /var/log/auth.log
*.*;auth,authpriv.none          -/var/log/syslog
#cron.*                         /var/log/cron.log
daemon.*                        -/var/log/daemon.log
kern.*                          -/var/log/kern.log
lpr.*                           -/var/log/lpr.log
mail.*                          -/var/log/mail.log
user.*                          -/var/log/user.log

#
# Logging for the mail system.  Split it up so that
# it is easy to write scripts to parse these files.
#
mail.info                       -/var/log/mail.info
mail.warn                       -/var/log/mail.warn
mail.err                        /var/log/mail.err

#
# Some "catch-all" log files.
#
*.`debug;\
        auth,authpriv.none;\
	news.none;mail.none     -/var/log/debug
*.`info;*.`notice;*.`warn;\
	auth,authpriv.none;\
	cron,daemon.none;\
	mail,news.none          -/var/log/messages
```

- Logging kann auch auf einem entfernten Rechner erfolgen
- dazu muss das Zielsystem wie folgt vorbereitet werden um Remotelogging sowohl
  für UDP wie auch TCP zu unterstützten:
```conf
# provides UDP syslog reception
$ModLoad imudp
$UDPServersRun 514
# provides TCP syslog reception
$ModLoad imtcp
$TCPServersRun 514
```
- auf dem System, welches geloggt werden soll, muss folgende Zeile eingetragen werden:
```
*.* 192.168.9.88:513

*.* <IP Remote>:513
```
- es wird zusätzlich lokal geloggt
- die Daten sind nicht verschlüsselt

#### Log Dateien durchsuchen

- mit den bekannten Tools: `less`, `tail -f`, `grep` etc.

```bash
grep sshd /var/log/syslog | grep invalid | less
```
### Kernel Meldungen

Die Log Meldungen des Kernel aus dem sog. *Kernel Ring Buffer* können mit dem Kommando `dmesg` angezeigt werden. `dmesg` liest diese Daten direkt aus, sie sind also nach dem nächsten Reboot nicht mehr vorhanden.

Daher schreibt der Syslog zusätzlich in die Datei `/var/log/kern.log`.
 
### Log-Dateien rotieren mit `logrotate`

- `logrotate` überwacht Log-Dateien, um zu vermeiden, dass die Log-Dateien zu sehr anwachsen und unser Speichermedium füllen
- Die Konfiguration erfolgt unter `/etc/logrotate.conf` bzw. `/etc/logrotate.d` (hier legen
  üblicherweise Programme ihre eigene Konfiguration ab)

**Ablauf der Logroation:**

- `logrotate` benennt eine Logdatei nach Ablauf einer bestimmten Zeit um, bzw. fügt das Suffix `.1` an und erstellt eine neue (leere) Datei
- beim nächsten Durchgang erhält diese Datei den Suffix `.2.gz` und wird
  zusätzlich komprimiert
- Anzahl zu behaltener Dateien sowie Intervall sind konfigurierbar
- sollte täglich von `cron` ausgeführt werden

#### Auszug aus der Datei in `/etc/logrotate.d/rsyslog`:

```bash
/var/log/syslog
/var/log/mail.log
/var/log/kern.log
/var/log/auth.log
/var/log/user.log
/var/log/cron.log
{
        rotate 4
        weekly
        missingok
        notifempty
        compress
        delaycompress
        sharedscripts
        postrotate
                /usr/lib/rsyslog/rsyslog-rotate
        endscript
}
```

### Aktuelles Logging mit journald

- `journald` speichert bereits Meldungen aus dem sog. _Early Boot_, da es in `systemd` integriert ist und somit direkt startet 
- es wird **alles** geloggt, inkl. Metainformationen    
- arbeitet mit sog. _Trustet Facilities_, Einträge werden signiert/gesealt
- Log-Einträge lassen sich somit im Nachhinein nicht mehr ändern, ohne dass dies nachgewiesen werden kann    
- `journald` loggt nicht mehr in Textdateien, sondern in Datenbanken
- keine Logrotation, `journald` überwacht seine Größe selbst: max. 10% der HD bzw. max 4 GB
- als Kompatibilitätsschicht stellt `journald` die Funktion bereit, Log Meldungen an den `rsyslog` weiterzuleiten. Dazu muss in der Konfigurationsdatei `/etc/system/journald.conf` der Eintrag `ForwardToSyslog=yes` existieren und der Dienst `rsyslog` installiert sein und laufen
- ab Debian 12 ist kein `rsyslog` mehr installiert. Obiges Verhalten kann also durch Installation von `rsyslog` wiederhergestellt werden
- `systemd` ist generell modular aufgebaut, man kann also Teile/Module abschalten falls man das möchte
- Das Journal kann entweder in eine Datei auf der Festlplatte erstellt werden oder nur im RAM. Dazu gibt es folgende Einstellungen in der `/etc/systemd/journald.conf`:
  - `Storage=volatile`:  Das Journal besteht nur im RAM    
  - `Storage=auto`:  Journal besteht nur im RAM, es sei denn das Verzeichnis `/var/log/journal` existiert, dann werden darin die Datenbankdateien erstellt
- `Storage=persistent`: Logging auf der Platte, die Datei `/var/log/jounal` wird erstellt falls nicht vorhanden
  - `Storage=none`:  Logging nur auf der Konsole etc.
- `Seal=yes`: Log Meldungen werden _gesealt_, können also nicht unbemerkt verändert werden
- `SystemMaxUse`:  max. Speicherverbrauch definierbar (z.B. `2G`, `100M`)
- `man journald.conf`: Manpage der journald-Konfigurationsdatei

#### Abfrage des Journals

Als regulärer User kann man nicht alle Log Meldungen sehen. Dies kann man ändern, in dem man den Benutzer der Gruppe `adm` oder `systemd-journal` hinzufügt.

- `jounalctl`: zeigt das komplette journal im Pager `less` an
- `jounalctl --vacuum-size 50M`:  beschränkt das Journal auf 50 MB  
- `jounalctl --vacuum-time 2weeks`: löscht alle Einträge die älter sind als 2 Wochen
- `jounalctl --disk-usage`: gibt die aktuelle Größe des Journals aus
- `jounalctl --verify`: Prüft die Journal-Dateien auf interne Konsistenz, wichtig z.B. nach Verkleinerung, da hier zusammenhängende Logmeldungen erhalten bleiben, die Beschränkung der Größe erfolgt also nicht exakt, sondern logisch
- `jounalctl -b`, `journalctl -b 0`: Einträge des aktuellen Boots anzeigen
- `jounalctl -b -1`  Einträge des vorherigen Boots anzeigen. `-1` ist hier der Offset. Mit `3` würden z.B. die Meldungen des dritten Boots angezeigt werden.
- `journalctl --list-boots` zeigt eine Liste aller Bootvorgänge an
- `jounalctl --since "20 min ago"`  Meldungen der letzten 20 Min.   
- `journalctl --since yesterday`: Meldungen seit gestern   
- `journalctl --since '2023-12-01 12.55'` Meldungen seit diesem Zeitpunkt 
- `jounalctl --since '2023-12-01 12.55' --until'2023-12-01 13.55'` Meldungen zwischen diesen Zeitpunkten
- Zeitangaben stehen in der Manpage von `systemd.time` -> einheitliche Syntax in `systemd` (also wie bei z.B. Timern)
- `jounalctl -n` (_new_) 10 neuste Einträge anzeigen (analog zu `tail`)
- `jounalctl -n 20` 20 neuste Einträge
- `jounalctl -e` (_end_) ans Ende des Logs springen  
- `jounalctl -r`  (_reverse_) umgedrehte Reihenfolge  
- `jounalctl -k` (_kernel_) Kernelmeldungen  
- `jounalctl -p err` (_priority errors_) Angabe der Priority / des Log-Levels _error_
- `jounalctl -u apache2` (_unit_) Anzeigen der Meldungen des _Units_ Apache2 (unter `systemd` ist alles ein _Unit_: Dienste (services), targets, mounts, device, sockets etc.)
- `jounalctl /dev/sda` zeigt Meldungen des Geräts `/dev/sda` an  
- `jounalctl _UID 1000`  Einträge des Nutzers mit der UID 1000
- `jounalctl _PID 1`  Einträge des Prozesses mit der PID 1
- etc.

All diese Filteroptionen können natürlich auch noch miteinander kombiniert werden. Zusätzlich lassen sich auch noch die klassischen Fitler wie `grep`, `head`, `tail` usw. nutzen, dazu sollte `journalctl` aber die Option `--no-pager` übergeben werden.

Auch bei Verwendung von `journald` können die Daten auf einen Server zentralisiert gespeichert werden    

Möchte man auf ein Journal einer anderen Maschine zugreifen, so kann man entweder die _Machine ID_ angeben, oder ein Verzeichnis, in dem sich das Journal befindet:

- `journalctl --file`<machine-id>`
- `journalctl -D /var/log/journal/<machine-id>`
- `cat /etc/machine-id` die Machine-ID ausgeben lassen
- Die Machine-ID kennzeichnet ein System eindeutig, ähnlich wie eine UID, PID etc.

### Selbst Ereignisse loggen

#### logger

- ursprünglich für `rsyslog`
- kann aber auch Einträge ins Journal schreiben

      logger -t Backup "Datensicherung erfolgreich"

      tail -n 1 /var/log/syslog

#### systemd-cat

     echo "Log as you can" | systemd-cat -t backup-script -p info

     journalctl -e -n 1


## SSH

- Client-Server Architektur (Client: `ssh`, Server: `sshd`)
- SSH ist ein _Dienst_ oder _Service_ bzw. ein _Darmon_

### SSH Client

Verbindung zu einem SSH Server:
```bash
 ssh <user>@<ip-adresse>
 ssh tux@10.0.1.2
```
Zusätzlich kann der Port angegeben werden:
```bash
 ssh -p <port> <user>@<ip-adresse>
 ssh -p 2222 tux@10.0.1.2
```
Bzw. der verwendete SSH-Key:
```bash
 ssh -i <pfad-zum-private-key> <user>@<ip-adresse>
 ssh -i ~/.ssh/id_rsa tux@10.0.1.2
```
Um all diese Angaben nicht jedes Mal beim Anmelden machen zu müssen, kann eine Konfgurationsdatei (`~/.ssh/config`) auf dem Client erstellt werden mit z.B. folgendem Inhalt:
```bash
Host debian-server
  HostName 10.0.1.2
  User tux
  Port 2222
  IdentityFile ~/.ssh/id_rsa
```

Die Anmeldung am Server kann dann folgendermaßen erfolgen:

    ssh debian-server

Bei Problemen mit der Anmeldung kann es sinnvoll sein, sich die Anmeldeinformationen _verbose_ ausgeben zu lassen, dies kann in drei Leveln geschehen:

    ssh -v debian-server
    ssh -vv debian-server
    ssh -vvv debian-server

### SSH Server

Status des SSH Servers prüfen:
```bash
 systemctl status ssh.service     # je nach System (z.B. Debian)
 systemctl status sshd.service    # je nach System
```
SSH Server neu starten (z.B. nach Änderung der Konfgurationsdatei):

```bash
 sudo systemctl restart apache2
```
Die Konfgurationsdatei des SSH-Servers befindet sich unter:
```bash
 /etc/ssh/sshd_config
```
Hier können u.a. der verwendete Port, die Zugriffsmöglichkeiten (Passwort, PublicKey etc), erlaubte IP-Adressen, Netze, Benutzer usw. konfiguriert werden.

Die Datei enthält die auskommentierten Standardeinstellungen. Obwohl auskommentiert gelten diese. So ist trotz folgenden Zeilen sowohl der Port 22 also auch die PubkeyAuthentication eingeschaltet:
```bash
# Port 22
# PubkeyAuthentication yes
```
Um **ausschließlich** die Anmeldung per PublicKey zuzulassen, wird folgende Zeile geändert:

    PasswordAuthentication yes

auf

    PasswordAuthentication no

Weiterhin darf die PubkeyAuthentication nicht verboten sein, folgendes wäre z.B. falsch:

    PubkeyAuthentication no 

**WICHTIG:** Wir testen unsere Konfiguration, bevor wir die Änderungen übernehmen, wir lassen also immer ein Shell mit einer bestehenden SSH-Verbindung offen. Um die neue Konfiguration zu übernehmen starten wir den SSH Server neu, bestehende Verbindugen bleiben davon unberührt, bzw. laufen mit der alten Konfiguration weiter.

### Public Key Authentication

Zur **Authentifizierung** mittels Privat-/Public Key muss auf dem **Client** ein Schlüsselpaar als der Benutzer von dem aus wir uns anmelden wollen erzeugt werden mit:

    ssh-keygen

Das Kommando ist interaktiv. Hier kann auch ein anderen Name für den Schlüssel angegeben werden (mit einem absoluter Pfad), z.B. `~/.ssh/debian-server`.

Mit dem optional einzugebenden Passwort wird der Private Key zusätzlich verschlüsselt und muss bei Benutzung jedes Mal entschlüsselt werden. Für die Praxis ist das sehr sinnvoll, in bestimmten Fällen nur sollte auf die Angabe eines Passwsorts verzichtet werden (z.B. Key für Automatisierungen o.ä.). 

#### SSH-Agent

Zur Vereinfachung kann der entschlüsselte Schlüssel mit dem `ssh-agent` verwaltet werden.

##### Windows 

Windows 10/11 bringt den **OpenSSH Authentication Agent** mit. So muss die Passphrase nicht jedes Mal eingeben werden:
```powershell
Get-Service ssh-agent
# Falls gestoppt:
Set-Service -Name ssh-agent -StartupType Automatic
Start-Service ssh-agent
# Schlüssel dem SSH Agent hinzufügen
ssh-add $env:USERPROFILE\.ssh\id_ed25519
```
##### Linux

Sollte der SSH-Agent noch nicht laufen, können wir ihn für die aktuelle Session/Shell mit folgendem Kommando aktivieren:

    eval $(ssh-agent)

Schlüssel können dann hinzugefügt werden:

    ssh-add ~/.ssh/id_ed25519

Soll der SSH-Agent automatisch beim Starten der BASH gestartet werden, können wir folgende Zeilen in die `~/.bashrc` einfügen:
```bash
if [ -z "$SSH_AUTH_SOCK" ]; then
   eval $(ssh-agent -s)
   ssh-add ~/.ssh/id_rsa
fi
```
In der Regel läuft er auf Systemd-basierten Systemen aber schon. Prüfen lässt sich das mit:

    echo $SSH_AUTH_SOCK

Noch komfortabler ist die Verwendung von `keychain`. Hiermit können wir global pro User SSH und GPG Schlüssel verwalten. Beim ersten Start einer Shell werden wir dazu aufgefordert, die verwalteten Schlüssel zu entschlüsseln, diese sind danach in allen weiteren Shells bzw. sogar systemweit gültig.

Installation mit z.B.:

    apt install keychain

Start durch z.B. `~/.bashrc`:
```bash
eval $(keychain --eval --quiet id_rsa id_ed25519)
```

### PublicKey auf Server übertragen

Nach der Erzeugung des Schlüsselpaares muss der *öffentliche* Schlüssel noch auf den Server übertragen und in die Datei `~/.ssh/authorized_keys` des Benutzers eingetragen werden, als der wir uns am Zielsystem anmelden wollen.

Wir wollen sicherstellen, dass die Schlüssel geschützt sind und folgende Berechtigungen auf das Verzeichnis `.ssh` und die Datei `authorized_keys` gesetzt sind:
```bash
chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys
```
Hierzu kann (auf Linux Systemen) z.B. das Kommando `ssh-copy-id` benutzt werden, welches den Vorgang für uns automatisiert.

Manuell wären u.a. folgende Schritte denkbar:

1. Öffentlichen Schlüssel mit `scp` auf das Zielsystem kopieren:
    ```bash
    scp ~/.ssh/id_rsa.pub tux@10.0.1.2:
    ```
Wichtig ist hier der Doppelpunkt (`:`) hinter der IP-Adresse, ansonsten arbeitet `scp` lokal (genau wie `cp`) und würde eine Datei mit Namen `tux@10.0.1.2` erzeugen.

2. Nun melden wir uns per Passwort am Zielsystem an und fügen den Inhalt der kopierten Datei an die Datei `~/.ssh/authorized_keys` an:
    ```bash
    cat ~/id_rsa.pub >> ~/.ssh/authorized_keys
    ```
3. In der Datei `authorized_keys` befindet sich jeweils ein öffentlicher Schlüssel pro Zeile.

Obiges Vorgehen ist auch in einem Schritt vom Client (wo wir den Key erstellt haben) aus möglich:
```bash
cat ~/id_rsa.pub | ssh tux@10.0.1.1 "mkdir -p .ssh && cat >> .ssh/authorized_keys"
```
### Kommandos über SSH ausführen

Normalerweise starten wir per SSH eine interaktive Shell auf dem Zielsystem. Wir können aber auch lediglich ein Kommando ausführen und die SSH Verbindung anschliessend wieder trennen:

    ssh tux@10.0.1.1 <some-command>
    ssh tux@10.0.1.1 ls

### Nur das ausführen bestimmter Kommandos per SSH erlauben

Wir können sogar noch weiter gehen und einem bestimmten User den interaktiven Login komplett verbieten und nur die Ausführung eines bestimmten Kommandos erlauben. Dazu tragen wir das Kommando wie folgt in die `~/.ssh/authorized_keys` ein:
```bash
command="some-command" id_ed25519 AAAAB3NzaC1yc2EAAAADAQABAAACAQ...
```
Möchten wir die Auführung mehrerer Kommandos erlauben, müssten wir entweder für jedes Kommando einen eigenen Key erstellen, oder wir schreiben ein kleines Wrapper-Skript wie folgt:
```bash
#!/bin/bash
# /usr/local/bin/ssh-wrapper.sh

case "$SSH_ORIGINAL_COMMAND" in
    "ls -la")
        ls -la
        ;;
    "df -h")
        df -h
        ;;
    "uptime")
        uptime
        ;;
    *)
        echo "Kommando nicht erlaubt: $SSH_ORIGINAL_COMMAND"
        exit 1
        ;;
esac
```
In `~/.ssh/authorized_keys`:
```
command="/usr/local/bin/ssh-wrapper.sh" ssh-rsa AAAAB3...
```
Mehrere Keys mit verschiedenen Kommandos:
```
command="ls -la" ssh-rsa AAAAB3NzaC1... key1
command="df -h" ssh-rsa AAAAB3NzaC1... key2
command="uptime" ssh-rsa AAAAB3NzaC1... key3
```
>[!NOTE]
> Die Beschränkung auf die Ausführung eines bestimmten Kommandos kann gerade in Verbindung mit einer entsprechenden `sudo`-Konfiguration sinnvoll sein.

## GPG

GPG kann verwendet werden, um:

- Dateien symmetrisch (mit Passwort) zu verschlüsseln
- Dateien asymmetrisch (mit Keys) zu verschlüsslen
- Dateien zu signieren

### Symmetrische Verschlüsselung

#### Verschlüsselung
```bash
gpg --symmetric geheim.txt
```
- GPG fragt nach einem Passwort.
- Die Datei `geheim.txt` wird verschlüsselt und als `geheim.txt.gpg` gespeichert.
- Wir könnten aber auch einen anderen Dateinamen über die Option `-o` angeben:
```bash
gpg -o geheim-verschluesselt.gpg --symmetric geheim.txt
```
#### Entschlüsselung
```bash
gpg --decrypt geheim.txt.gpg # Ausgabe nur in der Shell
gpg --decrypt geheim.txt.gpg > entschluesselt.txt
```
Hinweis: Falls keine Passwortabfrage erscheint, liegt das daran, dass GPG bzw. der GPG-Agent das eingegebene Passwort für eine bestimmte Zeit speichert. Im Gegensatz zu SSH läuft der GPG-Agent automatisch.


### Asymmetrische Verschlüsselung

#### Schlüsselpaar erstellen
Wir generieren ein GPG-Schlüsselpaar mit:
```bash
gpg --full-generate-key
```
GPG fragt dann nach bestimmten Angaben:

1. Typ: z.B. `1` (RSA und RSA) -> Wir nutzen RSA sowohl für die Verschlüsselung als auch für die Signierung.
2. Schlüssellänge: `3072` (Standard), `4096` ginge auch.
3. Ablaufdatum: `0` (kein Ablauf). Hier könnte auch z.B. `1y` oder `2y` angegeben werden.
4. Name, E-Mail und Kommentar.
5. Passwort für den privaten Schlüssel.

Der erstellten Schlüssel kann überprüft werden, bzw. werden uns damit alle verfügbaren Public-Keys angezeigt:
```bash
gpg --list-keys
```
#### Öffentlichen Schlüssel exportieren und teilen

Um einer anderen Person die Möglichkeit zu geben, eine Datei für uns zu verschlüsseln, müssen wir unseren Public-Key exportieren. Im Gegensatz zu SSH liegt dieser nämlich nicht als Textdatei vor.

Öffentlichen Schlüssel als ASCII exportieren:
```bash
gpg --export --armor "<Name oder E-Mail>" > public.key
# besser, da theoretisch mehrere Schlüssel für die gleich E-Mail/Name existieren könnten:
gpg --export --armor "<Key-ID>" > public.key
```
Die Option `--armor` sorgt dafür, dass der Public-Key im ASCII Format ausgegeben wird und nicht als Binärdatei.
 
#### Öffentlichen Schlüssel importieren
Wir können einen öffentlichen Schlüssel wie folgt in uneren Keyring importierten:
```bash
gpg --import public.key
```
#### Datei asymmetrisch verschlüsseln
Wollen wir eine Datei asymmetrisch verschlüsseln, müssen wir den/die Personen/Schlüssel angeben, **für die** diese Datei verschlüsselt wird:
```bash
gpg --encrypt --recipient "<Name/E-Mail/ID der anderen Person>" geheim.txt
```
Wir können auch mehrere Personen angeben in dem wir die Option `--recipient` mehrfach verwenden:
```bash
gpg --encrypt --recipient "<ID Person1>" --recipient "<ID Person2>" geheim.txt
```
Lassen wir die Option `--recipient` weg, werden wir interaktiv nach Empfängern gefragt.

#### 2.5. Datei entschlüsseln
Entschlüsseln können wir auch hier mit `--decrypt`:
```bash
gpg --decrypt geheim.txt.gpg > entschluesselt_asym.txt
```
#### Datei signieren
In der Regel wollen wir eine verschlüsselte Datei zusätzlich signieren (z.B. Backups). Dies machen wir mit der Option `--sign`:
```bash
gpg --encrypt --sign geheim.txt
```
- Die signierte Datei wird als `geheim.gpg` erstellt.

Wollen z.B. eine Textdatei signieren und das ASCII Format beibehalten, nutzen wir die Option `--clear-sign`:
```bash
gpg --clar-sign geheim.txt
```
- Die signierte Datei wird als `geheim.txt.asc` erstellt.

#### 3.2. Signatur überprüfen
```bash
gpg --verify geheim.txt.gpg
```
- GPG zeigt an, ob die Signatur gültig ist und von welchem Schlüssel sie stammt.
- Die Überprüfung erfolgt mit dem jeweiligen **öffentlichen** Schlüssel.

Damit das Signieren bzw. Überprüfen der Signatur funktioniert, müssen wir ggf. das *Trust Level* des jeweiligen Keys bearbeiten. Dazu nutzen dazu das Kommando `gpg --edit-key <Key-ID / E-Mail des importierten PubKeys>`. Es startet eine interaktive Shell von GPG. Das Kommando `help` zeigt alle verfügbaren Kommandos an. Wir geben `trust` ein und setzen das Trust-Level auf z.B. `5 = I trust ultimately`.

>[!NOTE]
> Mit dem Trust-Level geben wir auch an, wie sehr wir der jeweiligen Person **im Umgang mit GPG an sich** vertrauen. Siehe [Web-Of-Trust](https://de.wikipedia.org/wiki/Web_of_Trust)

## Basic Network Troubleshooting

### Netzwerkschnittstellen konfigurieren mit `ip`

Das Kommando `ip` aus dem `iproute2` Paket ist das moderne Werkzeug zur Netzwerkkonfiguration unter Linux. Es ersetzt die alten `net-tools` Kommandos wie `ifconfig`, `route` und `netstat`.

#### Netzwerkschnittstellen anzeigen

Alle Netzwerkschnittstellen auflisten:
```bash
ip link show
ip link
ip l
```

Detaillierte Informationen inkl. IP-Adressen anzeigen:
```bash
ip address show
ip addr show
ip addr
ip a
```

Informationen zu einer bestimmten Schnittstelle:
```bash
ip addr show dev eth0
ip a s eth0
```

#### Netzwerkschnittstellen aktivieren/deaktivieren

Schnittstelle aktivieren:
```bash
ip link set eth0 up
```

Schnittstelle deaktivieren:
```bash
ip link set eth0 down
```

#### IP-Adressen konfigurieren

IP-Adresse hinzufügen:
```bash
ip addr add 192.168.1.100/24 dev eth0
```

IPv6-Adresse hinzufügen:
```bash
ip addr add 2001:db8::1/64 dev eth0
```

IP-Adresse entfernen:
```bash
ip addr del 192.168.1.100/24 dev eth0
```

>[!NOTE]
> Alle mit `ip` vorgenommenen Änderungen sind **nicht persistent**! Nach einem Neustart sind die Änderungen verloren. Für persistente Konfiguration müssen die Netzwerkkonfigurationsdateien des Systems angepasst werden (z.B. `/etc/network/interfaces` bei Debian oder `/etc/netplan/` bei Ubuntu mit Netplan).

### Routing konfigurieren

#### Routing-Tabelle anzeigen

Aktuelle Routing-Tabelle ausgeben:
```bash
ip route show
ip route
ip r
```

Ausführliche Informationen:
```bash
ip route show table all
```

Route zu einem bestimmten Ziel anzeigen:
```bash
ip route get 8.8.8.8
```

#### Default-Gateway setzen

Standard-Route (Default-Gateway) hinzufügen:
```bash
ip route add default via 192.168.1.1
```

Standard-Route löschen:
```bash
ip route del default
```

#### Statische Routen hinzufügen

Route zu einem bestimmten Netzwerk:
```bash
ip route add 10.0.0.0/8 via 192.168.1.254
```

Route über ein bestimmtes Interface:
```bash
ip route add 172.16.0.0/16 dev eth1
```

Route löschen:
```bash
ip route del 10.0.0.0/8
```

### Netzwerkverbindungen prüfen

#### ping - Erreichbarkeit testen

Host per ICMP erreichen:
```bash
ping 192.168.1.1
ping google.com
```

Anzahl der Pakete begrenzen:
```bash
ping -c 4 8.8.8.8
```

IPv6 Ping:
```bash
ping6 2001:4860:4860::8888
ping -6 google.com
```

Ping-Intervall anpassen:
```bash
ping -i 0.5 192.168.1.1  # alle 0.5 Sekunden
```

#### traceroute - Routenverfolgung

Den Weg zu einem Zielhost nachverfolgen:
```bash
traceroute google.com
traceroute 8.8.8.8
```

IPv6 Traceroute:
```bash
traceroute6 google.com
```

Mit ICMP statt UDP (benötigt Root-Rechte):
```bash
traceroute -I google.com
```

#### Wie funktioniert traceroute?

`traceroute` zeigt den Weg (Route), den Pakete durch das Netzwerk zu einem Zielhost nehmen. Es nutzt die TTL (Time To Live) im IP-Header, um jeden Router auf dem Weg sichtbar zu machen.

**Funktionsweise:**
1. Sendet Pakete mit TTL=1, TTL=2, TTL=3, usw.
2. Jeder Router verringert TTL um 1
3. Bei TTL=0 sendet der Router eine ICMP "Time Exceeded" Nachricht zurück
4. So wird jeder Hop auf dem Weg sichtbar

**Beispielausgabe von traceroute:**
```bash
$ traceroute google.com
traceroute to google.com (142.250.185.46), 30 hops max, 60 byte packets
 1  192.168.1.1 (192.168.1.1)  2.847 ms  2.623 ms  2.498 ms
 2  10.0.0.1 (10.0.0.1)  8.234 ms  8.112 ms  7.998 ms
 3  172.16.254.1 (172.16.254.1)  15.456 ms  15.334 ms  15.221 ms
 4  * * *
 5  142.251.51.187 (142.251.51.187)  22.334 ms  22.198 ms  22.087 ms
 6  142.250.185.46 (142.250.185.46)  23.445 ms  23.312 ms  23.201 ms
```

**Erklärung der Ausgabe:**

- Erste Spalte: Hop-Nummer (Anzahl der Router)
- Zweite Spalte: Hostname und IP-Adresse des Routers
- Letzte 3 Spalten: Round-Trip-Time (RTT) von 3 Testpaketen
- `* * *`: Router antwortet nicht (Firewall/ICMP blockiert)

**Verschiedene Protokolle:**

Standardmäßig nutzt `traceroute` UDP-Pakete:
```bash
traceroute google.com
```

ICMP-Pakete verwenden (wie Windows `tracert`):
```bash
traceroute -I google.com
```

TCP-Pakete verwenden:
```bash
traceroute -T -p 80 google.com  # Port 80 (HTTP)
```

**Nützliche Optionen:**
```bash
traceroute -n google.com           # keine DNS-Auflösung (schneller)
traceroute -q 1 google.com         # nur 1 Paket pro Hop (statt 3)
traceroute -m 15 google.com        # max. 15 Hops (statt 30)
traceroute -w 2 google.com         # 2 Sek. Timeout (statt 5)
traceroute -f 5 google.com         # bei Hop 5 starten
```

#### tracepath - Alternative zu traceroute

`tracepath` ist ähnlich wie `traceroute`, hat aber wichtige Unterschiede:

**Hauptunterschiede:**

| Merkmal | traceroute | tracepath |
|---------|-----------|-----------|
| Root-Rechte nötig | Ja (für ICMP/TCP) | Nein |
| Protokoll | UDP/ICMP/TCP wählbar | Nur UDP |
| MTU Discovery | Nein | Ja (automatisch) |
| Optionen | Viele | Wenige |
| Verbreitung | Überall | Moderne Linux-Systeme |

**Beispielausgabe von tracepath:**
```bash
$ tracepath google.com
 1?: [LOCALHOST]                      pmtu 1500
 1:  192.168.1.1                       2.847ms 
 2:  10.0.0.1                          8.234ms 
 3:  172.16.254.1                     15.456ms 
 4:  no reply
 5:  142.251.51.187                   22.334ms 
 6:  142.250.185.46                   23.445ms reached
     Resume: pmtu 1500 hops 6 back 6
```

**Erklärung der Ausgabe:**

- `pmtu 1500`: Path MTU (Maximum Transmission Unit) = 1500 Bytes
- `1?:`: Hop-Nummer, `?` bedeutet unvollständige Informationen
- `no reply`: Router antwortet nicht
- `reached`: Ziel erreicht
- `Resume:`: Zusammenfassung (MTU, Anzahl Hops)

**MTU Discovery mit tracepath:**

Ein großer Vorteil von `tracepath` ist die automatische MTU-Erkennung:
```bash
$ tracepath -n google.com
 1:  192.168.1.1                       2.847ms 
 2:  10.0.0.1                          8.234ms pmtu 1492
 3:  172.16.254.1                     15.456ms 
```

Hier sehen wir, dass die MTU auf 1492 Bytes reduziert wird (typisch für PPPoE-Verbindungen).

**Nützliche Optionen:**
```bash
tracepath -n google.com          # keine DNS-Auflösung
tracepath -b google.com          # zeigt IP und Hostname
tracepath -l 1400 google.com     # initiale Paketgröße 1400
tracepath -m 20 google.com       # max. 20 Hops
tracepath -p 33434 google.com    # Start-Port (Standard)
```

IPv6 Tracepath:
```bash
tracepath6 google.com
```

#### Wann welches Tool verwenden?

**Nutze `traceroute` wenn:**
- Du Root-Rechte hast
- Du ICMP oder TCP statt UDP nutzen musst (manche Firewalls blockieren UDP)
- Du mehr Kontrolle über die Parameter brauchst
- Du mit älteren Unix-Systemen arbeitest

**Nutze `tracepath` wenn:**
- Du keine Root-Rechte hast
- Du MTU-Probleme diagnostizieren willst
- Dir die Basis-Funktionalität ausreicht
- Du ein schnelles, einfaches Tool brauchst

**Praktische Einsatzszenarien:**

1. **Netzwerk-Pfad ermitteln:**
```bash
traceroute -n 8.8.8.8  # Schnell und ohne DNS
```

2. **MTU-Probleme finden:**
```bash
tracepath google.com   # Zeigt wo MTU sich ändert
```

3. **Firewall-Tests:**
```bash
traceroute -I google.com    # ICMP
traceroute -T -p 443 google.com  # HTTPS-Port
```

4. **Verbindungsqualität prüfen:**
```bash
traceroute -q 10 google.com  # 10 Pakete pro Hop für bessere Statistik
```

5. **Problem in bestimmtem Bereich eingrenzen:**
```bash
traceroute -f 5 -m 10 google.com  # Nur Hops 5-10 testen
```

>[!NOTE]
> Viele moderne Firewalls und Router blockieren ICMP-"Time Exceeded"-Nachrichten oder antworten nicht auf Traceroute-Anfragen. Das führt zu `* * *` in der Ausgabe. Dies ist ein Sicherheitsfeature, kein Fehler. Das Ziel kann trotzdem erreichbar sein.

### Vergleich: traceroute vs tracepath vs ping

Alle drei Tools nutzen verschiedene Aspekte des ICMP-Protokolls:

```bash
# Ist das Ziel erreichbar?
ping -c 4 google.com

# Welchen Weg nehmen die Pakete?
traceroute google.com

# Wo sind MTU-Probleme im Pfad?
tracepath google.com
```

**Typische Troubleshooting-Reihenfolge:**

1. **Ping** → Ist das Ziel überhaupt erreichbar?
2. **Traceroute/Tracepath** → Wo ist die Verbindung langsam oder blockiert?
3. **Ping zu einzelnen Hops** → Welcher Router verursacht Probleme?
4. **MTU-Test mit tracepath** → Gibt es Fragmentierungs-Probleme?

### Socket-Statistiken mit `ss`

Das moderne Kommando `ss` (Socket Statistics) ersetzt das veraltete `netstat` und zeigt Informationen über Netzwerkverbindungen, Routing-Tabellen, Interface-Statistiken etc.

Alle Sockets anzeigen:
```bash
ss -a
```

Nur lauschende (listening) Sockets:
```bash
ss -l
```

TCP-Verbindungen:
```bash
ss -t
```

UDP-Verbindungen:
```bash
ss -u
```

Mit Prozessinformationen (benötigt Root):
```bash
ss -tap
ss -tulnp  # UDP, TCP, listening, numeric, mit Prozessen
```

Nützliche Optionen:
- `-a`: alle Sockets
- `-l`: nur listening
- `-t`: TCP
- `-u`: UDP
- `-n`: numerisch (keine Namensauflösung)
- `-p`: Prozessinformationen
- `-e`: erweiterte Informationen
- `-s`: Statistiken

Beispiel - alle lauschenden TCP-Ports mit Prozessen anzeigen:
```bash
sudo ss -tlnp
```

### Hostname konfigurieren

Aktuellen Hostnamen anzeigen:
```bash
hostname
```

Hostnamen persistent setzen (systemd):
```bash
hostnamectl set-hostname neuer-hostname
```

Alle Hostname-Informationen anzeigen:
```bash
hostnamectl
```

FQDN (Fully Qualified Domain Name) anzeigen:
```bash
hostname -f
```

### Netcat - das Netzwerk-Schweizer-Taschenmesser

`netcat` (oder `nc`) ist ein vielseitiges Werkzeug zum Lesen und Schreiben von Netzwerkverbindungen über TCP oder UDP.

Port-Test - ist ein Port erreichbar?
```bash
nc -zv 192.168.1.1 80
nc -zv google.com 443
```

Mehrere Ports scannen:
```bash
nc -zv 192.168.1.1 20-80
```
Wir können `nc` auch zum "Nachrichtenaustauch" (unverschlüsselt) zwischen zwei Rechnern einsetzen. `server1` ist der *Listener*:

```bash
nc -l 8080
```

`server2` verbindet sich mit diesem:
```bash
nc server1 8080
```
Der im Terminal von `server2` eingegebe Text erscheint im Terminal von `server1`.

Analog dazu können wir sogar Dateien über das Netzwerk übertragen:
```bash
# Empfänger (Server):
nc -l 9999 > empfangene_datei.txt

# Sender (Client):
nc 192.168.1.100 9999 < zu_sendende_datei.txt
```

UDP statt TCP:
```bash
nc -u 192.168.1.1 53
```

### Legacy net-tools Kommandos

>[!NOTE]
> Die folgenden Kommandos sind veraltet, werden aber noch in der LPIC-1 Prüfung abgefragt. Auf modernen Systemen sollten die `iproute2` Kommandos bevorzugt werden.

#### ifconfig - Netzwerkschnittstellen konfigurieren

Alle Interfaces anzeigen:
```bash
ifconfig
ifconfig -a
```

Bestimmtes Interface anzeigen:
```bash
ifconfig eth0
```

IP-Adresse setzen:
```bash
ifconfig eth0 192.168.1.100 netmask 255.255.255.0
```

Interface aktivieren/deaktivieren:
```bash
ifconfig eth0 up
ifconfig eth0 down
```

#### route - Routing-Tabelle anzeigen/bearbeiten

Routing-Tabelle anzeigen:
```bash
route
route -n  # numerisch, ohne DNS-Auflösung
```

Default-Gateway setzen:
```bash
route add default gw 192.168.1.1
```

Route hinzufügen:
```bash
route add -net 10.0.0.0/8 gw 192.168.1.254
```

Route löschen:
```bash
route del -net 10.0.0.0/8
```

#### netstat - Netzwerkstatistiken

Alle Verbindungen anzeigen:
```bash
netstat -a
```

Listening Ports:
```bash
netstat -l
```

TCP-Verbindungen mit Programmnamen:
```bash
netstat -tap
```

Routing-Tabelle:
```bash
netstat -r
```

Interface-Statistiken:
```bash
netstat -i
```

### Häufige Netzwerkprobleme debuggen

#### 1. Keine Netzwerkverbindung

Schritt-für-Schritt Diagnose:

```bash
# 1. Interface-Status prüfen
ip link show

# 2. IP-Konfiguration prüfen
ip addr show

# 3. Gateway erreichen?
ping -c 3 192.168.1.1

# 4. DNS funktioniert?
ping -c 3 google.com

# 5. Routing-Tabelle prüfen
ip route show

# 6. Firewall-Regeln prüfen
sudo iptables -L -n
```

#### 2. Langsame Verbindung

MTU-Probleme testen:
```bash
ping -M do -s 1472 8.8.8.8  # MTU 1500 testen
```

Paketloss prüfen:
```bash
ping -c 100 8.8.8.8 | grep loss
```

#### 3. Port-Probleme

Prüfen, ob ein Port lokal lauscht:
```bash
sudo ss -tlnp | grep :80
```

Von außen testen:
```bash
nc -zv example.com 80
```
## Client-seitige DNS-Konfiguration

### Lokale Namensauflösung mit `/etc/hosts`

Die Datei `/etc/hosts` ermöglicht statische Zuordnungen von Hostnamen zu IP-Adressen, die vor DNS-Anfragen ausgewertet werden.

Format der `/etc/hosts`:
```bash
# IP-Adresse    Hostname    [Aliase]
127.0.0.1       localhost
127.0.1.1       debian-server
192.168.1.10    webserver   web
192.168.1.20    database.local.lan  db
::1             localhost ip6-localhost ip6-loopback
```

Beispiel - lokale Entwicklungsumgebung:
```bash
127.0.0.1       dev.myapp.local
127.0.0.1       api.myapp.local
```

>[!NOTE]
> Einträge in `/etc/hosts` haben Vorrang vor DNS-Anfragen (standardmäßig). Dies kann über `/etc/nsswitch.conf` konfiguriert werden.

### DNS-Konfiguration mit `/etc/resolv.conf`

Die Datei `/etc/resolv.conf` enthält die Konfiguration für die DNS-Namensauflösung.

Typischer Aufbau:
```bash
# DNS-Server
# Maximal drei Einträge für nameserver
nameserver 8.8.8.8
nameserver 8.8.4.4
nameserver 2001:4860:4860::8888

# Suchdomain für unqualifizierte Namen
search example.com local.lan

# Alternative zu search (nur Angabe eine Domain möglich)
domain example.com

# Optionen
options timeout:2 attempts:3
```

Wichtige Optionen:
- `nameserver`: DNS-Server IP-Adresse (max. 3)
- `search`: Liste von Domains für Hostname-Suche
- `domain`: Lokale Domain (veraltet, besser `search` nutzen)
- `options timeout:n`: Timeout in Sekunden
- `options attempts:n`: Anzahl der Versuche

>[!NOTE]
> Auf Systemen mit `systemd-resolved` wird `/etc/resolv.conf` oft automatisch generiert und ist ein Symlink nach `/run/systemd/resolve/stub-resolv.conf`. Manuelle Änderungen gehen bei Neustart verloren!

### Reihenfolge der Namensauflösung mit `/etc/nsswitch.conf`

Die Datei `/etc/nsswitch.conf` (Name Service Switch) bestimmt die Reihenfolge und Quellen für verschiedene Systemdatenbanken, einschließlich Hostname-Auflösung.

Relevante Zeile für DNS:
```bash
hosts:      files dns
```

Dies bedeutet:
1. Zuerst `/etc/hosts` prüfen (`files`)
2. Dann DNS-Server anfragen (`dns`)

Weitere mögliche Einträge:
```bash
hosts:      files mdns4_minimal [NOTFOUND=return] dns mdns4
```

Erklärung:
- `files`: `/etc/hosts`
- `dns`: DNS-Server aus `/etc/resolv.conf`
- `mdns4`: Multicast DNS (Avahi/Bonjour)
- `[NOTFOUND=return]`: Abbruch bei bestimmten Ergebnissen

Andere Service-Einträge:
```bash
passwd:     files systemd
group:      files systemd
shadow:     files
```

### DNS-Abfragen mit `host`

`host` ist ein einfaches DNS-Lookup-Tool:

Standard-Abfrage (A-Record):
```bash
host google.com
```

Alle Record-Typen:
```bash
host -a google.com
```

Reverse-Lookup (IP zu Hostname):
```bash
host 8.8.8.8
```

Bestimmten DNS-Server nutzen:
```bash
host google.com 8.8.8.8
```

Spezifische Record-Typen:
```bash
host -t MX google.com    # Mail-Server
host -t NS google.com    # Nameserver
host -t TXT google.com   # TXT-Records
host -t AAAA google.com  # IPv6-Adresse
```

Ausführliche Ausgabe:
```bash
host -v google.com
```

### DNS-Abfragen mit `dig`

`dig` (Domain Information Groper) ist das mächtigste DNS-Abfrage-Tool:

Einfache Abfrage:
```bash
dig google.com
```

Kurze Ausgabe (nur Antwort):
```bash
dig google.com +short
```

Bestimmten Record-Typ abfragen:
```bash
dig google.com A      # IPv4
dig google.com AAAA   # IPv6
dig google.com MX     # Mail-Server
dig google.com NS     # Nameserver
dig google.com TXT    # TXT-Records
dig google.com SOA    # Start of Authority
```

Bestimmten DNS-Server nutzen:
```bash
dig @8.8.8.8 google.com
dig @1.1.1.1 example.com
```

Reverse-Lookup:
```bash
dig -x 8.8.8.8
```

Trace der DNS-Delegation:
```bash
dig +trace google.com
```

Alle Informationen:
```bash
dig google.com ANY
```

Nützliche Optionen:
```bash
dig +short           # Kurze Ausgabe
dig +noall +answer   # Nur Antwort-Sektion
dig +tcp             # TCP statt UDP
dig +dnssec          # DNSSEC-Informationen
```

Batch-Abfragen:
```bash
dig google.com facebook.com twitter.com
```

### Name Service Abfragen mit `getent`

`getent` (Get Entries) fragt die NSS-Datenbanken ab und respektiert die Konfiguration in `/etc/nsswitch.conf`:

Hostname auflösen (berücksichtigt `/etc/hosts` und DNS):
```bash
getent hosts google.com
getent hosts 8.8.8.8
```

Alle Hosts aus `/etc/hosts`:
```bash
getent hosts
```

Benutzerinformationen:
```bash
getent passwd root
getent passwd
```

Gruppeninformationen:
```bash
getent group sudo
```

Services und Ports:
```bash
getent services ssh
getent services 80
```

>[!NOTE]
> Im Gegensatz zu `dig` und `host` nutzt `getent` die komplette System-Konfiguration inkl. `/etc/hosts` und `/etc/nsswitch.conf`. Es zeigt also das Ergebnis, das auch Anwendungen erhalten würden.

### systemd-resolved

Auf modernen Systemd-basierten Distributionen wird DNS oft durch `systemd-resolved` verwaltet.

Status anzeigen:
```bash
systemctl status systemd-resolved
```

DNS-Statistiken und Konfiguration:
```bash
resolvectl status
```

DNS-Cache leeren:
```bash
resolvectl flush-caches
```

DNS-Abfrage über systemd-resolved:
```bash
resolvectl query google.com
```

Statistiken anzeigen:
```bash
resolvectl statistics
```

Konfigurationsdatei:
```bash
/etc/systemd/resolved.conf
```

Beispiel-Konfiguration:
```conf
[Resolve]
DNS=8.8.8.8 1.1.1.1
FallbackDNS=8.8.4.4 1.0.0.1
Domains=~.
DNSSEC=allow-downgrade
DNSOverTLS=opportunistic
```

Nach Änderungen Service neu starten:
```bash
sudo systemctl restart systemd-resolved
```

### DNS-Probleme debuggen

Typische Fehlersuche bei DNS-Problemen:

```bash
# 1. Ist der DNS-Server erreichbar?
ping -c 3 8.8.8.8

# 2. DNS-Konfiguration prüfen
cat /etc/resolv.conf

# 3. NSS-Konfiguration prüfen
grep hosts /etc/nsswitch.conf

# 4. /etc/hosts prüfen
cat /etc/hosts

# 5. DNS-Abfrage testen
dig google.com
host google.com

# 6. Unterschied zwischen DNS und NSS testen
dig google.com +short      # Nur DNS
getent hosts google.com    # DNS + /etc/hosts

# 7. Bei systemd-resolved
resolvectl status
resolvectl query google.com

# 8. DNS-Cache leeren
sudo resolvectl flush-caches  # systemd-resolved
sudo systemd-resolve --flush-caches  # ältere Systeme
```

Häufige Probleme:

**Problem 1: Name wird nicht aufgelöst**
- `/etc/resolv.conf` leer oder falsch
- DNS-Server nicht erreichbar
- Firewall blockiert Port 53
- `systemd-resolved` nicht aktiv

**Problem 2: Nur manche Namen funktionieren**
- `/etc/hosts` überschreibt DNS
- Split-DNS Konfiguration
- Falsche `search`-Domain

**Problem 3: Langsame Auflösung**
- DNS-Server antwortet langsam
- IPv6-Timeouts bei IPv4-only Netzwerk
- Zu viele Nameserver konfiguriert

**Problem 4: Unterschiedliche Ergebnisse**
- `dig` ignoriert `/etc/hosts`
- `getent` respektiert NSS-Konfiguration
- Cache-Unterschiede

### Persistente Netzwerkkonfiguration

#### Debian/Ubuntu mit `/etc/network/interfaces`

```bash
# Loopback
auto lo
iface lo inet loopback

# DHCP
auto eth0
iface eth0 inet dhcp

# Statische IP
auto eth1
iface eth1 inet static
    address 192.168.1.100
    netmask 255.255.255.0
    gateway 192.168.1.1
    dns-nameservers 8.8.8.8 8.8.4.4
    dns-search example.com
```

Nach Änderungen:
```bash
sudo systemctl restart networking
# oder
sudo ifdown eth0 && sudo ifup eth0
```

**Interface-Verwaltung mit ifup und ifdown:**

Die Kommandos `ifup` und `ifdown` aktivieren bzw. deaktivieren Netzwerkschnittstellen basierend auf der Konfiguration in `/etc/network/interfaces`.

Einzelnes Interface starten:
```bash
sudo ifup eth0
```

Einzelnes Interface stoppen:
```bash
sudo ifdown eth0
```

Interface neu starten (Konfiguration neu laden):
```bash
sudo ifdown eth0 && sudo ifup eth0
```

Alle konfigurierten Interfaces starten:
```bash
sudo ifup -a
```

Verbose-Modus (detaillierte Ausgabe):
```bash
sudo ifup -v eth0
```

Konfiguration testen ohne Ausführung:
```bash
sudo ifup --no-act eth0
```

>[!NOTE]
> `ifup` und `ifdown` funktionieren **nur** mit Interfaces, die in `/etc/network/interfaces` konfiguriert sind. Sie lesen diese Datei und wenden die dort definierten Einstellungen an. Für dynamisch konfigurierte Interfaces (z.B. über DHCP oder NetworkManager) müssen andere Tools verwendet werden.

**Wichtige Hinweise:**
- `ifup`/`ifdown` sind Debian/Ubuntu-spezifische Wrapper-Skripte
- Sie sind höhere Abstraktionen über `ip link set up/down`
- Bei Verwendung von NetworkManager oder systemd-networkd haben sie oft keine Wirkung
- Auf Red Hat/CentOS gibt es ähnliche Kommandos, aber die Konfiguration erfolgt anders

**Die Direktive `auto` in `/etc/network/interfaces`:**

Interfaces mit `auto` werden beim Systemstart automatisch aktiviert:
```bash
auto eth0    # Interface startet beim Booten
iface eth0 inet dhcp
```

Ohne `auto` muss das Interface manuell mit `ifup` gestartet werden.

#### Ubuntu mit Netplan

**Was ist Netplan?**

Netplan ist das moderne Netzwerk-Konfigurationstool für Ubuntu (ab 17.10) und nutzt YAML-Dateien statt der klassischen `/etc/network/interfaces`. Netplan ist ein Abstraktionslayer, der die Konfiguration an den eigentlichen *Renderer* (NetworkManager oder systemd-networkd) weitergibt.

**Vorteile von Netplan:**

- Einfache, lesbare YAML-Syntax
- Unterstützt verschiedene Backend-Renderer
- Einheitliche Konfiguration für Desktop und Server
- Validierung vor dem Anwenden

**Konfigurationsdateien:**

Netplan-Dateien liegen unter `/etc/netplan/` und haben die Endung `.yaml`:
```bash
/etc/netplan/01-netcfg.yaml
/etc/netplan/50-cloud-init.yaml
```

Die Dateien werden alphabetisch verarbeitet.

**Beispiel-Konfiguration:**

```yaml
network:
  version: 2
  renderer: networkd  # oder 'NetworkManager' für Desktop
  ethernets:
    eth0:
      dhcp4: yes
      dhcp6: yes
    eth1:
      addresses:
        - 192.168.1.100/24
      routes:
        - to: default
          via: 192.168.1.1
      nameservers:
        addresses:
          - 8.8.8.8
          - 8.8.4.4
        search:
          - example.com
```

>[!NOTE]
> Ab Ubuntu 22.04 (und neueren Versionen) wurde `gateway4` durch `routes` ersetzt. Die alte Syntax funktioniert zwar noch, wird aber als deprecated markiert.

**Erweiterte Beispiele:**

Mehrere IP-Adressen auf einem Interface:
```yaml
network:
  version: 2
  ethernets:
    eth0:
      addresses:
        - 192.168.1.100/24
        - 192.168.1.101/24
        - 10.0.0.50/8
      routes:
        - to: default
          via: 192.168.1.1
```

Statische Route zu einem Netzwerk:
```yaml
network:
  version: 2
  ethernets:
    eth0:
      addresses:
        - 192.168.1.100/24
      routes:
        - to: default
          via: 192.168.1.1
        - to: 10.0.0.0/8
          via: 192.168.1.254
```

VLAN-Konfiguration:
```yaml
network:
  version: 2
  ethernets:
    eth0:
      dhcp4: no
  vlans:
    vlan10:
      id: 10
      link: eth0
      addresses: [192.168.10.100/24]
```

WiFi-Konfiguration:
```yaml
network:
  version: 2
  renderer: NetworkManager
  wifis:
    wlan0:
      access-points:
        "SSID-Name":
          password: "geheimes-passwort"
      dhcp4: yes
```

**Netplan-Kommandos:**

Konfiguration anwenden:
```bash
sudo netplan apply
```

Konfiguration testen (automatischer Rollback nach 120 Sekunden):
```bash
sudo netplan try
```

Syntax der YAML-Datei überprüfen:
```bash
sudo netplan generate
```

Debugging-Informationen anzeigen:
```bash
sudo netplan --debug apply
```

Aktuellen Status anzeigen:
```bash
netplan status
```

**Renderer: networkd vs NetworkManager**

Netplan nutzt einen von zwei Renderern:

**systemd-networkd** (Standard für Server):
```yaml
network:
  version: 2
  renderer: networkd
```

**NetworkManager** (Standard für Desktop):
```yaml
network:
  version: 2
  renderer: NetworkManager
```

Der Renderer bestimmt, welches Backend die Netzwerkkonfiguration tatsächlich umsetzt.

**Troubleshooting:**

Netplan-Logs anzeigen:
```bash
sudo journalctl -u systemd-networkd
sudo journalctl -u NetworkManager
```

Generierte Konfiguration prüfen:
```bash
ls -la /run/systemd/network/
cat /run/systemd/network/10-netplan-*.network
```

Netplan zurücksetzen:
```bash
sudo netplan apply
# oder manuell die Services neu starten:
sudo systemctl restart systemd-networkd
```

#### Red Hat/CentOS/Rocky Linux mit NetworkManager

**NetworkManager Übersicht:**

Red Hat Enterprise Linux (RHEL), CentOS, Fedora, Rocky Linux und AlmaLinux nutzen standardmäßig **NetworkManager** zur Netzwerkverwaltung. Dies gilt sowohl für Desktop- als auch für Server-Systeme.

**Hauptkommando: nmcli**

`nmcli` (NetworkManager Command Line Interface) ist das primäre Werkzeug zur Netzwerkkonfiguration:

**Grundlegende Befehle:**

Status aller Geräte anzeigen:
```bash
nmcli device status
nmcli dev status
nmcli d
```

Ausgabe:
```
DEVICE  TYPE      STATE      CONNECTION 
eth0    ethernet  connected  eth0
eth1    ethernet  connected  Wired connection 1
lo      loopback  unmanaged  --
```

Alle Verbindungen anzeigen:
```bash
nmcli connection show
nmcli con show
nmcli c
```

Details einer Verbindung:
```bash
nmcli connection show eth0
nmcli con show eth0
```

**Neue Verbindungen erstellen:**

Statische IP-Konfiguration:
```bash
sudo nmcli connection add \
  type ethernet \
  con-name eth0-static \
  ifname eth0 \
  ipv4.addresses 192.168.1.100/24 \
  ipv4.gateway 192.168.1.1 \
  ipv4.dns "8.8.8.8 8.8.4.4" \
  ipv4.method manual
```

DHCP-Konfiguration:
```bash
sudo nmcli connection add \
  type ethernet \
  con-name eth0-dhcp \
  ifname eth0 \
  ipv4.method auto
```

**Verbindungen verwalten:**

Verbindung aktivieren:
```bash
sudo nmcli connection up eth0
```

Verbindung deaktivieren:
```bash
sudo nmcli connection down eth0
```

Verbindung neu laden:
```bash
sudo nmcli connection reload
```

Verbindung löschen:
```bash
sudo nmcli connection delete eth0
```

**Bestehende Verbindung ändern:**

IP-Adresse ändern:
```bash
sudo nmcli connection modify eth0 ipv4.addresses 192.168.1.101/24
sudo nmcli connection up eth0
```

Gateway ändern:
```bash
sudo nmcli connection modify eth0 ipv4.gateway 192.168.1.254
```

DNS-Server ändern:
```bash
sudo nmcli connection modify eth0 ipv4.dns "8.8.8.8 8.8.4.4"
```

DNS-Server hinzufügen (nicht ersetzen):
```bash
sudo nmcli connection modify eth0 +ipv4.dns 1.1.1.1
```

Von DHCP auf statisch wechseln:
```bash
sudo nmcli connection modify eth0 ipv4.method manual
sudo nmcli connection modify eth0 ipv4.addresses 192.168.1.100/24
sudo nmcli connection modify eth0 ipv4.gateway 192.168.1.1
sudo nmcli connection up eth0
```

**Interaktiver Editor:**

NetworkManager hat auch einen interaktiven Editor:
```bash
sudo nmcli connection edit eth0
```

Im Editor verfügbare Kommandos:
- `print`: Zeigt alle Einstellungen
- `set ipv4.addresses 192.168.1.100/24`: Setzt IP
- `save`: Speichert Änderungen
- `quit`: Beenden

**Konfigurationsdateien (Legacy):**

NetworkManager nutzt Konfigurationsdateien unter `/etc/sysconfig/network-scripts/` (RHEL 7/8) bzw. `/etc/NetworkManager/system-connections/` (RHEL 9+):

Beispiel `/etc/sysconfig/network-scripts/ifcfg-eth0`:
```bash
TYPE=Ethernet
BOOTPROTO=none
NAME=eth0
DEVICE=eth0
ONBOOT=yes
IPADDR=192.168.1.100
PREFIX=24
GATEWAY=192.168.1.1
DNS1=8.8.8.8
DNS2=8.8.4.4
```

Für DHCP:
```bash
TYPE=Ethernet
BOOTPROTO=dhcp
NAME=eth0
DEVICE=eth0
ONBOOT=yes
```

>[!NOTE]
> Ab RHEL 9/Rocky Linux 9 werden die Konfigurationsdateien im neuen Format unter `/etc/NetworkManager/system-connections/` im keyfile-Format gespeichert. Die alten `ifcfg-*` Dateien werden weiterhin unterstützt, aber deprecated.

**Neue Keyfile-Format (RHEL 9+):**

Datei: `/etc/NetworkManager/system-connections/eth0.nmconnection`
```ini
[connection]
id=eth0
type=ethernet
interface-name=eth0

[ipv4]
method=manual
address1=192.168.1.100/24
gateway=192.168.1.1
dns=8.8.8.8;8.8.4.4

[ipv6]
method=auto
```

Berechtigungen müssen auf 600 gesetzt sein:
```bash
sudo chmod 600 /etc/NetworkManager/system-connections/eth0.nmconnection
```

**Legacy-Kommandos (veraltet, aber noch vorhanden):**

Ältere Red Hat Systeme kennen noch:
```bash
# Interface starten/stoppen (deprecated)
sudo ifup eth0
sudo ifdown eth0

# Service verwalten
sudo systemctl restart NetworkManager
sudo systemctl status NetworkManager
```

**NetworkManager-Status und Troubleshooting:**

Service-Status prüfen:
```bash
sudo systemctl status NetworkManager
```

NetworkManager neu starten:
```bash
sudo systemctl restart NetworkManager
```

Logs anzeigen:
```bash
sudo journalctl -u NetworkManager -f
```

Verbindungstest:
```bash
nmcli networking connectivity check
```

NetworkManager deaktivieren (falls gewünscht):
```bash
sudo systemctl stop NetworkManager
sudo systemctl disable NetworkManager
```

**Statische Routen hinzufügen:**

```bash
sudo nmcli connection modify eth0 +ipv4.routes "10.0.0.0/8 192.168.1.254"
sudo nmcli connection up eth0
```

Oder manuell in der Konfigurationsdatei:
```bash
# /etc/sysconfig/network-scripts/route-eth0
10.0.0.0/8 via 192.168.1.254
```

**Hostname setzen (Red Hat):**

```bash
sudo hostnamectl set-hostname mein-server.example.com
```

Oder persistente Datei bearbeiten:
```bash
sudo vi /etc/hostname
```












