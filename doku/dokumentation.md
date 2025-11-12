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



















