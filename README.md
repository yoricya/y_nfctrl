# Y_NFCTRL TCP-SYN Filtering Firewall
__Суть:__

Перехватывается входящий TCP-SYN пакет → дропается, этим создается вид закрытого порта.
Telegram-бот отправляет уведомление о попытке подключения и запрос: запретить или разрешить этот IP.
Если разрешаем → IP временно(на 1 час) добавляется в белый список, и дальнейшие SYN пакеты проходят дальше.
Все SYN пакеты по умолчанию идут в черный список если явно не были разрешены, поэтому спам бесполезен.

__Настройка:__

_Прежде чем настраивать, выберите номер очереди NFQUEUE который не используется другим ПО._

Все правила использующие NFQUEUE можно посмотреть так:
```
sudo iptables-save | grep -i "NFQUEUE"
```

Настройка iptables
```
sudo iptables -A INPUT -p tcp --dport 1:65535 --syn \
    -m iprange ! --src-range 127.0.0.0-127.255.255.255 \
    -m iprange ! --src-range 192.168.0.0-192.168.255.255 \
    -m iprange ! --src-range 10.0.0.0-10.255.255.255 \
    -m iprange ! --src-range 172.16.0.0-172.31.255.255 \
    -j NFQUEUE --queue-num <Номер очереди NFQUEUE>
```

Запуск программы
```
sudo ./y_nfctrl -tg_owned_id <ID Вашего аккаунта в телеграме> -tg_bot_token "<Токен телеграм бота>" -nf_queue_id <Номер очереди NFQUEUE>
```
