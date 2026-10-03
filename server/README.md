# Relay

«Слепой» сервер доставки. Он хранит публичные ключи для установки сессий и очереди зашифрованных конвертов, адресованные анонимным ID. Отправителей не знает. Логов запросов и IP-адресов не пишет. Недоставленные конверты удаляются через `-ttl` (по умолчанию 14 дней).

## API

| Метод | Путь | Аутентификация |
|---|---|---|
| POST | `/v1/accounts` | подпись новым ключом ящика |
| DELETE | `/v1/accounts` | да |
| GET | `/v1/accounts/{id}/bundle` | нет (расходует один одноразовый пре-ключ) |
| PUT | `/v1/keys` | да |
| GET | `/v1/keys/count` | да |
| PUT | `/v1/messages/{id}` | **нет**: отправитель анонимен |
| GET | `/v1/messages` | да |
| POST | `/v1/messages/ack` | да |

Аутентификация: заголовок `Authorization: Calc <id>:<unix>:<nonce>:<base64 ed25519 sig>`, подпись покрывает `method\npath\nunix\nnonce\nhex(sha256(body))`.

## Развёртывание

Вариант со встроенным TLS:

```sh
go build -o relay ./cmd/relay
./relay -addr :443 -db /var/lib/relay/relay.db -tls-cert fullchain.pem -tls-key privkey.pem
```

Вариант за Caddy. Логирование **должно быть выключено**: Caddy не пишет access-логи, пока их явно не включить, поэтому не добавляйте директиву `log`.

```
relay.example.com {
	reverse_proxy 127.0.0.1:8080
}
```

```sh
./relay -addr 127.0.0.1:8080 -db /var/lib/relay/relay.db
```

SPKI-пин для [AppConfig.swift](../ios/Calculon/App/AppConfig.swift):

```sh
openssl x509 -in cert.pem -pubkey -noout | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary | base64
```

Пиньте ключ, а не сертификат, и держите резервный ключ. Для Let's Encrypt используйте `--reuse-key`, иначе ключ меняется при каждом продлении.

Рекомендации для хоста: шифрование диска, отключённый swap или зашифрованный swap, минимум сервисов, не хранить бэкапы `relay.db`. Там только транзитные данные, их потеря ничего не ломает.
