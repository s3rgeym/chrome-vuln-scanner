Something like Burp Suite for Chrome.

Перехватывает запросы браузера, заменяет параметры и пытается вызвать ошибку сервера.

Баг: если хромиум в первый раз запускается без `--remote-debugging-port`, то отладчик не будет запускаться с дефолтной сессией.

```bash
$ chromium --remote-debugging-port=9222
```

When Chromium is started with a --remote-debugging-port=0 flag, it starts a Chrome DevTools DevToolsClient server and prints its WebSocket URL to STDERR. The output looks something like this:

```bash
DevTools listening on ws://127.0.0.1:36775/devtools/browser/a292f96c-7332-4ce8-82a9-7411f3bd280a
```
