# Host recipes

Settings that fit common applications. Each host carries its own settings; copy what you need into the host's YAML
(web interface: host page > Advanced, or `debrev host edit DOMAIN`). Nothing is shared between hosts, so changing one
host never affects another.

## WebSocket app (chat, dashboards, Home Assistant, Proxmox console ...)
```yaml
websockets: true
timeouts: { read: 1h, send: 1h }
```

## Large uploads (file sharing, registries)
```yaml
max_body: 10g
timeouts: { read: 10m, send: 10m }
```

## Nextcloud
```yaml
websockets: true
max_body: 10g
timeouts: { read: 10m, send: 10m }
rate_limit: { rate: 200, burst: 2000, connections: 500 }   # sync clients are chatty
custom_snippet: |
  location /.well-known/carddav { return 301 $scheme://$host/remote.php/dav; }
  location /.well-known/caldav  { return 301 $scheme://$host/remote.php/dav; }
  location ^~ /.well-known      { return 301 $scheme://$host/index.php$uri; }
```
(NPM also set `client_body_buffer_size 400M`; left out on purpose, it lets every concurrent upload hold up to 400 MB in RAM.)

## MinIO / S3 compatible storage
```yaml
websockets: true
max_body: 0                     # unlimited
buffering: false
request_buffering: false
rate_limit: { rate: 200, burst: 2000, connections: 500 }   # parallel multipart uploads
custom_snippet: |
  chunked_transfer_encoding off;
  ignore_invalid_headers off;
```

## Mostly static site
```yaml
cache: { enabled: true, ttl: 1h, static_only: true }
```
