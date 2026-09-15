# `docs/firmware/` (same-origin firmware for the browser flasher)

Generated. **Do not hand-edit**; `.github/workflows/release.yml` writes this
directory on every `v*` tag via [`tools/publish_pages_firmware.py`](../../tools/publish_pages_firmware.py).

## Why it exists

A browser cannot fetch a GitHub Release asset. `browser_download_url` 302s to
`release-assets.githubusercontent.com`, and neither the redirect nor the final
response carries `Access-Control-Allow-Origin`, so every download fails CORS.
`api.github.com` *is* CORS-enabled, which is what made this so easy to miss:
listing releases worked and only the downloads failed, so the flasher looked
healthy right up until someone pressed **Flash** (#138).

Serving the images from `docs/` puts them on the same origin as the flasher, so
CORS never applies.

The GitHub Release stays the source of truth and keeps every asset (host
binary, `partitions.csv`, `SHA256SUMS`). Pages carries only what the page
actually downloads: the `.bin` images, `manifest.json`, and the
`flasher_args-*.json` files.

## Layout

```
docs/firmware/
  index.json          # [{tag, prerelease, date, files:[{name,size}]}] — the picker's source
  v1.3.0/
    manifest.json     # variant -> parts[{offset,file,role,size}] + cfgseed_offset
    flasher_args-esp32s3-eth.json
    bootloader-esp32s3-eth.bin
    partition-table-esp32s3-eth.bin
    ota_data_initial-esp32s3-eth.bin
    SipServer-esp32s3-eth.bin
    ...                # same four images per variant
```

`index.json` carries an explicit `files` array because GitHub Pages serves no
directory listing; it is what lets the page rebuild the asset map it used to
get from the API, without a second round trip.

An empty `releases` array is the honest state before the first tag lands on this
scheme; the flasher renders "No release published to this site yet" and falls
back to its local-file picker.
