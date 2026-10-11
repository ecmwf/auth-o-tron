# Aviso-branded UI preview

From the workspace root:

```bash
AOT_CONFIG_PATH=authotron/examples/login-ui/aviso.yaml cargo run -p authotron
```

Open **http://127.0.0.1:8080/login**. This example binds only to loopback and
does not enable providers or the token store. Its signing-secret value is public
demo data, not a production credential.

The page is a branding-only preview: no credentials are collected and interactive
sign-in is unavailable. The existing service homepage remains at `/`.

The example uses the official Aviso mark served by the
[Aviso playground](https://aviso-playground.ecmwf.int/). The browser fetches this
public HTTPS image directly; the example therefore needs access to that host.
Remove `ui.branding.logo_url` to use the application-name wordmark instead, or
replace it with an HTTPS image or root-relative image already served by the
origin. A local pathname does not mount or serve a file. Logos use a white
surface so light-background artwork remains legible in either page theme.

Browser application sign-in requires a separate authentication implementation:
registered callback URIs, authorization codes, state/PKCE verification, and
application session handling. This preview does not implement those flows.
