# e2e-secret-files-probe

A Tabbify platform end-to-end test fixture: the app the tenant file-secrets
drill deploys. It is generated from the e2e suite's `fixtures/secret_files_probe`;
do not edit it here. It holds no credentials and no real certificate material:
the drill stores random throwaway bytes as the secret at run time.

`GET /` answers with what the guest observes about the file named by
`CERT_PATH`: its SHA-256, size, mode and owner, and whether its bytes appear in
any environment the app can read or on the kernel command line. It also
reports the SHA-256 and length of `PLAIN_TOKEN`, a plain `secret:` reference.
It never answers with a secret's contents.

The branches differ only in the `[env]` block of `tabbify.toml`:

| Branch | `[env]` |
|---|---|
| `baseline` | `PROBE_STAGE = "baseline"`, no secret |
| `file-ref` | `CERT_PATH = "secret-file:TEST_CERT"` and `PLAIN_TOKEN = "secret:TEST_TEXT"` |
| `text-ref` | `CERT_PATH = "secret:TEST_CERT"`, which a deploy must refuse |
