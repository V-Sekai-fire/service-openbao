# service-openbao

The workspace's secrets server: OpenBao built with a FoundationDB storage backend and deployed as a hosted app.

## What it is for

It holds the secrets, certificates and minted tokens the desks use. The image builds the server
from a fork that carries the FoundationDB backend, adds the secrets engines it needs as plugins,
and reaches the database as a client only. A desk reaches it over a private network, or through
an SSH tunnel with a certificate the server signs itself. RFD 2140 owns the storage design, RFD
2147 says why it is critical infrastructure, and RFD 2255 owns the tunnel.

## Deploy

Bao runs on the three `weftspun-fdb` machines, one HA instance beside each FDB server (RFD 2147).
`Dockerfile.colocated` layers the live Bao image's files onto the live FDB image. Build it into the
FDB app's registry, then roll it one machine at a time and unseal each instance:

```sh
flyctl deploy --build-only --push -a weftspun-fdb --dockerfile Dockerfile.colocated --image-label <tag> --remote-only -c /dev/null .
```

The single-machine app below is what it replaces.

```sh
fly deploy --build-secret GH_TOKEN="$(gh auth token)"
```

The token reads the private service-bao-taskweft release asset during the build; it is not kept in the image.

## Licence

MIT. See [LICENSE](LICENSE).
