# service-openbao

The workspace's secrets server: OpenBao built with a FoundationDB storage backend and deployed as one hosted machine.

## What it is for

It holds the secrets, certificates and minted tokens the desks use. The image builds the server
from a fork that carries the FoundationDB backend, adds the secrets engines it needs as plugins,
and reaches the database as a client only. A desk reaches it over a private network, or through
an SSH tunnel with a certificate the server signs itself. RFD 2140 owns the storage design, RFD
2147 says why it is critical infrastructure, and RFD 2255 owns the tunnel.

## Deploy

```sh
fly deploy
```

## Licence

No licence file is present. `checks/tunnel_ladder.py` carries an `Apache-2.0 OR MIT` SPDX header.
