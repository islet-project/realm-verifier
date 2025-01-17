# realm-verifier

The realm verifier implements our own realm token verification service. It checks the reference values stored inside the realm part of the attestation token against the provided ones in the configuration.

## Configuration example

```json=
{
    "version": "0.1",
    "issuer": {
        "name": "Samsung",
        "url": "https://cca-realms.samsung.com/"
    },
    "realm": {
        "uuid": "f7e3e8ef-e0cc-4098-98f8-3a12436da040",
        "name": "Data Processing Service",
        "version": "1.0.0",
        "release-timestamp": "2024-09-09T05:21:31Z",
        "attestation-protocol": "HTTPS/RA-TLSv1.0",
        "port": 8088,
        "reference-values": {
            "rim": "fdd82b3e2ef1da0091a3a9ce22549c4258265968d9c6487ea9886664b94a9b61",
            "rems": [
                [
                    "0000000000000000000000000000000000000000000000000000000000000000",
                    "0000000000000000000000000000000000000000000000000000000000000000",
                    "0000000000000000000000000000000000000000000000000000000000000000",
                    "0000000000000000000000000000000000000000000000000000000000000000"
                ],
                [
                    "0000000000000000000000000000000000000000000000000000000000000000",
                    "7d43aefe4c6a955cd0753bccee2e707232d2b44b84c4607ac925597419ac104d",
                    "0000000000000000000000000000000000000000000000000000000000000000",
                    "9e6f6535ee6cf18be0eae95d0a2fd6876ccdc216a172e8f15607fe1a814d0b6c"
                ]
            ],
            "hash-algo": "sha-256"
        }
    }
}
```
