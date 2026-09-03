# Integration Tests

To run these integration tests, you need a Linux machine with a root user and LSM enabled via the GRUB configuration.

These tests cannot be run in GitHub CI because those machines don't have LSM enabled.

To run the tests, you can use the following command:

```bash
sudo CGO_ENABLED=0 go test -mod=vendor -v -tags=integration -count=1 -timeout=20m  ./integration
```