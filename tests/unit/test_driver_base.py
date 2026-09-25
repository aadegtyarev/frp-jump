from frp_jump.driver.base import (
    ConsumedGrant,
    DesiredState,
    ExposedService,
    RelayDriver,
    RelayState,
    TunnelDriver,
)
from tests.support.fakes import FakeDriver, FakeRelayDriver


def _desired_state() -> DesiredState:
    return DesiredState(
        device_id="dev-1",
        server_addr="relay.example.com",
        server_port=7000,
        ca_cert_pem=b"ca",
        cert_pem=b"cert",
        key_pem=b"key",
        exposed=(ExposedService(grant_id="g1", secret="s1", local_port=22),),
        consumed=(ConsumedGrant(grant_id="g2", secret="s2", local_bind_port=2222),),
    )


def test_fake_driver_satisfies_the_tunnel_driver_protocol() -> None:
    assert isinstance(FakeDriver(), TunnelDriver)


def test_fake_relay_driver_satisfies_the_relay_driver_protocol() -> None:
    assert isinstance(FakeRelayDriver(), RelayDriver)


def test_fake_driver_records_applied_desired_state() -> None:
    driver = FakeDriver()
    desired = _desired_state()
    driver.apply(desired)
    assert driver.last_applied is desired
    assert driver.applied == [desired]


def test_fake_driver_stop_sets_flag() -> None:
    driver = FakeDriver()
    driver.stop()
    assert driver.stopped is True


def test_fake_relay_driver_records_applied_state() -> None:
    driver = FakeRelayDriver()
    desired = RelayState(bind_port=7000, ca_cert_pem=b"ca", cert_pem=b"c", key_pem=b"k")
    driver.apply(desired)
    assert driver.last_applied is desired
