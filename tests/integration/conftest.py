import pytest

from frp_jump.common.settings import Settings
from frp_jump.driver.frp.binaries import FrpBinaries, ensure_installed


@pytest.fixture(scope="session")
def frp_binaries(tmp_path_factory) -> FrpBinaries:
    install_dir = tmp_path_factory.mktemp("frp-bin")
    return ensure_installed(install_dir, version=Settings().frp_version)
