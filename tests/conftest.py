import pytest  # noqa E402


def pytest_configure(config):
    config.option.numprocesses = 1


def pytest_addoption(parser):
    parser.addoption(
        "--real-aws",
        action="store_true",
        default=False,
        help="Run tests with real AWS integration",
    )
    parser.addoption("--all", action="store_true", help="run all combinations")


def pytest_generate_tests(metafunc):
    if "param1" in metafunc.fixturenames:
        if metafunc.config.getoption("all"):
            end = 5
        else:
            end = 2
        metafunc.parametrize("param1", range(end))
