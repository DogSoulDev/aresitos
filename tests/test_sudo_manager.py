from aresitos.utils.sudo_manager import SudoManager


def test_sudo_manager_set_and_clear(monkeypatch):
    sm = SudoManager()
    # No password initially
    sm.clear_sudo()
    assert not sm.is_sudo_active()

    # Set password and ensure active
    sm.set_sudo_authenticated('fakepass')
    assert sm.is_sudo_active()
    assert sm.sudo_password == 'fakepass'

    # Clear sudo and check
    sm.clear_sudo()
    assert not sm.is_sudo_active()


def test_execute_sudo_command_mock(monkeypatch):
    sm = SudoManager()
    sm.set_sudo_authenticated('pwd')

    class DummyResult:
        def __init__(self):
            self.returncode = 0
            self.stdout = 'ok'
            self.stderr = ''

    def fake_run(*args, **kwargs):
        return DummyResult()

    monkeypatch.setattr('subprocess.run', fake_run)
    res = sm.execute_sudo_command('echo test')
    assert hasattr(res, 'returncode')
    assert res.returncode == 0
