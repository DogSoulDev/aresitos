import types
from unittest.mock import MagicMock

from aresitos.vista.vista_login import LoginAresitos


def test_login_flow_no_kali(monkeypatch):
    # Force verificar_kali_linux_estricto to return True for instantiation
    monkeypatch.setattr('aresitos.vista.vista_login.verificar_kali_linux_estricto', lambda: True)

    # Mock Tk mainloop to avoid opening UI
    monkeypatch.setattr('tkinter.Tk', lambda: MagicMock())

    app = LoginAresitos()
    # After init, rate_limiter should exist
    assert hasattr(app, 'rate_limiter')
    # continue_btn should exist
    assert hasattr(app, 'continue_btn')


def test_login_sets_sudo(monkeypatch):
    monkeypatch.setattr('aresitos.vista.vista_login.verificar_kali_linux_estricto', lambda: True)
    # Mock subprocess.run used in verificar_password
    class DummyRes:
        def __init__(self):
            self.returncode = 0
            self.stdout = 'test'
            self.stderr = ''

    monkeypatch.setattr('subprocess.run', lambda *a, **k: DummyRes())
    monkeypatch.setattr('tkinter.Tk', lambda: MagicMock())

    app = LoginAresitos()
    # Simulate entering password
    app.password_entry = MagicMock()
    app.password_entry.get = lambda: 'fakepass'
    app.password_entry.delete = lambda *a, **k: None
    app.password_entry.winfo_exists = lambda: True

    # Run verificar_password and ensure SudoManager is configured
    app.verificar_password()
    from aresitos.utils.sudo_manager import get_sudo_manager
    sm = get_sudo_manager()
    assert sm.is_sudo_active()
