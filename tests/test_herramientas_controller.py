from unittest.mock import patch, MagicMock
from aresitos.controlador.controlador_herramientas import ControladorHerramientas


def test_validar_nombre_herramienta():
    ch = ControladorHerramientas(None)
    assert ch._validar_nombre_herramienta('nmap')
    assert not ch._validar_nombre_herramienta('rm -rf /')


def test_instalar_herramienta_mock(monkeypatch):
    ch = ControladorHerramientas(None)
    # Patch subprocess.run to simulate apt-get
    class DummyRes:
        def __init__(self):
            self.returncode = 0
            self.stdout = 'installed'
            self.stderr = ''

    monkeypatch.setattr('subprocess.run', lambda *a, **k: DummyRes())
    res = ch.instalar_herramienta('nmap')
    assert res['exito']
