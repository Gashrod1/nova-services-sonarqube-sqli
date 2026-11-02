"""Tests de non-régression : injection SQL dans sqli_low (vulnerabilities/SQLi.py).

Chaque test travaille sur une copie temporaire de TIWAP.db : la base du dépôt
n'est jamais modifiée et l'application n'est pas lancée.
"""
import importlib
import shutil
import sys
from pathlib import Path

import pytest

TIWAP_DIR = Path(__file__).resolve().parents[1]
PAYLOAD = "x' OR '1'='1' --"


@pytest.fixture
def sqli(tmp_path, monkeypatch):
    shutil.copy(TIWAP_DIR / "TIWAP.db", tmp_path / "TIWAP.db")
    monkeypatch.chdir(tmp_path)  # DBManager ouvre 'TIWAP.db' dans le répertoire courant
    monkeypatch.syspath_prepend(str(TIWAP_DIR))
    for name in ("vulnerabilities.SQLi", "helper.db_manager"):
        sys.modules.pop(name, None)
    return importlib.import_module("vulnerabilities.SQLi")


def test_injection_ne_contourne_pas_le_filtre(sqli):
    # Avant correction, cette charge renvoyait les 5 comptes de la table users.
    assert sqli.sqli_low(username=PAYLOAD, password="peu-importe") == []


def test_quote_traitee_comme_une_valeur(sqli):
    # Une apostrophe ne doit plus casser la requête ni remonter d'erreur SQL.
    assert sqli.sqli_low(username="O'Brien", password="x'y") == []


def test_identifiants_inconnus(sqli):
    assert sqli.sqli_low(username="inconnu", password="faux") == []


def test_utilisateur_existant_comportement_inchange(sqli):
    assert sqli.sqli_low(username="admin", password="peu-importe") == "User Exists"
