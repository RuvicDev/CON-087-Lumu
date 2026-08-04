"""Configuración del conector leída desde variables de entorno.

Prefijo: RUVIC_LUMU_
"""
from __future__ import annotations
import os
from dataclasses import dataclass
from .exceptions import LumuConfigError

ENV_PREFIX = "RUVIC_LUMU_"

def _to_bool(value: str, default: bool) -> bool:
    raw = (value or "").strip().lower()
    if raw == "":
        return default
    if raw in {"true", "1", "yes", "y", "on"}:
        return True
    if raw in {"false", "0", "no", "n", "off"}:
        return False
    raise LumuConfigError("Configuración inválida: VERIFY_SSL debe ser true/false.")

@dataclass(frozen=True)
class LumuConfig:
    """Parámetros para autenticar y consultar la API Lumu Defender."""
    api_key: str
    base_url: str = "https://defender.lumu.io/api"
    verify_ssl: bool = True
    timeout: int = 20
    max_results: int = 100
    incidents_path: str = "/incidents/all"
    compromises_path: str = "/incidents/open"
    iocs_path: str = "/adversarial-activity"
    evidence_path_template: str = "/incidents/{incident_id}/context"

    @classmethod
    def from_env(cls) -> "LumuConfig":
        """Construye la configuración desde variables RUVIC_LUMU_*.

        Raises:
            ValueError: si falta una variable requerida.
            LumuConfigError: si un valor opcional es inválido.

        Ejemplo:
            >>> config = LumuConfig.from_env()
            >>> config.base_url
            'https://defender.lumu.io/api'
        """
        api_key = os.environ.get(f"{ENV_PREFIX}API_KEY", "").strip()
        missing = [n for n, v in ((f"{ENV_PREFIX}API_KEY", api_key),) if not v]
        if missing:
            raise ValueError("Faltan variables de entorno del conector lumu: " + ", ".join(missing) + ". Configura el conector en Settings → Conectores.")
        base_url = os.environ.get(f"{ENV_PREFIX}BASE_URL", "").strip().rstrip("/") or "https://defender.lumu.io/api"
        if not base_url.startswith("https://"):
            raise LumuConfigError("RUVIC_LUMU_BASE_URL debe iniciar por https://.")
        try:
            timeout = int(os.environ.get(f"{ENV_PREFIX}TIMEOUT", "20").strip() or "20")
            max_results = int(os.environ.get(f"{ENV_PREFIX}MAX_RESULTS", "100").strip() or "100")
            verify_ssl = _to_bool(os.environ.get(f"{ENV_PREFIX}VERIFY_SSL", "true"), default=True)
        except ValueError as exc:
            raise LumuConfigError("RUVIC_LUMU_TIMEOUT y RUVIC_LUMU_MAX_RESULTS deben ser enteros.") from exc
        if timeout <= 0 or timeout > 120:
            raise LumuConfigError("RUVIC_LUMU_TIMEOUT debe estar entre 1 y 120 segundos.")
        if max_results <= 0 or max_results > 1000:
            raise LumuConfigError("RUVIC_LUMU_MAX_RESULTS debe estar entre 1 y 1000.")
        return cls(
            api_key=api_key,
            base_url=base_url,
            verify_ssl=verify_ssl,
            timeout=timeout,
            max_results=max_results,
            incidents_path=os.environ.get(f"{ENV_PREFIX}INCIDENTS_PATH", "").strip() or "/incidents/all",
            compromises_path=os.environ.get(f"{ENV_PREFIX}COMPROMISES_PATH", "").strip() or "/incidents/open",
            iocs_path=os.environ.get(f"{ENV_PREFIX}IOCS_PATH", "").strip() or "/adversarial-activity",
            evidence_path_template=os.environ.get(f"{ENV_PREFIX}EVIDENCE_PATH_TEMPLATE", "").strip() or "/incidents/{incident_id}/context",
        )
