"""Cliente para Lumu Defender API.

Capacidades:
- get_compromises(): consultar compromisos/incidentes abiertos confirmados.
- get_iocs(): consultar indicadores de compromiso/adversarial activity.
- get_incidents(): obtener incidentes con filtros.
- get_evidence(): consultar evidencias/contexto de un incidente.

La API usa autenticación por company API key. Por compatibilidad con la API
pública documentada, la key se envía como query parameter `key`.
"""
from __future__ import annotations
from datetime import datetime, timedelta, timezone
from typing import Any, Sequence
import requests
from requests import Response
from .config import LumuConfig
from .exceptions import LumuAuthError, LumuDataError, LumuNetworkError
from .logging_utils import get_logger

_VALID_STATUSES = {"open", "muted", "closed"}
_VALID_ADVERSARIES = {"C2C", "Malware", "DGA", "Mining", "Spam", "Phishing"}

class LumuClient:
    """Cliente para consultar detección continua de compromiso con Lumu.

    Args:
        config: configuración opcional. Si se omite, lee RUVIC_LUMU_*.

    Ejemplo:
        >>> client = LumuClient()
        >>> client.get_incidents(limit=10)
        [{'id': '...', 'status': 'open'}]
    """
    def __init__(self, config: LumuConfig | None = None) -> None:
        self.config = config or LumuConfig.from_env()
        self._logger = get_logger()
        self._session = requests.Session()

    def _path(self, path: str) -> str:
        return path if path.startswith("/") else f"/{path}"

    def _url(self, path: str) -> str:
        return self.config.base_url + self._path(path)

    def _base_params(self, extra: dict[str, Any] | None = None) -> dict[str, Any]:
        params = {"key": self.config.api_key}
        for key, value in (extra or {}).items():
            if value is not None:
                params[key] = value
        return params

    def _handle_response(self, response: Response) -> Any:
        if response.status_code in {401, 403}:
            raise LumuAuthError(f"Lumu rechazó autenticación o permisos ({response.status_code}). Revisa API key y permisos Defender.")
        if response.status_code == 404:
            raise LumuDataError("Endpoint o recurso Lumu no encontrado. Verifica base_url, paths e incident_id.")
        if response.status_code == 429:
            raise LumuDataError("Lumu aplicó rate limiting (429). Reduce frecuencia o tamaño de consulta.")
        if response.status_code >= 400:
            raise LumuDataError(f"Lumu retornó HTTP {response.status_code}: {response.text[:500]}")
        if not response.content:
            return {}
        try:
            return response.json()
        except ValueError as exc:
            raise LumuDataError("Lumu respondió contenido no JSON cuando se esperaba JSON.") from exc

    def _request(self, method: str, path: str, params: dict[str, Any] | None = None, json_body: dict[str, Any] | None = None) -> Any:
        try:
            response = self._session.request(method=method.upper(), url=self._url(path), params=self._base_params(params), json=json_body, timeout=self.config.timeout, verify=self.config.verify_ssl, headers={"Accept": "application/json", "Content-Type": "application/json"})
        except requests.exceptions.SSLError as exc:
            raise LumuNetworkError("Error SSL conectando con Lumu. Verifica certificado o RUVIC_LUMU_VERIFY_SSL.") from exc
        except requests.exceptions.Timeout as exc:
            raise LumuNetworkError(f"Timeout conectando con Lumu ({self.config.timeout}s).") from exc
        except requests.exceptions.RequestException as exc:
            raise LumuNetworkError(f"No se pudo conectar con Lumu: {exc}.") from exc
        return self._handle_response(response)

    def _extract_items(self, data: Any, limit: int | None) -> list[dict[str, Any]]:
        if isinstance(data, dict):
            for key in ("incidents", "items", "data", "results", "iocs", "indicators", "activity", "evidence", "context"):
                if isinstance(data.get(key), list):
                    data = data[key]
                    break
        if isinstance(data, dict):
            data = [data]
        if not isinstance(data, list):
            raise LumuDataError("La respuesta Lumu no tiene formato esperado de lista/dict.")
        effective_limit = self.config.max_results if limit is None else int(limit)
        resolved_limit = max(1, min(effective_limit, self.config.max_results))
        return [dict(item) if isinstance(item, dict) else {"value": item} for item in data[:resolved_limit]]

    def _date_payload(self, from_date: str | None, to_date: str | None) -> dict[str, str]:
        now = datetime.now(timezone.utc)
        if to_date is None:
            to_date = now.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        if from_date is None:
            from_date = (now - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        return {"fromDate": from_date, "toDate": to_date}

    def _validate_filters(self, statuses: Sequence[str] | None, adversary_types: Sequence[str] | None) -> None:
        if statuses:
            invalid = set(statuses) - _VALID_STATUSES
            if invalid:
                raise LumuDataError(f"Estados inválidos: {sorted(invalid)}. Usa open, muted o closed.")
        if adversary_types:
            invalid = set(adversary_types) - _VALID_ADVERSARIES
            if invalid:
                raise LumuDataError(f"Tipos de adversario inválidos: {sorted(invalid)}. Usa C2C, Malware, DGA, Mining, Spam o Phishing.")

    def ping(self) -> bool:
        """Verifica conexión consultando incidentes con límite mínimo.

        Returns:
            True si Lumu responde correctamente.
        Ejemplo:
            >>> client.ping()
            True
        """
        self.get_incidents(limit=1)
        self._logger.info("Ping exitoso a Lumu Defender")
        return True

    def get_incidents(self, from_date: str | None = None, to_date: str | None = None, statuses: Sequence[str] | None = None, adversary_types: Sequence[str] | None = None, page: int = 0, limit: int | None = None) -> list[dict[str, Any]]:
        """Obtiene incidentes de seguridad Lumu.

        Args:
            from_date: fecha inicial ISO/RFC3339. Default últimos 7 días.
            to_date: fecha final ISO/RFC3339. Default ahora.
            statuses: filtros `open`, `muted`, `closed`.
            adversary_types: filtros `C2C`, `Malware`, `DGA`, `Mining`, `Spam`, `Phishing`.
            page: página 0-indexed.
            limit: máximo de incidentes.
        Returns:
            Lista de incidentes.
        Ejemplo:
            >>> client.get_incidents(statuses=["open"], limit=10)
            [{'id': '...', 'status': 'open'}]
        """
        self._validate_filters(statuses, adversary_types)
        effective_limit = self.config.max_results if limit is None else int(limit)
        resolved_limit = max(1, min(effective_limit, self.config.max_results))
        payload = self._date_payload(from_date, to_date)
        if statuses:
            payload["status"] = list(statuses)
        if adversary_types:
            payload["adversary-types"] = list(adversary_types)
        data = self._request("POST", self.config.incidents_path, params={"page": page + 1, "items": resolved_limit}, json_body=payload)
        rows = self._extract_items(data, resolved_limit)
        self._logger.info("Consultados %d incidentes Lumu", len(rows))
        return rows

    def get_compromises(self, adversary_types: Sequence[str] | None = None, limit: int | None = None) -> list[dict[str, Any]]:
        """Consulta compromisos/incidentes abiertos confirmados por Lumu.

        Args:
            adversary_types: filtros por tipo de adversario.
            limit: máximo de resultados.
        Returns:
            Lista de compromisos/incidentes abiertos.
        Ejemplo:
            >>> client.get_compromises(adversary_types=["Malware"], limit=10)
            [{'id': '...', 'adversaryType': 'Malware'}]
        """
        self._validate_filters(None, adversary_types)
        effective_limit = self.config.max_results if limit is None else int(limit)
        resolved_limit = max(1, min(effective_limit, self.config.max_results))
        payload: dict[str, Any] = {}
        if adversary_types:
            payload["adversary-types"] = list(adversary_types)
        data = self._request("POST", self.config.compromises_path, params={"page": 1, "items": resolved_limit}, json_body=payload)
        rows = self._extract_items(data, resolved_limit)
        self._logger.info("Consultados %d compromisos Lumu", len(rows))
        return rows

    def get_iocs(self, ioc_types: Sequence[str] | None = None, adversary_types: Sequence[str] | None = None, days: int = 7, limit: int | None = None) -> list[dict[str, Any]]:
        """Consulta indicadores de compromiso/adversarial activity.

        Args:
            ioc_types: tipos de IOC (`ip`, `domain`, `url`, `hash`) si la API lo soporta.
            adversary_types: tipos de adversario.
            days: ventana de consulta, 1 a 30 días.
            limit: máximo de resultados.
        Returns:
            Lista de IOCs/actividad adversarial.
        Ejemplo:
            >>> client.get_iocs(ioc_types=["domain", "ip"], days=7)
            [{'indicator': 'bad.example', 'type': 'domain'}]
        """
        self._validate_filters(None, adversary_types)
        days = max(1, min(int(days), 30))
        effective_limit = self.config.max_results if limit is None else int(limit)
        resolved_limit = max(1, min(effective_limit, self.config.max_results))
        payload: dict[str, Any] = {"days": days}
        if ioc_types:
            payload["ioc_types"] = list(ioc_types)
        if adversary_types:
            payload["adversary-types"] = list(adversary_types)
        data = self._request("POST", self.config.iocs_path, params={"items": resolved_limit}, json_body=payload)
        rows = self._extract_items(data, resolved_limit)
        self._logger.info("Consultados %d IOCs Lumu", len(rows))
        return rows

    def get_evidence(self, incident_id: str, hash_type: str | None = None, limit: int | None = None) -> list[dict[str, Any]]:
        """Consulta evidencias/contexto de un incidente Lumu.

        Args:
            incident_id: UUID del incidente.
            hash_type: tipo de hash opcional.
            limit: máximo de evidencias.
        Returns:
            Lista de evidencias/contexto del incidente.
        Ejemplo:
            >>> client.get_evidence("incident-uuid")
            [{'endpoint': '10.0.0.5', 'contact': 'malicious.example'}]
        """
        if not isinstance(incident_id, str) or not incident_id.strip():
            raise LumuDataError(f"incident_id debe ser un texto no vacío, recibido: {incident_id!r}.")
        path = self.config.evidence_path_template.format(incident_id=incident_id)
        data = self._request("GET", path, params={"hash": hash_type} if hash_type else None)
        rows = self._extract_items(data, limit)
        self._logger.info("Consultadas %d evidencias Lumu para incidente", len(rows))
        return rows
