# Conector Lumu para Ruvic

Conector Ruvic para detección continua de compromiso con Lumu Defender. Permite consultar compromisos, indicadores de compromiso (IOC), incidentes y evidencias/contexto de incidentes.

## Capacidades

1. `get_compromises(...)`.
2. `get_iocs(...)`.
3. `get_incidents(...)`.
4. `get_evidence(incident_id, ...)`.

## Instalación

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ./lib
```

Desde Git:

```bash
pip install git+https://github.com/tu-org/conector-lumu.git#subdirectory=lib
```

## Variables de entorno

| Variable | Obligatoria | Descripción | Default |
|---|---:|---|---|
| `RUVIC_LUMU_API_KEY` | Sí | Defender API Key | — |
| `RUVIC_LUMU_BASE_URL` | No | Base URL API | `https://defender.lumu.io/api` |
| `RUVIC_LUMU_VERIFY_SSL` | No | Verificar SSL | `true` |
| `RUVIC_LUMU_TIMEOUT` | No | Timeout | `20` |
| `RUVIC_LUMU_MAX_RESULTS` | No | Máximo resultados | `100` |
| `RUVIC_LUMU_INCIDENTS_PATH` | No | Path incidentes | `/incidents/all` |
| `RUVIC_LUMU_COMPROMISES_PATH` | No | Path compromisos | `/incidents/open` |
| `RUVIC_LUMU_IOCS_PATH` | No | Path IOCs | `/adversarial-activity` |
| `RUVIC_LUMU_EVIDENCE_PATH_TEMPLATE` | No | Path evidencias | `/incidents/{incident_id}/context` |

## Configuración en Lumu

1. Entra a Lumu Defender.
2. Ve a Settings / API Keys o Defender API.
3. Genera o copia la API Key de la compañía.
4. Asigna permisos de lectura sobre incidentes, adversarial activity/IOCs y contexto.

## Pruebas

```bash
python test_connection.py
python validate_local.py
```

Para evidencias de un incidente real:

```bash
export RUVIC_LUMU_TEST_INCIDENT_ID="uuid-del-incidente"
python validate_local.py
```

## Seguridad

- Nunca subas API Keys al repositorio.
- No imprimas URLs con `key=` ni headers sensibles.
- Trata IOCs y evidencias como información sensible.
