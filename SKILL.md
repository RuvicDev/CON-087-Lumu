---
name: lumu
description: "Usa la librería ruvic_lumu_connector para consultar compromisos, indicadores de compromiso (IOC), incidentes y evidencias en Lumu Defender. Úsala cuando el usuario pida detección continua de compromiso, análisis de IOC, incidentes de Lumu o evidencias asociadas."
triggers:
- lumu
- lumu defender
- compromiso
- ioc
- indicadores de compromiso
- incidentes lumu
- evidencias
---

# Conector Lumu (ruvic_lumu_connector)

## Regla crítica de credenciales

El código generado NUNCA hardcodea credenciales. Siempre se leen de variables de entorno:

| Variable | Contenido |
|---|---|
| `RUVIC_LUMU_API_KEY` | Defender API Key |
| `RUVIC_LUMU_BASE_URL` | Base URL opcional, default `https://defender.lumu.io/api` |
| `RUVIC_LUMU_VERIFY_SSL` | Verificación SSL opcional |
| `RUVIC_LUMU_TIMEOUT` | Timeout opcional |
| `RUVIC_LUMU_MAX_RESULTS` | Máximo de resultados |
| `RUVIC_LUMU_INCIDENTS_PATH` | Path opcional para incidentes |
| `RUVIC_LUMU_COMPROMISES_PATH` | Path opcional para compromisos |
| `RUVIC_LUMU_IOCS_PATH` | Path opcional para IOCs |
| `RUVIC_LUMU_EVIDENCE_PATH_TEMPLATE` | Path opcional para evidencias |

Si estas variables NO existen, el conector no está configurado: no generes código que lo use; indica al usuario que lo configure en Settings → Conectores. Nunca uses variables con alias `_DEFAULT_`, `_TEST_` o `_PRODUCCION_`.

## Conexión

```python
from ruvic_lumu_connector import LumuClient
client = LumuClient()
```

## Capacidad 1 — Consultar compromisos

```python
compromises = client.get_compromises(adversary_types=["Malware"], limit=10)
for compromise in compromises:
    print(compromise)
```

## Capacidad 2 — Consultar indicadores IOC

```python
iocs = client.get_iocs(ioc_types=["ip", "domain"], days=7, limit=50)
for ioc in iocs:
    print(ioc)
```

## Capacidad 3 — Obtener incidentes

```python
incidents = client.get_incidents(statuses=["open"], limit=20)
for incident in incidents:
    print(incident)
```

## Capacidad 4 — Consultar evidencias

```python
evidence = client.get_evidence("incident-uuid")
for item in evidence:
    print(item)
```

## Manejo de errores

```python
from ruvic_lumu_connector import LumuAuthError, LumuConfigError, LumuDataError, LumuNetworkError
try:
    incidents = client.get_incidents(limit=10)
except LumuConfigError as exc:
    print(f"Configuración inválida: {exc}")
except LumuAuthError:
    print("API Key Lumu inválida o sin permisos")
except LumuNetworkError:
    print("No se pudo alcanzar Lumu Defender")
except LumuDataError as exc:
    print(f"Lumu rechazó la solicitud: {exc}")
```

## Buenas prácticas al generar código

1. Lee credenciales SOLO de `RUVIC_LUMU_*`.
2. Nunca imprimas API Keys ni URL con `key=` en logs.
3. Usa límites razonables y filtros por estado/tipo de adversario.
4. Trata IOCs y evidencias como información sensible de seguridad.
5. Si no llegan resultados, prueba ampliar rango de fechas o quitar filtros.
