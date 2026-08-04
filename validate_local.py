"""Validación local del conector Lumu contra Lumu Defender real.

Requiere RUVIC_LUMU_API_KEY. No usa mocks.
"""
from __future__ import annotations
import os
from ruvic_lumu_connector import LumuClient, setup_logging
setup_logging("INFO")
client = LumuClient()
print("== Ping =="); print(client.ping())
print("== Incidentes =="); incidents = client.get_incidents(limit=5); print(f"Incidentes: {len(incidents)}"); [print(f"  {i}") for i in incidents[:3]]
print("== Compromisos abiertos =="); comps = client.get_compromises(limit=5); print(f"Compromisos: {len(comps)}"); [print(f"  {c}") for c in comps[:3]]
print("== IOCs =="); iocs = client.get_iocs(days=7, limit=5); print(f"IOCs: {len(iocs)}"); [print(f"  {ioc}") for ioc in iocs[:3]]
incident_id = os.environ.get("RUVIC_LUMU_TEST_INCIDENT_ID", "").strip()
if incident_id:
    print("== Evidencias =="); evidence = client.get_evidence(incident_id, limit=5); print(f"Evidencias: {len(evidence)}"); [print(f"  {e}") for e in evidence[:3]]
else:
    print("Evidencias omitidas. Define RUVIC_LUMU_TEST_INCIDENT_ID para probar contexto de incidente real.")
