"""Prueba de conexión estándar del conector Lumu."""
from __future__ import annotations

def test_connection() -> tuple[bool, str]:
    """Prueba API key y acceso consultando incidentes Lumu."""
    try:
        from ruvic_lumu_connector import LumuAuthError, LumuClient, LumuConfigError, LumuDataError, LumuNetworkError, LumuSecurityError
    except ImportError:
        return False, "La librería ruvic-lumu-connector no está instalada. Instala con: pip install git+https://github.com/tu-org/conector-lumu.git#subdirectory=lib"
    try:
        client = LumuClient(); client.ping()
    except ValueError as exc:
        return False, str(exc)
    except LumuConfigError as exc:
        return False, f"Configuración inválida: {exc}"
    except LumuAuthError as exc:
        return False, f"Autenticación o permisos Lumu inválidos: {exc}"
    except LumuNetworkError as exc:
        return False, f"Error de red hacia Lumu: {exc}"
    except LumuSecurityError as exc:
        return False, f"Bloqueo de seguridad: {exc}"
    except LumuDataError as exc:
        return False, f"Lumu rechazó la solicitud: {exc}"
    except Exception as exc:
        return False, f"Error inesperado probando Lumu: {exc}"
    return True, f"Conexión exitosa a Lumu Defender en {client.config.base_url}."

if __name__ == "__main__":
    ok, message = test_connection(); print(f"{'OK' if ok else 'FALLO'}: {message}"); raise SystemExit(0 if ok else 1)
