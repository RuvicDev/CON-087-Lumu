"""Excepciones propias del conector Lumu."""

class LumuConnectorError(Exception):
    """Error base del conector Lumu."""

class LumuConfigError(LumuConnectorError):
    """Falta configuración requerida o algún valor de configuración es inválido."""

class LumuAuthError(LumuConnectorError):
    """API key Lumu inválida, expirada o con permisos insuficientes."""

class LumuNetworkError(LumuConnectorError):
    """Error de red, DNS, SSL, timeout o API Lumu no alcanzable."""

class LumuDataError(LumuConnectorError):
    """Solicitud inválida, recurso inexistente o respuesta inesperada de Lumu."""

class LumuSecurityError(LumuConnectorError):
    """Operación bloqueada por reglas de seguridad del conector."""
