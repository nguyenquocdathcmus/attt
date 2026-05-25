from app.services.normalization.nikto_parser import parse as parse_nikto
from app.services.normalization.zap_parser import parse as parse_zap


def normalize(scanner: str, raw: dict) -> list[dict]:
    if scanner == "zap":
        return parse_zap(raw)
    if scanner == "nikto":
        return parse_nikto(raw)
    return []
