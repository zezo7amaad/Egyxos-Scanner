"""Adapters for optional security tools."""

from .arjun import ArjunScanner
from .ffuf import FfufScanner
from .httpx import HttpxScanner
from .katana import KatanaScanner
from .nmap import NmapScanner
from .nuclei import NucleiScanner
from .paramspider import ParamSpiderScanner
from .sqlmap import SqlmapScanner
from .subfinder import SubfinderScanner

SCANNERS = {
    "subfinder": SubfinderScanner,
    "http": HttpxScanner,
    "httpx": HttpxScanner,
    "crawl": KatanaScanner,
    "katana": KatanaScanner,
    "urls": ParamSpiderScanner,
    "paramspider": ParamSpiderScanner,
    "params": ArjunScanner,
    "arjun": ArjunScanner,
    "fuzz": FfufScanner,
    "ffuf": FfufScanner,
    "ports": NmapScanner,
    "nmap": NmapScanner,
    "vuln": NucleiScanner,
    "nuclei": NucleiScanner,
    "sqli": SqlmapScanner,
    "sqlmap": SqlmapScanner,
}

__all__ = ["SCANNERS"]
