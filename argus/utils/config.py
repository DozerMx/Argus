"""Argus v3.4 Configuration"""
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

@dataclass
class Config:

    deep:            bool = False
    brute:           bool = False
    axfr:            bool = False
    cdn_bypass:      bool = False
    ports:           bool = False
    jarm:            bool = False
    fuzz:            bool = False
    auth:            bool = False
    credentials:     List[Tuple[str, str]] = field(default_factory=list)
    stealth_profile: str  = "normal"
    diff:            bool = True
    grab_live_certs: bool = True

    threads:           int   = 30
    timeout:           int   = 10
    delay:             float = 0.0
    proxy:             Optional[str] = None
    brute_concurrency: int   = 100
    port_concurrency:  int   = 150

    cache:     bool = True
    cache_ttl: int  = 3600

    verbose: bool = False
    quiet:   bool = False

    @classmethod
    def from_args(cls, args) -> "Config":
        full = getattr(args, "full", False)
        return cls(
            deep=full or getattr(args, "deep", False),
            brute=full or getattr(args, "brute", False),
            axfr=full or getattr(args, "axfr", False),
            cdn_bypass=full or getattr(args, "cdn_bypass", False),
            ports=full or getattr(args, "ports", False),
            jarm=full or getattr(args, "jarm", False),
            fuzz=getattr(args, "fuzz", False),
            auth=getattr(args, "auth", False),
            credentials=[(args.user, args.password)] if getattr(args, "user", "") else [],
            stealth_profile=getattr(args, "stealth_profile", "normal"),
            diff=not getattr(args, "no_diff", False),
            grab_live_certs=not getattr(args, "no_live_certs", False),
            threads=getattr(args, "threads", 30),
            timeout=getattr(args, "timeout", 10),
            delay=getattr(args, "delay", 0.0),
            proxy=getattr(args, "proxy", None),
            brute_concurrency=getattr(args, "brute_concurrency", 100),
            port_concurrency=getattr(args, "port_concurrency", 150),
            cache=not getattr(args, "no_cache", False),
            cache_ttl=getattr(args, "cache_ttl", 3600),
            verbose=getattr(args, "verbose", False),
            quiet=getattr(args, "quiet", False),
        )
