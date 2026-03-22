"""
Cloud Storage Enumeration Module
- S3 bucket discovery via domain permutations + DNS/HTTP probing
- Azure Blob Storage enumeration
- Google Cloud Storage bucket discovery
- DigitalOcean Spaces
- Cloudflare R2
- Detect public read/write access
- Extract bucket contents listing when publicly accessible
"""
from __future__ import annotations
import asyncio
import logging
import re
from typing import Dict, List, Optional, Set
from argus.ontology.entities import Anomaly, EntityType, Severity
from argus.ontology.graph import KnowledgeGraph

logger = logging.getLogger("argus.intelligence.cloud_enum")

S3_REGION_ENDPOINTS = [
    "s3.amazonaws.com",
    "s3-us-east-1.amazonaws.com",
    "s3-us-west-2.amazonaws.com",
    "s3-eu-west-1.amazonaws.com",
    "s3-ap-southeast-1.amazonaws.com",
    "s3.ap-south-1.amazonaws.com",
    "s3.sa-east-1.amazonaws.com",
]

BUCKET_PERMUTATION_TEMPLATES = [
    "{name}",
    "{name}-backup",
    "{name}-backups",
    "{name}-dev",
    "{name}-staging",
    "{name}-prod",
    "{name}-production",
    "{name}-data",
    "{name}-assets",
    "{name}-static",
    "{name}-media",
    "{name}-uploads",
    "{name}-files",
    "{name}-logs",
    "{name}-archive",
    "{name}-config",
    "{name}-export",
    "{name}-dump",
    "{name}-database",
    "{name}-db",
    "{name}-web",
    "{name}-www",
    "{name}-api",
    "{name}-test",
    "{name}-testing",
    "{name}-qa",
    "{name}-uat",
    "{name}-public",
    "{name}-private",
    "{name}-internal",
    "{name}-storage",
    "{name}-bucket",
    "{name}bucket",
    "{name}storage",
    "backup-{name}",
    "dev-{name}",
    "staging-{name}",
    "assets-{name}",
    "static-{name}",
    "media-{name}",
]

S3_PUBLIC_INDICATORS = [
    "<ListBucketResult",
    "<Contents>",
    "<Key>",
    "AmazonS3",
]

S3_PRIVATE_INDICATORS = [
    "AccessDenied",
    "AllAccessDisabled",
    "NoSuchBucket",
]

AZURE_BLOB_INDICATORS = [
    "<?xml version",
    "<EnumerationResults",
    "<Blobs>",
    "BlobEndpoint",
]

GCS_INDICATORS = [
    "storage.googleapis.com",
    "<ListBucketResult",
    "\"kind\": \"storage#objects\"",
]


class CloudStorageEnumerator:
    def __init__(self, http_client, graph: KnowledgeGraph,
                 concurrency: int = 15):
        self.http  = http_client
        self.graph = graph
        self._sem  = asyncio.Semaphore(concurrency)
        self._seen: Set[str] = set()

    async def run(self) -> Dict:
        domains = self.graph.get_by_type(EntityType.DOMAIN)
        apex_domains = set()
        for d in domains:
            if not d.properties.get("is_neighbor"):
                parts = d.name.split(".")
                if len(parts) >= 2:
                    apex = parts[-2]
                    apex_domains.add((apex, d))

        results = {
            "buckets_found":    0,
            "public_buckets":   0,
            "private_buckets":  0,
            "azure_found":      0,
            "gcs_found":        0,
            "do_found":         0,
        }
        lock = asyncio.Lock()

        async def enum_apex(apex, entity):
            async with self._sem:
                r = await self._enumerate_apex(apex, entity)
                async with lock:
                    for k, v in r.items():
                        results[k] = results.get(k, 0) + v

        await asyncio.gather(
            *[enum_apex(apex, entity) for apex, entity in apex_domains],
            return_exceptions=True,
        )
        return results

    async def _enumerate_apex(self, apex: str, entity) -> Dict:
        counts = {"buckets_found": 0, "public_buckets": 0,
                  "private_buckets": 0, "azure_found": 0,
                  "gcs_found": 0, "do_found": 0}

        bucket_names = [
            t.format(name=apex)
            for t in BUCKET_PERMUTATION_TEMPLATES
        ]

        tasks = []
        for bucket in bucket_names[:25]:
            tasks.append(self._check_s3(bucket, entity, counts))
            tasks.append(self._check_azure(bucket, entity, counts))
            tasks.append(self._check_gcs(bucket, entity, counts))
            tasks.append(self._check_do_spaces(bucket, entity, counts))

        await asyncio.gather(*tasks[:60], return_exceptions=True)
        return counts

    async def _check_s3(self, bucket: str, entity, counts: Dict) -> None:
        key = f"s3:{bucket}"
        if key in self._seen:
            return
        self._seen.add(key)

        url = f"https://{bucket}.s3.amazonaws.com/"
        try:
            resp = await self.http.get(url, timeout_override=8)
            if not resp:
                return

            status = resp.get("status", 0)
            body   = resp.get("data", "") or ""

            if status == 200 and any(ind in body for ind in S3_PUBLIC_INDICATORS):
                counts["buckets_found"]  += 1
                counts["public_buckets"] += 1
                files = re.findall(r"<Key>(.*?)</Key>", body)[:10]
                self._add_finding(entity, "S3_BUCKET_PUBLIC",
                    f"S3 bucket {bucket} is publicly readable — "
                    f"{len(files)} files visible: {', '.join(files[:5])}",
                    Severity.CRITICAL, url)
                logger.warning(f"CLOUD: Public S3 bucket: {bucket} ({len(files)} files)")

            elif status == 403 and "AccessDenied" not in body:
                counts["buckets_found"]   += 1
                counts["private_buckets"] += 1
                self._add_finding(entity, "S3_BUCKET_EXISTS",
                    f"S3 bucket {bucket} exists but access is restricted",
                    Severity.MEDIUM, url)

            elif status == 200 and "NoSuchBucket" not in body:
                counts["buckets_found"] += 1
                self._add_finding(entity, "S3_BUCKET_EXISTS",
                    f"S3 bucket {bucket} found (status {status})",
                    Severity.MEDIUM, url)

        except Exception:
            pass

    async def _check_azure(self, container: str, entity, counts: Dict) -> None:
        key = f"az:{container}"
        if key in self._seen:
            return
        self._seen.add(key)

        account = container.replace("-", "").replace("_", "")[:24]
        url = f"https://{account}.blob.core.windows.net/{container}?restype=container&comp=list"

        try:
            resp = await self.http.get(url, timeout_override=8)
            if not resp:
                return

            status = resp.get("status", 0)
            body   = resp.get("data", "") or ""

            if status == 200 and any(ind in body for ind in AZURE_BLOB_INDICATORS):
                counts["azure_found"]    += 1
                counts["public_buckets"] += 1
                blobs = re.findall(r"<Name>(.*?)</Name>", body)[:10]
                self._add_finding(entity, "AZURE_BLOB_PUBLIC",
                    f"Azure Blob container {account}/{container} is public — "
                    f"{len(blobs)} blobs: {', '.join(blobs[:5])}",
                    Severity.CRITICAL, url)
                logger.warning(f"CLOUD: Public Azure blob: {account}/{container}")

            elif status == 403:
                counts["azure_found"]     += 1
                counts["private_buckets"] += 1
                self._add_finding(entity, "AZURE_BLOB_EXISTS",
                    f"Azure Blob storage {account}/{container} exists (access restricted)",
                    Severity.LOW, url)

        except Exception:
            pass

    async def _check_gcs(self, bucket: str, entity, counts: Dict) -> None:
        key = f"gcs:{bucket}"
        if key in self._seen:
            return
        self._seen.add(key)

        url = f"https://storage.googleapis.com/{bucket}/"

        try:
            resp = await self.http.get(url, timeout_override=8)
            if not resp:
                return

            status = resp.get("status", 0)
            body   = resp.get("data", "") or ""

            if status == 200 and any(ind in body for ind in GCS_INDICATORS):
                counts["gcs_found"]      += 1
                counts["public_buckets"] += 1
                files = re.findall(r'"name": "(.*?)"', body)[:10]
                self._add_finding(entity, "GCS_BUCKET_PUBLIC",
                    f"GCS bucket {bucket} is publicly accessible — "
                    f"{len(files)} objects: {', '.join(files[:5])}",
                    Severity.CRITICAL, url)
                logger.warning(f"CLOUD: Public GCS bucket: {bucket}")

            elif status == 403:
                counts["gcs_found"]       += 1
                counts["private_buckets"] += 1
                self._add_finding(entity, "GCS_BUCKET_EXISTS",
                    f"GCS bucket {bucket} exists (access denied)",
                    Severity.LOW, url)

        except Exception:
            pass

    async def _check_do_spaces(self, bucket: str, entity, counts: Dict) -> None:
        key = f"do:{bucket}"
        if key in self._seen:
            return
        self._seen.add(key)

        for region in ["nyc3", "sfo3", "sgp1", "fra1", "ams3"]:
            url = f"https://{bucket}.{region}.digitaloceanspaces.com/"
            try:
                resp = await self.http.get(url, timeout_override=6)
                if not resp:
                    continue
                status = resp.get("status", 0)
                body   = resp.get("data", "") or ""
                if status == 200 and "<ListBucketResult" in body:
                    counts["do_found"]       += 1
                    counts["public_buckets"] += 1
                    self._add_finding(entity, "DO_SPACES_PUBLIC",
                        f"DigitalOcean Space {bucket} ({region}) is publicly readable",
                        Severity.CRITICAL, url)
                    logger.warning(f"CLOUD: Public DO Space: {bucket}.{region}")
                    break
                elif status == 403:
                    counts["do_found"] += 1
                    break
            except Exception:
                pass

    def _add_finding(self, entity, code: str, detail: str,
                     severity: Severity, url: str) -> None:
        self.graph.penalize_entity(entity.id, Anomaly(
            code=code,
            title=code.replace("_", " ").title(),
            detail=f"{detail} | {url}",
            severity=severity,
            entity_id=entity.id, entity_name=entity.name,
        ))
