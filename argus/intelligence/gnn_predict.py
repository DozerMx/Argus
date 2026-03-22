"""
Graph Neural Network — Subdomain Prediction
Uses structural patterns in the Knowledge Graph to predict
subdomains that likely exist but weren't discovered.

Architecture: simplified GNN using NetworkX graph features
(no PyTorch/TF dependency — pure Python with numpy).

Features extracted per domain node:
  - Label parts (split by dots)
  - Depth (number of sublevels)
  - Degree (how many connections in graph)
  - Co-occurrence patterns with other domains

Prediction approach:
  1. Extract label patterns from ALL known subdomains
  2. Build n-gram model of label sequences
  3. Compute label embedding via co-occurrence matrix
  4. Generate candidates from pattern combinations
  5. Score by graph structural similarity
  6. Return top-N predicted subdomains not yet in graph

This is what separates elite recon frameworks from wordlist scanners.
"""
from __future__ import annotations
import asyncio
import logging
import re
from collections import Counter, defaultdict
from typing import Dict, List, Optional, Set, Tuple

from argus.ontology.entities import EntityType
from argus.ontology.graph import KnowledgeGraph

logger = logging.getLogger("argus.intelligence.gnn_predict")

class SubdomainPredictor:
    """
    Learns naming patterns from discovered subdomains
    and predicts undiscovered ones.
    """

    def __init__(self, graph: KnowledgeGraph, dns_correlator, threshold: float = 0.6):
        self.graph     = graph
        self.dns       = dns_correlator
        self.threshold = threshold

    async def predict_and_verify(self, domain: str, top_n: int = 50) -> Dict:
        """
        Predict likely subdomains + verify via DNS.
        Returns discovered/verified predictions.
        """

        known = self._get_known_subdomains(domain)
        if len(known) < 3:
            return {"predicted": 0, "verified": 0, "candidates": []}

        logger.info(f"GNN predictor: learning from {len(known)} known subdomains for {domain}")

        patterns = self._learn_patterns(known, domain)

        candidates = self._generate_candidates(patterns, domain, known)

        scored = self._score_candidates(candidates, known, domain)
        top_candidates = scored[:top_n]

        logger.info(f"GNN predictor: {len(top_candidates)} candidates generated")

        verified = await self._verify_candidates(top_candidates, domain)

        return {
            "predicted":    len(top_candidates),
            "verified":     len(verified),
            "new_domains":  verified,
            "patterns_used": len(patterns["label_patterns"]),
        }

    def _get_known_subdomains(self, domain: str) -> List[str]:
        """Extract all known subdomains from graph."""
        subdomains = []
        for entity in self.graph.get_by_type(EntityType.DOMAIN):
            name = entity.name
            if name != domain and (name.endswith(f".{domain}") or
               name.endswith(f".{domain}")):
                subdomains.append(name)
        return subdomains

    def _learn_patterns(self, subdomains: List[str], domain: str) -> Dict:
        """
        Learn naming patterns from known subdomains.
        Extracts: label frequencies, bigrams, depth patterns,
        prefix/suffix patterns, numeric patterns.
        """
        domain_suffix = f".{domain}"
        labels_by_depth: Dict[int, List[str]] = defaultdict(list)
        all_labels: List[str] = []
        bigrams: Counter = Counter()
        has_numbers: Dict[str, int] = Counter()

        for sub in subdomains:
            if sub.endswith(domain_suffix):
                subdomain_part = sub[:-len(domain_suffix)]
            else:
                continue

            parts = subdomain_part.split(".")
            depth = len(parts)

            for i, part in enumerate(parts):
                all_labels.append(part)
                labels_by_depth[i].append(part)
                if re.search(r"\d", part):

                    base = re.sub(r"\d+", "{N}", part)
                    has_numbers[base] += 1

            for i in range(len(parts) - 1):
                bigrams[(parts[i], parts[i+1])] += 1

        depth_freq: Dict[int, Counter] = {}
        for depth, labels in labels_by_depth.items():
            depth_freq[depth] = Counter(labels)

        label_counter = Counter(all_labels)

        return {
            "label_patterns":  label_counter,
            "depth_freq":      depth_freq,
            "bigrams":         bigrams,
            "numeric_bases":   has_numbers,
            "max_depth":       max(labels_by_depth.keys()) if labels_by_depth else 1,
            "common_depths":   Counter(
                len(s[:-len(domain_suffix)].split("."))
                for s in subdomains
                if s.endswith(domain_suffix)
            ),
        }

    def _generate_candidates(
        self, patterns: Dict, domain: str, known: List[str]
    ) -> List[Tuple[str, float]]:
        """
        Generate candidate subdomains based on learned patterns.
        Returns list of (candidate, confidence_score).
        """
        known_set = set(known)
        candidates: Dict[str, float] = {}
        domain_suffix = f".{domain}"

        label_freq   = patterns["label_patterns"]
        depth_freq   = patterns["depth_freq"]
        bigrams      = patterns["bigrams"]
        common_depths= patterns["common_depths"]

        for target_depth, depth_count in common_depths.most_common(3):
            if target_depth == 1:

                top_labels = [l for l, _ in label_freq.most_common(30)]
                for label in top_labels:
                    candidate = f"{label}{domain_suffix}"
                    if candidate not in known_set:
                        score = label_freq[label] / max(label_freq.values())
                        candidates[candidate] = max(candidates.get(candidate, 0), score * 0.8)

            elif target_depth == 2:

                depth0_labels = [l for l, _ in depth_freq.get(0, Counter()).most_common(10)]
                depth1_labels = [l for l, _ in depth_freq.get(1, Counter()).most_common(10)]
                for l0 in depth0_labels:
                    for l1 in depth1_labels:
                        candidate = f"{l0}.{l1}{domain_suffix}"
                        if candidate not in known_set:
                            bigram_score = bigrams.get((l0, l1), 0)
                            base_score   = (label_freq[l0] + label_freq[l1]) / (2 * max(label_freq.values()))
                            score = (base_score + bigram_score * 0.3)
                            candidates[candidate] = max(candidates.get(candidate, 0), score * 0.7)

        for base, count in patterns["numeric_bases"].most_common(5):
            if count >= 2:
                for n in range(1, 6):
                    for d in range(patterns.get("max_depth", 1), 0, -1):
                        candidate_label = base.replace("{N}", str(n))
                        if d == 1:
                            candidate = f"{candidate_label}{domain_suffix}"
                        else:

                            if 1 in depth_freq:
                                top_d1 = depth_freq[1].most_common(1)[0][0]
                                candidate = f"{candidate_label}.{top_d1}{domain_suffix}"
                            else:
                                continue
                        if candidate not in known_set:
                            candidates[candidate] = 0.6

        bigram_graph: Dict[str, List[str]] = defaultdict(list)
        for (src, dst), count in bigrams.most_common(20):
            if count >= 2:
                bigram_graph[src].append(dst)

        for src, dsts in bigram_graph.items():
            for dst in dsts[:3]:
                candidate = f"{src}.{dst}{domain_suffix}"
                if candidate not in known_set:
                    candidates[candidate] = max(
                        candidates.get(candidate, 0),
                        bigrams[(src, dst)] / max(bigrams.values()) * 0.65
                    )

        semantic_variants = {
            "api":      ["api2", "api-v2", "api-v3", "api-prod", "api-staging", "api-internal"],
            "mail":     ["mail2", "smtp", "webmail", "imap", "pop"],
            "admin":    ["admin2", "administration", "backend", "control"],
            "dev":      ["dev2", "develop", "development", "developer"],
            "staging":  ["stg", "stage", "uat", "preprod"],
            "web":      ["web2", "www2", "portal", "site"],
            "db":       ["database", "mysql", "postgres", "mongo"],
            "cdn":      ["static", "assets", "media", "files"],
            "vpn":      ["vpn2", "remote", "access", "secure"],
            "auth":     ["login", "sso", "oauth", "identity"],
        }
        for label, variants in semantic_variants.items():
            if label in label_freq and label_freq[label] > 0:
                for variant in variants:
                    candidate = f"{variant}{domain_suffix}"
                    if candidate not in known_set:
                        candidates[candidate] = max(
                            candidates.get(candidate, 0),
                            label_freq[label] / max(label_freq.values()) * 0.5
                        )

        return [(c, s) for c, s in sorted(candidates.items(), key=lambda x: x[1], reverse=True)]

    def _score_candidates(
        self, candidates: List[Tuple[str, float]], known: List[str], domain: str
    ) -> List[Tuple[str, float]]:
        """
        Refine scores using graph structural features.
        Candidates structurally similar to high-degree known nodes score higher.
        """

        known_degrees: Dict[str, int] = {}
        for sub in known:
            entity = self.graph.get_by_name(sub)
            if entity:
                known_degrees[sub] = self.graph._graph.degree(entity.id)

        avg_degree = sum(known_degrees.values()) / len(known_degrees) if known_degrees else 1

        scored = []
        for candidate, base_score in candidates:

            label = candidate.split(".")[0]
            similar_degree_bonus = 0.0
            for known_sub, degree in known_degrees.items():
                known_label = known_sub.split(".")[0]
                if label[:3] == known_label[:3] and degree > avg_degree:
                    similar_degree_bonus = min(0.2, degree / (avg_degree * 10))
                    break

            final_score = min(1.0, base_score + similar_degree_bonus)
            if final_score >= self.threshold:
                scored.append((candidate, final_score))

        return sorted(scored, key=lambda x: x[1], reverse=True)

    async def _detect_wildcard(self, domain: str) -> set:
        """Detect wildcard DNS — *.domain resolves to same IPs for any subdomain."""
        import random, string
        wildcard_ips: set = set()
        for _ in range(3):
            rand = ''.join(random.choices(string.ascii_lowercase, k=12))
            fake = f"{rand}.{domain}"
            ips = await self.dns.resolve_a(fake)
            wildcard_ips.update(ips)
        return wildcard_ips

    async def _verify_candidates(
        self, candidates: List[Tuple[str, float]], domain: str
    ) -> List[str]:
        """Verify top candidates via DNS. Skips results matching wildcard IPs."""
        sem = asyncio.Semaphore(50)
        verified: List[str] = []
        lock = asyncio.Lock()

        wildcard_ips = await self._detect_wildcard(domain)
        if wildcard_ips:
            logger.debug(f"GNN: wildcard DNS detected for {domain} — {wildcard_ips}. Skipping predictions.")
            return []

        async def verify_one(candidate: str, score: float):
            async with sem:
                try:
                    ips = await self.dns.resolve_a(candidate)
                    if ips and not wildcard_ips.intersection(ips):
                        async with lock:
                            verified.append(candidate)

                        entity = self.graph.find_or_create(
                            EntityType.DOMAIN,
                            name=candidate,
                            properties={
                                "is_alive":       True,
                                "gnn_predicted":  True,
                                "gnn_confidence": round(score, 3),
                            },
                            source="gnn_prediction",
                        )

                        for ip in ips[:2]:
                            ip_entity = self.graph.find_or_create(
                                EntityType.IP, name=ip, source="gnn_prediction"
                            )
                            from argus.ontology.entities import RelationType
                            self.graph.link(entity.id, ip_entity.id,
                                            RelationType.RESOLVES_TO, source="gnn_prediction")
                            self.graph.index_ip_domain(ip, candidate)

                        logger.warning(f"GNN PREDICTION VERIFIED: {candidate} (confidence={score:.2f}) → {ips[0]}")
                except Exception:
                    pass

        await asyncio.gather(*[verify_one(c, s) for c, s in candidates], return_exceptions=True)
        return verified
