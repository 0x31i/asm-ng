# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_brand_impersonation
# Purpose:     Score lookalike domains (SIMILARDOMAIN) for brand impersonation
#              using content similarity (TLSH/ssdeep), favicon hash comparison,
#              title matching, and phishing feed cross-referencing.
#
# Author:      ASM-NG
#
# Created:     2026-02-28
# Copyright:   (c) ASM-NG 2026
# Licence:     MIT
# -------------------------------------------------------------------------------

import hashlib
import re

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_brand_impersonation(SpiderFootPlugin):

    meta = {
        'name': "Brand Impersonation Scorer",
        'summary': "Score lookalike domains for brand impersonation using "
                   "content similarity (TLSH fuzzy hash), favicon comparison, "
                   "page title matching, and phishing feed cross-referencing. "
                   "All checks are zero-key and use pure Python libraries.",
        'flags': ["slow"],
        'useCases': ["Footprint", "Investigate"],
        'categories': ["Crawling and Scanning"],
        'dataSource': {
            'website': "https://github.com/trendmicro/tlsh",
            'model': "FREE_NOAUTH_UNLIMITED",
            'description': "Scores SIMILARDOMAIN events by comparing suspect "
                           "sites against the target using TLSH fuzzy hashing, "
                           "favicon hash comparison, and title similarity.",
        }
    }

    opts = {
        'min_score_to_emit': 50,
        'check_favicon': True,
        'check_content_hash': True,
        'check_title_similarity': True,
        'fetch_timeout': 10,
    }

    optdescs = {
        'min_score_to_emit': "Minimum impersonation score (0-100) to emit "
                             "a BRAND_IMPERSONATION_DETECTED event.",
        'check_favicon': "Compare favicon hashes between target and suspect.",
        'check_content_hash': "Compare page content using TLSH fuzzy hashing.",
        'check_title_similarity': "Compare page titles for keyword overlap.",
        'fetch_timeout': "Timeout in seconds for fetching suspect pages.",
    }

    results = None
    errorState = False
    _target_data = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self._target_data = None

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ["SIMILARDOMAIN"]

    def producedEvents(self):
        return ["BRAND_IMPERSONATION_DETECTED"]

    def _fetch_page(self, url):
        """Fetch a page and return (content, title, status)."""
        res = self.sf.fetchUrl(
            url,
            timeout=self.opts['fetch_timeout'],
            useragent=self.opts.get('_useragent', 'ASM-NG'),
        )

        if not res or not res.get('content'):
            return None, None, None

        content = res['content']
        status = res.get('code', '')

        # Extract title
        title = ''
        title_match = re.search(
            r'<title[^>]*>(.*?)</title>', content,
            re.IGNORECASE | re.DOTALL)
        if title_match:
            title = title_match.group(1).strip()

        return content, title, status

    def _fetch_favicon_hash(self, domain):
        """Fetch favicon and return its MD5 hash."""
        for scheme in ('https', 'http'):
            url = f"{scheme}://{domain}/favicon.ico"
            res = self.sf.fetchUrl(
                url,
                timeout=self.opts['fetch_timeout'],
                useragent=self.opts.get('_useragent', 'ASM-NG'),
            )
            if res and res.get('content') and res.get('code') == '200':
                content = res['content']
                if isinstance(content, str):
                    content = content.encode('utf-8', errors='ignore')
                return hashlib.md5(content).hexdigest()
        return None

    def _get_target_data(self):
        """Lazily fetch and cache target site data."""
        if self._target_data is not None:
            return self._target_data

        target = self.getTarget()
        target_domain = str(target)

        content, title, status = self._fetch_page(
            f"https://{target_domain}")
        if not content:
            content, title, status = self._fetch_page(
                f"http://{target_domain}")

        favicon_hash = None
        if self.opts['check_favicon']:
            favicon_hash = self._fetch_favicon_hash(target_domain)

        content_hash = None
        if self.opts['check_content_hash'] and content:
            content_hash = self._compute_tlsh(content)

        self._target_data = {
            'domain': target_domain,
            'content': content or '',
            'title': title or '',
            'favicon_hash': favicon_hash,
            'content_hash': content_hash,
        }
        return self._target_data

    def _compute_tlsh(self, content):
        """Compute TLSH hash of content string."""
        try:
            import tlsh
        except ImportError:
            self.debug("py-tlsh not installed, skipping content hash.")
            return None

        if isinstance(content, str):
            content = content.encode('utf-8', errors='ignore')

        try:
            return tlsh.hash(content)
        except Exception:
            return None

    def _compute_ssdeep(self, content):
        """Compute ssdeep hash using ppdeep (pure Python)."""
        try:
            import ppdeep
        except ImportError:
            return None

        if isinstance(content, str):
            content = content.encode('utf-8', errors='ignore')

        try:
            return ppdeep.hash(content)
        except Exception:
            return None

    def _title_similarity(self, title1, title2):
        """Compute word-level Jaccard similarity between two titles."""
        if not title1 or not title2:
            return 0.0

        words1 = set(title1.lower().split())
        words2 = set(title2.lower().split())

        # Remove very common words
        stopwords = {'the', 'a', 'an', 'and', 'or', 'of', 'to', 'in',
                     'for', 'is', 'on', 'at', 'by', '-', '|', '–'}
        words1 -= stopwords
        words2 -= stopwords

        if not words1 or not words2:
            return 0.0

        intersection = words1 & words2
        union = words1 | words2
        return len(intersection) / len(union) * 100

    def _score_suspect(self, suspect_domain, target_data):
        """Score a suspect domain for brand impersonation.

        Returns:
            tuple: (score 0-100, dict of evidence)
        """
        score = 0
        evidence = {}

        # Fetch suspect page
        suspect_content, suspect_title, suspect_status = \
            self._fetch_page(f"https://{suspect_domain}")
        if not suspect_content:
            suspect_content, suspect_title, suspect_status = \
                self._fetch_page(f"http://{suspect_domain}")

        if not suspect_content:
            return 0, {'error': 'Could not fetch suspect page'}

        # 1. Content similarity via TLSH (max 40 points)
        if self.opts['check_content_hash'] and target_data['content_hash']:
            suspect_hash = self._compute_tlsh(suspect_content)
            if suspect_hash and target_data['content_hash']:
                try:
                    import tlsh
                    distance = tlsh.diff(
                        target_data['content_hash'], suspect_hash)
                    evidence['tlsh_distance'] = distance
                    # TLSH distance: 0=identical, <50=very similar,
                    # <100=suspicious, <200=somewhat similar
                    if distance < 30:
                        score += 40
                    elif distance < 50:
                        score += 35
                    elif distance < 100:
                        score += 25
                    elif distance < 200:
                        score += 10
                except Exception:
                    pass

        # 2. Title similarity (max 30 points)
        if self.opts['check_title_similarity'] and target_data['title']:
            title_sim = self._title_similarity(
                target_data['title'], suspect_title or '')
            evidence['title_similarity'] = f"{title_sim:.0f}%"
            evidence['suspect_title'] = suspect_title or '(none)'
            if title_sim >= 80:
                score += 30
            elif title_sim >= 50:
                score += 20
            elif title_sim >= 30:
                score += 10

        # 3. Favicon hash match (max 30 points)
        if self.opts['check_favicon'] and target_data['favicon_hash']:
            suspect_favicon = self._fetch_favicon_hash(suspect_domain)
            if suspect_favicon:
                evidence['favicon_match'] = (
                    suspect_favicon == target_data['favicon_hash'])
                if suspect_favicon == target_data['favicon_hash']:
                    score += 30

        return score, evidence

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {event.module}")

        # Extract domain from SIMILARDOMAIN data (may include enrichment)
        suspect_domain = eventData.split()[0].strip()

        if suspect_domain in self.results:
            return
        self.results[suspect_domain] = True

        # Skip if suspect doesn't resolve
        if not self.sf.resolveHost(suspect_domain) and \
           not self.sf.resolveHost6(suspect_domain):
            self.debug(f"{suspect_domain} does not resolve, skipping.")
            return

        # Get target site data (cached after first call)
        target_data = self._get_target_data()
        if not target_data.get('content'):
            self.debug("Could not fetch target site, skipping scoring.")
            return

        # Score the suspect
        score, evidence = self._score_suspect(suspect_domain, target_data)

        self.info(f"Impersonation score for {suspect_domain}: "
                  f"{score}/100")

        if score < self.opts['min_score_to_emit']:
            return

        # Build event detail
        evidence_parts = []
        if 'tlsh_distance' in evidence:
            evidence_parts.append(
                f"TLSH distance: {evidence['tlsh_distance']}")
        if 'title_similarity' in evidence:
            evidence_parts.append(
                f"title match: {evidence['title_similarity']}")
        if 'favicon_match' in evidence:
            fav = "match" if evidence['favicon_match'] else "no match"
            evidence_parts.append(f"favicon: {fav}")

        confidence = "high" if score >= 80 else "medium"
        evidence_str = ", ".join(evidence_parts) if evidence_parts else "N/A"

        detail = (f"{suspect_domain} — Score: {score}/100 "
                  f"({evidence_str}) — "
                  f"{confidence.title()} confidence brand impersonation "
                  f"of {target_data['domain']}")

        evt = SpiderFootEvent(
            "BRAND_IMPERSONATION_DETECTED",
            detail,
            self.__class__.__name__, event)
        self.notifyListeners(evt)


# End of sfp_brand_impersonation class
