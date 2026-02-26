# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_ai_compliance
# Purpose:     Map discovered AI findings to regulatory compliance frameworks
#              (EU AI Act, NIST AI RMF, ISO 42001) and report gaps.
#
# Author:      ASM-NG
#
# Created:     2026-02-25
# Copyright:   (c) ASM-NG 2026
# Licence:     MIT
# -------------------------------------------------------------------------------

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_ai_compliance(SpiderFootPlugin):

    meta = {
        'name': "AI Regulatory Compliance Gap Reporter",
        'summary': "Maps all discovered AI findings to regulatory compliance "
                   "frameworks including EU AI Act, NIST AI RMF, and "
                   "ISO 42001. Every AI finding translates to one or more "
                   "compliance checkpoints. Produces structured compliance "
                   "gap reports with framework references, gap descriptions, "
                   "and severity ratings.",
        'flags': [],
        'useCases': ["Footprint", "Investigate", "AI Attack Surface"],
        'categories': ["Reporting and Analysis"],
        'dataSource': {
            'website': "N/A",
            'model': "FREE_NOAUTH_UNLIMITED",
            'description': "Pure analysis module that maps AI discovery "
                           "findings to regulatory compliance checkpoints. "
                           "No external API required.",
        }
    }

    # Supported compliance frameworks
    FRAMEWORKS = [
        'EU AI Act',
        'NIST AI RMF',
        'ISO 42001',
    ]

    # Mapping of AI event types to compliance framework checkpoints
    COMPLIANCE_MAPPING = {
        'AI_INFRASTRUCTURE_DETECTED': [
            {
                'framework': 'EU AI Act',
                'reference': 'Article 9 — Risk Management',
                'gap_text': 'AI system detected without evidence of risk management system',
                'severity': 'medium',
            },
            {
                'framework': 'NIST AI RMF',
                'reference': 'MAP 1.1 — Intended purpose and context',
                'gap_text': 'AI infrastructure detected; verify intended purpose is documented',
                'severity': 'low',
            },
            {
                'framework': 'ISO 42001',
                'reference': 'Clause 8.2 — AI risk assessment',
                'gap_text': 'AI system operational; verify risk assessment is current',
                'severity': 'low',
            },
        ],
        'AI_MODEL_EXPOSED': [
            {
                'framework': 'EU AI Act',
                'reference': 'Article 15 — Accuracy, robustness, cybersecurity',
                'gap_text': 'AI model exposed externally without adequate access controls',
                'severity': 'high',
            },
            {
                'framework': 'NIST AI RMF',
                'reference': 'MANAGE 2.2 — Risk treatment mechanisms',
                'gap_text': 'Exposed model indicates inadequate risk treatment controls',
                'severity': 'high',
            },
            {
                'framework': 'ISO 42001',
                'reference': 'Clause 8.4 — AI system operation',
                'gap_text': 'Model exposure indicates operational security gap',
                'severity': 'high',
            },
        ],
        'AI_ENDPOINT_UNAUTHENTICATED': [
            {
                'framework': 'EU AI Act',
                'reference': 'Article 15 — Accuracy, robustness, cybersecurity',
                'gap_text': 'Unauthenticated AI endpoint violates cybersecurity requirements',
                'severity': 'critical',
            },
            {
                'framework': 'NIST AI RMF',
                'reference': 'MANAGE 2.4 — Risk controls effectiveness',
                'gap_text': 'Unauthenticated endpoint demonstrates ineffective access controls',
                'severity': 'critical',
            },
            {
                'framework': 'ISO 42001',
                'reference': 'Clause 7.5 — Documented information protection',
                'gap_text': 'Unauthenticated access to AI system violates information protection',
                'severity': 'critical',
            },
        ],
        'AI_API_KEY_LEAKED': [
            {
                'framework': 'EU AI Act',
                'reference': 'Article 15 — Accuracy, robustness, cybersecurity',
                'gap_text': 'Leaked AI API key indicates credential management failure',
                'severity': 'critical',
            },
            {
                'framework': 'NIST AI RMF',
                'reference': 'MANAGE 2.2 — Risk treatment mechanisms',
                'gap_text': 'API key leak demonstrates inadequate secret management',
                'severity': 'critical',
            },
            {
                'framework': 'ISO 42001',
                'reference': 'Clause 7.5 — Documented information protection',
                'gap_text': 'Credential leak violates information protection controls',
                'severity': 'critical',
            },
        ],
        'AI_MCP_SERVER_EXPOSED': [
            {
                'framework': 'EU AI Act',
                'reference': 'Article 14 — Human oversight',
                'gap_text': 'Exposed MCP server may lack required human oversight controls',
                'severity': 'high',
            },
            {
                'framework': 'NIST AI RMF',
                'reference': 'GOVERN 1.2 — Roles and responsibilities',
                'gap_text': 'Exposed agent protocol server indicates governance gap',
                'severity': 'high',
            },
            {
                'framework': 'ISO 42001',
                'reference': 'Clause 6.1 — Actions to address risks',
                'gap_text': 'MCP server exposure not addressed in risk planning',
                'severity': 'high',
            },
        ],
        'AI_SHADOW_SERVICE_DETECTED': [
            {
                'framework': 'EU AI Act',
                'reference': 'Article 17 — Quality management system',
                'gap_text': 'Shadow AI service not part of quality management system',
                'severity': 'high',
            },
            {
                'framework': 'NIST AI RMF',
                'reference': 'GOVERN 1.1 — Legal and regulatory compliance',
                'gap_text': 'Unsanctioned AI service may violate compliance requirements',
                'severity': 'high',
            },
            {
                'framework': 'ISO 42001',
                'reference': 'Clause 9.1 — Monitoring and measurement',
                'gap_text': 'Shadow AI not tracked in monitoring framework',
                'severity': 'high',
            },
        ],
        'AI_VECTORDB_EXPOSED': [
            {
                'framework': 'EU AI Act',
                'reference': 'Article 10 — Data and data governance',
                'gap_text': 'Exposed vector database indicates data governance failure',
                'severity': 'high',
            },
            {
                'framework': 'NIST AI RMF',
                'reference': 'MAP 3.4 — Data quality and relevance',
                'gap_text': 'Exposed vector DB may contain unprotected training/RAG data',
                'severity': 'high',
            },
            {
                'framework': 'ISO 42001',
                'reference': 'Clause 7.5 — Documented information protection',
                'gap_text': 'Vector database exposure violates data protection controls',
                'severity': 'high',
            },
        ],
        'AI_AGENT_INFRASTRUCTURE_DETECTED': [
            {
                'framework': 'EU AI Act',
                'reference': 'Article 14 — Human oversight',
                'gap_text': 'AI agent infrastructure requires human oversight mechanisms',
                'severity': 'medium',
            },
            {
                'framework': 'NIST AI RMF',
                'reference': 'GOVERN 1.2 — Roles and responsibilities',
                'gap_text': 'Agent infrastructure needs defined governance roles',
                'severity': 'medium',
            },
            {
                'framework': 'ISO 42001',
                'reference': 'Clause 8.4 — AI system operation',
                'gap_text': 'Agent infrastructure must be included in operational controls',
                'severity': 'medium',
            },
        ],
        'AI_GOVERNANCE_FINDING': [
            {
                'framework': 'EU AI Act',
                'reference': 'Article 13 — Transparency and information',
                'gap_text': 'AI governance posture indicates transparency obligations may not be met',
                'severity': 'medium',
            },
            {
                'framework': 'NIST AI RMF',
                'reference': 'GOVERN 1.1 — Legal and regulatory compliance',
                'gap_text': 'Governance finding indicates compliance posture gap',
                'severity': 'medium',
            },
            {
                'framework': 'ISO 42001',
                'reference': 'Clause 10.1 — Nonconformity and corrective action',
                'gap_text': 'Governance gap requires corrective action process',
                'severity': 'medium',
            },
        ],
        'AI_VENDOR_WIDGET_DETECTED': [
            {
                'framework': 'EU AI Act',
                'reference': 'Article 17 — Quality management system',
                'gap_text': 'Third-party AI vendor widget may not be tracked in AI inventory',
                'severity': 'medium',
            },
            {
                'framework': 'NIST AI RMF',
                'reference': 'GOVERN 5.1 — Third-party AI risk',
                'gap_text': 'Third-party AI vendor requires supply chain risk assessment',
                'severity': 'medium',
            },
            {
                'framework': 'ISO 42001',
                'reference': 'Clause 8.5 — External provision of AI systems',
                'gap_text': 'Third-party AI vendor must be managed per external provision controls',
                'severity': 'medium',
            },
        ],
        'AI_HISTORICAL_EVIDENCE': [
            {
                'framework': 'EU AI Act',
                'reference': 'Article 17 — Quality management system',
                'gap_text': 'Historical AI infrastructure may indicate undocumented AI lifecycle',
                'severity': 'low',
            },
            {
                'framework': 'NIST AI RMF',
                'reference': 'MAP 1.6 — System decommission',
                'gap_text': 'Historical evidence suggests AI systems may not have been properly decommissioned',
                'severity': 'low',
            },
            {
                'framework': 'ISO 42001',
                'reference': 'Clause 9.1 — Monitoring and measurement',
                'gap_text': 'Historical AI evidence not tracked in change management records',
                'severity': 'low',
            },
        ],
        'AI_COMPUTE_CLUSTER_EXPOSED': [
            {
                'framework': 'EU AI Act',
                'reference': 'Article 15 — Accuracy, robustness, cybersecurity',
                'gap_text': 'Exposed GPU/compute cluster indicates infrastructure security gap',
                'severity': 'high',
            },
            {
                'framework': 'NIST AI RMF',
                'reference': 'MANAGE 2.2 — Risk treatment mechanisms',
                'gap_text': 'Exposed compute infrastructure requires risk treatment',
                'severity': 'high',
            },
            {
                'framework': 'ISO 42001',
                'reference': 'Clause 8.4 — AI system operation',
                'gap_text': 'Compute cluster exposure indicates operational security failure',
                'severity': 'high',
            },
        ],
        'AI_DATA_PIPELINE_EXPOSED': [
            {
                'framework': 'EU AI Act',
                'reference': 'Article 10 — Data and data governance',
                'gap_text': 'Exposed data pipeline violates data governance requirements',
                'severity': 'high',
            },
            {
                'framework': 'NIST AI RMF',
                'reference': 'MAP 3.4 — Data quality and relevance',
                'gap_text': 'Exposed pipeline may compromise data quality and integrity',
                'severity': 'high',
            },
            {
                'framework': 'ISO 42001',
                'reference': 'Clause 7.5 — Documented information protection',
                'gap_text': 'Data pipeline exposure violates information protection controls',
                'severity': 'high',
            },
        ],
        'AI_MODEL_REGISTRY_EXPOSED': [
            {
                'framework': 'EU AI Act',
                'reference': 'Article 17 — Quality management system',
                'gap_text': 'Exposed model registry undermines quality management controls',
                'severity': 'high',
            },
            {
                'framework': 'NIST AI RMF',
                'reference': 'MANAGE 4.1 — Risk monitoring',
                'gap_text': 'Model registry exposure indicates risk monitoring failure',
                'severity': 'high',
            },
            {
                'framework': 'ISO 42001',
                'reference': 'Clause 8.4 — AI system operation',
                'gap_text': 'Model registry exposure indicates operational controls gap',
                'severity': 'high',
            },
        ],
    }

    opts = {
        'frameworks': "EU AI Act,NIST AI RMF,ISO 42001",
        'min_findings': 1,
    }

    optdescs = {
        'frameworks': "Comma-separated list of compliance frameworks to check against.",
        'min_findings': "Minimum number of AI findings before generating compliance gaps.",
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self._finding_count = 0
        self._enabled_frameworks = []

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

        self._enabled_frameworks = [
            f.strip() for f in self.opts['frameworks'].split(',')
            if f.strip()
        ]

    def watchedEvents(self):
        return [
            "AI_INFRASTRUCTURE_DETECTED",
            "AI_MODEL_EXPOSED",
            "AI_ENDPOINT_UNAUTHENTICATED",
            "AI_API_KEY_LEAKED",
            "AI_MCP_SERVER_EXPOSED",
            "AI_SHADOW_SERVICE_DETECTED",
            "AI_VECTORDB_EXPOSED",
            "AI_AGENT_INFRASTRUCTURE_DETECTED",
            "AI_GOVERNANCE_FINDING",
            "AI_VENDOR_WIDGET_DETECTED",
            "AI_HISTORICAL_EVIDENCE",
            "AI_COMPUTE_CLUSTER_EXPOSED",
            "AI_DATA_PIPELINE_EXPOSED",
            "AI_MODEL_REGISTRY_EXPOSED",
        ]

    def producedEvents(self):
        return ["AI_COMPLIANCE_GAP", "AI_INFRASTRUCTURE_DETECTED"]

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {event.module}")

        # Skip our own output to avoid loops
        if eventName == "AI_INFRASTRUCTURE_DETECTED" and "compliance" in eventData.lower():
            return

        # Dedup by event type + data prefix
        dedup_key = f"compliance:{eventName}:{eventData[:150]}"
        if dedup_key in self.results:
            self.debug(f"Already processed compliance for this event, skipping.")
            return
        self.results[dedup_key] = True

        self._finding_count += 1

        if self._finding_count < self.opts['min_findings']:
            self.debug(f"Below min_findings threshold ({self._finding_count}/"
                       f"{self.opts['min_findings']}), deferring compliance gaps.")
            return

        # Look up compliance checkpoints for this event type
        checkpoints = self.COMPLIANCE_MAPPING.get(eventName, [])

        if not checkpoints:
            self.debug(f"No compliance mapping for {eventName}.")
            return

        for checkpoint in checkpoints:
            if self.checkForStop():
                return

            framework = checkpoint['framework']

            # Only emit for enabled frameworks
            if framework not in self._enabled_frameworks:
                continue

            gap_key = f"gap:{framework}:{checkpoint['reference']}:{eventName}"
            if gap_key in self.results:
                continue
            self.results[gap_key] = True

            detail = (f"[{framework}] {checkpoint['reference']}: "
                      f"{checkpoint['gap_text']} "
                      f"(severity: {checkpoint['severity']}, "
                      f"evidence: {eventName})")

            evt = SpiderFootEvent(
                "AI_COMPLIANCE_GAP",
                detail,
                self.__class__.__name__, event)
            self.notifyListeners(evt)


# End of sfp_ai_compliance class
