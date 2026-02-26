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
        'AI_MODEL_EXPOSED': [
            {
                'framework': 'EU AI Act',
                'reference': 'Article 15 — Accuracy, robustness, cybersecurity',
                'gap_text': 'An AI model is publicly reachable without access controls. Article 15 requires providers to protect high-risk AI systems against unauthorized access and ensure cybersecurity throughout the lifecycle. ACTION: Restrict the model endpoint to authenticated users, deploy API gateway controls, and document the access policy.',
                'severity': 'high',
            },
            {
                'framework': 'NIST AI RMF',
                'reference': 'MANAGE 2.2 — Risk treatment mechanisms',
                'gap_text': 'An exposed model means risk treatment controls are not effectively limiting access. MANAGE 2.2 requires that identified risks have corresponding treatment mechanisms in place. ACTION: Implement network-level access controls, add authentication, and update the risk treatment plan to cover this endpoint.',
                'severity': 'high',
            },
            {
                'framework': 'ISO 42001',
                'reference': 'Clause 8.4 — AI system operation',
                'gap_text': 'The model is accessible without operational security controls. Clause 8.4 requires organizations to operate AI systems under defined security conditions. ACTION: Place the model behind an authenticated gateway, log all access, and add the endpoint to operational monitoring.',
                'severity': 'high',
            },
        ],
        'AI_ENDPOINT_UNAUTHENTICATED': [
            {
                'framework': 'EU AI Act',
                'reference': 'Article 15 — Accuracy, robustness, cybersecurity',
                'gap_text': 'An AI inference endpoint accepts requests with no authentication. Article 15 mandates cybersecurity measures proportionate to risk, including preventing unauthorized manipulation. ACTION: Deploy authentication immediately (API key, OAuth, or mTLS), rate-limit the endpoint, and audit logs for prior unauthorized usage.',
                'severity': 'critical',
            },
            {
                'framework': 'NIST AI RMF',
                'reference': 'MANAGE 2.4 — Risk controls effectiveness',
                'gap_text': 'The absence of authentication on this endpoint proves access controls are ineffective. MANAGE 2.4 requires regular assessment of whether deployed controls actually mitigate identified risks. ACTION: Add authentication, conduct a control effectiveness review across all AI endpoints, and document findings.',
                'severity': 'critical',
            },
            {
                'framework': 'ISO 42001',
                'reference': 'Clause 7.5 — Documented information protection',
                'gap_text': 'Unauthenticated access to the AI system means documented information protection controls have failed. Clause 7.5 requires that information used by or produced by AI systems is protected from unauthorized access. ACTION: Enforce authentication, review all AI-adjacent endpoints for the same gap, and update the information protection register.',
                'severity': 'critical',
            },
        ],
        'AI_API_KEY_LEAKED': [
            {
                'framework': 'EU AI Act',
                'reference': 'Article 15 — Accuracy, robustness, cybersecurity',
                'gap_text': 'An AI platform API key was found in a public location. Leaked credentials allow unauthorized access to AI systems, directly violating Article 15 cybersecurity requirements. ACTION: Rotate the key immediately, scan all repositories and public sources for additional leaks, and implement pre-commit secret scanning.',
                'severity': 'critical',
            },
            {
                'framework': 'NIST AI RMF',
                'reference': 'MANAGE 2.2 — Risk treatment mechanisms',
                'gap_text': 'The leaked API key demonstrates that secret management controls are inadequate. MANAGE 2.2 requires mechanisms that effectively treat credential-related risks. ACTION: Rotate the key, deploy a secrets manager (e.g., Vault, AWS Secrets Manager), enforce secret scanning in CI/CD, and audit access logs for misuse.',
                'severity': 'critical',
            },
            {
                'framework': 'ISO 42001',
                'reference': 'Clause 7.5 — Documented information protection',
                'gap_text': 'A leaked credential exposes AI system access, violating information protection requirements under Clause 7.5. ACTION: Rotate the key immediately, investigate the scope of potential unauthorized access, implement automated secret detection, and update the credential management procedure.',
                'severity': 'critical',
            },
        ],
        'AI_MCP_SERVER_EXPOSED': [
            {
                'framework': 'EU AI Act',
                'reference': 'Article 14 — Human oversight',
                'gap_text': 'An exposed MCP (Model Context Protocol) server allows external parties to invoke AI agent tools without human oversight. Article 14 requires that high-risk AI systems have effective human oversight measures. ACTION: Restrict MCP server access to authorized networks, implement approval workflows for tool invocations, and add logging for all agent actions.',
                'severity': 'high',
            },
            {
                'framework': 'NIST AI RMF',
                'reference': 'GOVERN 1.2 — Roles and responsibilities',
                'gap_text': 'An exposed agent protocol server has no clear governance owner or access boundary. GOVERN 1.2 requires defined roles and responsibilities for AI risk management. ACTION: Assign an owner for this MCP server, restrict network access, and define who can authorize new tool registrations.',
                'severity': 'high',
            },
            {
                'framework': 'ISO 42001',
                'reference': 'Clause 6.1 — Actions to address risks',
                'gap_text': 'The exposed MCP server represents an unaddressed risk in the AI system risk register. Clause 6.1 requires planned actions to address risks and opportunities. ACTION: Add MCP server exposure to the risk register, implement network controls, and schedule a risk reassessment.',
                'severity': 'high',
            },
        ],
        'AI_SHADOW_SERVICE_DETECTED': [
            {
                'framework': 'EU AI Act',
                'reference': 'Article 17 — Quality management system',
                'gap_text': 'An unsanctioned AI service is operating outside the organization\'s quality management system. Article 17 requires providers to have a QMS covering all AI systems. ACTION: Identify the service owner, determine what data it processes, and either formalize it into the AI inventory or decommission it.',
                'severity': 'high',
            },
            {
                'framework': 'NIST AI RMF',
                'reference': 'GOVERN 1.1 — Legal and regulatory compliance',
                'gap_text': 'A shadow AI service is operating without compliance review. GOVERN 1.1 requires that all AI systems are subject to legal and regulatory compliance processes. ACTION: Identify the service owner, assess regulatory exposure (data residency, sector-specific rules), and bring it under governance or shut it down.',
                'severity': 'high',
            },
            {
                'framework': 'ISO 42001',
                'reference': 'Clause 9.1 — Monitoring and measurement',
                'gap_text': 'An untracked AI service cannot be monitored or measured for performance and risk. Clause 9.1 requires monitoring of all AI systems within scope. ACTION: Register the service in the AI inventory, deploy monitoring, or decommission it if it cannot be brought under management.',
                'severity': 'high',
            },
        ],
        'AI_VECTORDB_EXPOSED': [
            {
                'framework': 'EU AI Act',
                'reference': 'Article 10 — Data and data governance',
                'gap_text': 'A vector database is publicly accessible, potentially exposing training data or RAG knowledge base content. Article 10 requires appropriate data governance including access controls. ACTION: Restrict database access to authorized services only, audit stored embeddings for sensitive data, and implement encryption at rest.',
                'severity': 'high',
            },
            {
                'framework': 'NIST AI RMF',
                'reference': 'MAP 3.4 — Data quality and relevance',
                'gap_text': 'An exposed vector database may allow unauthorized reading or poisoning of AI training/retrieval data. MAP 3.4 requires that data quality and integrity are maintained. ACTION: Restrict access, enable audit logging, verify embedding integrity, and assess whether data poisoning may have occurred.',
                'severity': 'high',
            },
            {
                'framework': 'ISO 42001',
                'reference': 'Clause 7.5 — Documented information protection',
                'gap_text': 'The vector database is accessible without protection controls, violating Clause 7.5 requirements for documented information. ACTION: Implement authentication and network restrictions, classify the stored data by sensitivity, and add the database to the information protection register.',
                'severity': 'high',
            },
        ],
        'AI_AGENT_INFRASTRUCTURE_DETECTED': [
            {
                'framework': 'EU AI Act',
                'reference': 'Article 14 — Human oversight',
                'gap_text': 'AI agent infrastructure (autonomous tool-calling systems) was detected. Article 14 requires human oversight mechanisms proportionate to risk, especially for autonomous systems. ACTION: Verify that human-in-the-loop controls exist for high-impact agent actions, document the oversight mechanism, and test kill-switch functionality.',
                'severity': 'medium',
            },
            {
                'framework': 'NIST AI RMF',
                'reference': 'GOVERN 1.2 — Roles and responsibilities',
                'gap_text': 'AI agent infrastructure requires clearly defined governance roles to manage autonomous decision-making risk. GOVERN 1.2 requires that roles and responsibilities are documented. ACTION: Assign an owner, define escalation paths for agent failures, and document which tools the agent can invoke.',
                'severity': 'medium',
            },
            {
                'framework': 'ISO 42001',
                'reference': 'Clause 8.4 — AI system operation',
                'gap_text': 'Agent infrastructure must operate under defined controls per Clause 8.4. Autonomous agents pose unique operational risks including unintended actions and scope creep. ACTION: Document the agent\'s permitted actions, implement rate limits and scope restrictions, and include agents in operational monitoring.',
                'severity': 'medium',
            },
        ],
        'AI_VENDOR_WIDGET_DETECTED': [
            {
                'framework': 'EU AI Act',
                'reference': 'Article 17 — Quality management system',
                'gap_text': 'A third-party AI vendor widget is embedded in the application but may not be tracked in the AI system inventory. Article 17 requires the QMS to cover all AI components including third-party ones. ACTION: Add the vendor widget to the AI inventory, review the vendor\'s compliance documentation, and assess the widget\'s risk classification.',
                'severity': 'medium',
            },
            {
                'framework': 'NIST AI RMF',
                'reference': 'GOVERN 5.1 — Third-party AI risk',
                'gap_text': 'A third-party AI widget introduces supply chain risk that must be assessed. GOVERN 5.1 requires organizations to identify and manage third-party AI risks. ACTION: Conduct a vendor risk assessment, review data sharing agreements, and verify the vendor\'s own AI governance posture.',
                'severity': 'medium',
            },
            {
                'framework': 'ISO 42001',
                'reference': 'Clause 8.5 — External provision of AI systems',
                'gap_text': 'The third-party AI widget must be managed under Clause 8.5 external provision controls. Unmanaged third-party AI components create blind spots in governance. ACTION: Execute a supplier evaluation, define SLA and data processing terms, and include the widget in periodic AI system reviews.',
                'severity': 'medium',
            },
        ],
        'AI_HISTORICAL_EVIDENCE': [
            {
                'framework': 'EU AI Act',
                'reference': 'Article 17 — Quality management system',
                'gap_text': 'Historical evidence of AI infrastructure suggests AI systems may have been deployed without lifecycle documentation. Article 17 requires QMS documentation across the entire AI lifecycle including decommissioning. ACTION: Investigate whether the historical AI system is still active, check for residual data or models, and update lifecycle records.',
                'severity': 'low',
            },
            {
                'framework': 'NIST AI RMF',
                'reference': 'MAP 1.6 — System decommission',
                'gap_text': 'Historical AI evidence suggests systems may not have been properly decommissioned. MAP 1.6 requires that AI system retirement includes data disposal and access revocation. ACTION: Verify whether the system is fully decommissioned, check for lingering endpoints or credentials, and document the decommission status.',
                'severity': 'low',
            },
            {
                'framework': 'ISO 42001',
                'reference': 'Clause 9.1 — Monitoring and measurement',
                'gap_text': 'Historical AI activity was not tracked in change management records. Clause 9.1 requires ongoing monitoring that would capture system lifecycle transitions. ACTION: Investigate the historical evidence, update the AI system register, and ensure change management processes capture future AI deployments and retirements.',
                'severity': 'low',
            },
        ],
        'AI_COMPUTE_CLUSTER_EXPOSED': [
            {
                'framework': 'EU AI Act',
                'reference': 'Article 15 — Accuracy, robustness, cybersecurity',
                'gap_text': 'A GPU/compute cluster used for AI workloads is publicly accessible. Article 15 requires cybersecurity protections for AI infrastructure to prevent unauthorized access and model theft. ACTION: Restrict cluster access to VPN/private network, deploy authentication on management interfaces, and audit for unauthorized job submissions.',
                'severity': 'high',
            },
            {
                'framework': 'NIST AI RMF',
                'reference': 'MANAGE 2.2 — Risk treatment mechanisms',
                'gap_text': 'Exposed compute infrastructure creates a direct risk of resource abuse and model exfiltration. MANAGE 2.2 requires risk treatment mechanisms for identified threats. ACTION: Implement network segmentation, require authentication for job submission, and add the cluster to infrastructure monitoring.',
                'severity': 'high',
            },
            {
                'framework': 'ISO 42001',
                'reference': 'Clause 8.4 — AI system operation',
                'gap_text': 'The compute cluster is operating without adequate access controls, violating Clause 8.4 operational requirements. Exposed clusters can be abused for cryptomining or model theft. ACTION: Deploy network-level access controls, enable audit logging for all compute jobs, and add the cluster to the operational security baseline.',
                'severity': 'high',
            },
        ],
        'AI_DATA_PIPELINE_EXPOSED': [
            {
                'framework': 'EU AI Act',
                'reference': 'Article 10 — Data and data governance',
                'gap_text': 'An AI data pipeline (training, ETL, or feature engineering) is publicly accessible. Article 10 requires data governance measures including access controls over data used by AI systems. ACTION: Restrict pipeline access, audit data flows for PII or sensitive content, and implement encryption for data in transit and at rest.',
                'severity': 'high',
            },
            {
                'framework': 'NIST AI RMF',
                'reference': 'MAP 3.4 — Data quality and relevance',
                'gap_text': 'An exposed data pipeline allows unauthorized parties to view or tamper with AI training data, compromising data quality and integrity. MAP 3.4 requires data quality controls. ACTION: Restrict access, validate data integrity checksums, implement input validation, and assess whether data poisoning may have occurred.',
                'severity': 'high',
            },
            {
                'framework': 'ISO 42001',
                'reference': 'Clause 7.5 — Documented information protection',
                'gap_text': 'The data pipeline is accessible without protection, violating Clause 7.5. Exposed pipelines risk data leakage and integrity compromise. ACTION: Implement access controls and encryption in transit, classify pipeline data by sensitivity, and add to the information protection register.',
                'severity': 'high',
            },
        ],
        'AI_MODEL_REGISTRY_EXPOSED': [
            {
                'framework': 'EU AI Act',
                'reference': 'Article 17 — Quality management system',
                'gap_text': 'A model registry (e.g., MLflow, SageMaker) is publicly accessible. Article 17 requires quality management over AI model versioning and deployment. An exposed registry allows unauthorized model downloads or tampering. ACTION: Restrict access to authenticated users, enable audit logging, and review for unauthorized model modifications.',
                'severity': 'high',
            },
            {
                'framework': 'NIST AI RMF',
                'reference': 'MANAGE 4.1 — Risk monitoring',
                'gap_text': 'An exposed model registry undermines risk monitoring because unauthorized changes to models cannot be detected. MANAGE 4.1 requires ongoing risk monitoring. ACTION: Restrict access, implement model signing and integrity verification, and set up alerts for unauthorized registry modifications.',
                'severity': 'high',
            },
            {
                'framework': 'ISO 42001',
                'reference': 'Clause 8.4 — AI system operation',
                'gap_text': 'The model registry lacks operational access controls required by Clause 8.4. An unprotected registry allows model theft, poisoning, or unauthorized deployment. ACTION: Implement RBAC on the registry, enable audit trails, and integrate registry access into the operational security baseline.',
                'severity': 'high',
            },
        ],
        'AI_PASSIVE_RECON_HIT': [
            {
                'framework': 'EU AI Act',
                'reference': 'Article 13 — Transparency and information',
                'gap_text': 'AI infrastructure metadata was discovered through passive reconnaissance (DNS, certificates, HTTP headers). Article 13 requires transparency, but excessive metadata leakage reveals internal AI architecture to adversaries. ACTION: Review public-facing metadata for unnecessary AI system disclosure, minimize information leakage in DNS names, headers, and certificates.',
                'severity': 'low',
            },
            {
                'framework': 'NIST AI RMF',
                'reference': 'MAP 5.1 — Likelihood and impact characterization',
                'gap_text': 'Passive recon reveals AI infrastructure details that help adversaries characterize attack likelihood and impact. MAP 5.1 requires understanding how system information affects risk. ACTION: Audit public DNS, certificate, and header metadata for AI-related leakage and remove unnecessary identifiers.',
                'severity': 'low',
            },
            {
                'framework': 'ISO 42001',
                'reference': 'Clause 6.1 — Actions to address risks',
                'gap_text': 'Discoverable AI metadata constitutes a risk that should be addressed per Clause 6.1. Information leakage assists adversaries in mapping AI attack surface. ACTION: Conduct a metadata audit, remove unnecessary AI-identifying information from public records, and add metadata leakage to the risk register.',
                'severity': 'low',
            },
        ],
        'AI_LLM_VULN_DETECTED': [
            {
                'framework': 'EU AI Act',
                'reference': 'Article 15 — Accuracy, robustness, cybersecurity',
                'gap_text': 'A known LLM vulnerability (e.g., prompt injection, jailbreak, data extraction) was detected. Article 15 requires AI systems to be resilient against adversarial attacks. ACTION: Classify the vulnerability type (OWASP LLM Top 10), implement input/output filtering, apply vendor patches, and test mitigations.',
                'severity': 'high',
            },
            {
                'framework': 'NIST AI RMF',
                'reference': 'MANAGE 2.2 — Risk treatment mechanisms',
                'gap_text': 'A detected LLM vulnerability requires specific risk treatment. MANAGE 2.2 requires mechanisms to treat identified AI-specific risks including adversarial manipulation. ACTION: Document the vulnerability, implement guardrails (input validation, output filtering), and verify the fix through red-team testing.',
                'severity': 'high',
            },
            {
                'framework': 'ISO 42001',
                'reference': 'Clause 10.1 — Nonconformity and corrective action',
                'gap_text': 'The detected LLM vulnerability is a nonconformity requiring corrective action per Clause 10.1. ACTION: Log the vulnerability as a nonconformity, implement corrective controls, verify effectiveness through testing, and update the risk assessment to prevent recurrence.',
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
            "AI_MODEL_EXPOSED",
            "AI_ENDPOINT_UNAUTHENTICATED",
            "AI_API_KEY_LEAKED",
            "AI_MCP_SERVER_EXPOSED",
            "AI_SHADOW_SERVICE_DETECTED",
            "AI_VECTORDB_EXPOSED",
            "AI_AGENT_INFRASTRUCTURE_DETECTED",
            "AI_VENDOR_WIDGET_DETECTED",
            "AI_HISTORICAL_EVIDENCE",
            "AI_COMPUTE_CLUSTER_EXPOSED",
            "AI_DATA_PIPELINE_EXPOSED",
            "AI_MODEL_REGISTRY_EXPOSED",
            "AI_PASSIVE_RECON_HIT",
            "AI_LLM_VULN_DETECTED",
        ]

    def producedEvents(self):
        return ["AI_COMPLIANCE_GAP"]

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {event.module}")

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

            detail = (f"[{framework}] {checkpoint['reference']} ({checkpoint['severity'].upper()})\n"
                      f"Finding: {checkpoint['gap_text']}\n"
                      f"Evidence: {eventName} — {eventData[:200]}")

            evt = SpiderFootEvent(
                "AI_COMPLIANCE_GAP",
                detail,
                self.__class__.__name__, event)
            self.notifyListeners(evt)


# End of sfp_ai_compliance class
