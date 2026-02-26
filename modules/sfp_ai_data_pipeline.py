# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_ai_data_pipeline
# Purpose:     Detect exposed ML data pipelines and experiment trackers
#              (Airflow, MLflow, Label Studio, Feast, W&B) that may leak
#              training data, model artifacts, or feature store contents.
#
# Author:      ASM-NG
#
# Created:     2026-02-25
# Copyright:   (c) ASM-NG 2026
# Licence:     MIT
# -------------------------------------------------------------------------------

import json
import re

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_ai_data_pipeline(SpiderFootPlugin):

    meta = {
        'name': "AI Data Pipeline Scanner",
        'summary': "Detect exposed ML data pipelines and experiment trackers "
                   "such as Apache Airflow, MLflow, Label Studio, Feast, and "
                   "Weights & Biases. Identifies unauthenticated access to "
                   "training data, DAG definitions, and feature stores.",
        'flags': ["slow", "invasive"],
        'useCases': ["Footprint", "Investigate", "AI Attack Surface"],
        'categories': ["Crawling and Scanning"],
        'dataSource': {
            'website': "N/A",
            'model': "FREE_NOAUTH_UNLIMITED",
            'description': "Probes common ML data pipeline endpoints for "
                           "unauthenticated access to Airflow DAGs, MLflow "
                           "experiments, Label Studio projects, and Feast "
                           "feature services.",
        }
    }

    # (port, path, response_check, service_name, has_training_data)
    PIPELINE_PROBES = [
        ('8080', '/api/v1/dags', 'dags', 'Apache Airflow', False),
        ('5000', '/api/2.0/mlflow/experiments/search', 'experiments', 'MLflow Tracking', False),
        ('8080', '/api/projects', 'results', 'Label Studio', True),
        ('6566', '/feature-store/v1/feature-services', None, 'Feast Feature Store', False),
    ]

    ML_DAG_KEYWORDS = [
        'training', 'inference', 'embedding', 'finetune', 'fine_tune',
        'fine-tune', 'ml_pipeline', 'ml-pipeline', 'model_train',
        'feature_engineer', 'data_prep', 'etl_ml', 'llm', 'vector', 'rag',
    ]

    opts = {
        'probe_timeout': 10,
        'check_dag_names': True,
    }

    optdescs = {
        'probe_timeout': "Timeout in seconds for each data pipeline probe.",
        'check_dag_names': "Analyze Airflow DAG names for ML/AI-related keywords.",
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return [
            "TCP_PORT_OPEN",
            "INTERNET_NAME",
            "AI_INFRASTRUCTURE_DETECTED",
        ]

    def producedEvents(self):
        return [
            "AI_DATA_PIPELINE_EXPOSED",
            "AI_TRAINING_DATA_EXPOSED",
            "AI_INFRASTRUCTURE_DETECTED",
            "AI_ENDPOINT_UNAUTHENTICATED",
        ]

    def _extract_host_port(self, data):
        """Extract host and port from event data string."""
        # Try direct IP:port format
        match = re.search(r'(\d+\.\d+\.\d+\.\d+):(\d+)', data)
        if match:
            return match.group(1), match.group(2)

        # Try hostname:port
        match = re.search(r'([\w.-]+):(\d+)', data)
        if match:
            return match.group(1), match.group(2)

        return None, None

    def _check_ml_dags(self, dags_data):
        """Check a list of Airflow DAG dicts for ML/AI-related keywords.

        Args:
            dags_data: list of DAG objects from the Airflow API response.

        Returns:
            list of DAG IDs that match ML keywords.
        """
        ml_dags = []
        if not isinstance(dags_data, list):
            return ml_dags

        for dag in dags_data:
            if not isinstance(dag, dict):
                continue
            dag_id = dag.get('dag_id', '')
            if not dag_id:
                continue
            dag_id_lower = dag_id.lower()
            for keyword in self.ML_DAG_KEYWORDS:
                if keyword in dag_id_lower:
                    ml_dags.append(dag_id)
                    break

        return ml_dags

    def _probe_pipeline(self, host, port, path, response_check, service_name,
                        has_training_data, event):
        """Probe a single pipeline endpoint over http then https.

        Returns True if the service was detected, False otherwise.
        """
        for scheme in ['http', 'https']:
            if self.checkForStop():
                return False

            url = f"{scheme}://{host}:{port}{path}"

            try:
                res = self.sf.fetchUrl(
                    url,
                    timeout=self.opts['probe_timeout'],
                    useragent=self.opts.get('_useragent', 'ASM-NG')
                )
            except Exception:
                continue

            if not res:
                continue

            code = str(res.get('code', ''))
            content = res.get('content', '') or ''

            if not code.startswith('2'):
                continue

            # If response_check is None, any 2xx is a match
            if response_check is not None:
                try:
                    parsed = json.loads(content)
                except (json.JSONDecodeError, ValueError):
                    continue

                if not isinstance(parsed, dict):
                    continue

                if response_check not in parsed:
                    continue
            else:
                # For probes without a response_check, a 2xx with
                # non-empty content is sufficient
                if not content.strip():
                    continue
                try:
                    parsed = json.loads(content)
                except (json.JSONDecodeError, ValueError):
                    parsed = {}

            # --- Match confirmed ---
            detail = (f"{service_name} detected on {host}:{port} "
                      f"({scheme}) — endpoint {path} accessible "
                      f"without authentication")

            # Airflow ML DAG analysis
            if service_name == 'Apache Airflow' and self.opts['check_dag_names']:
                dags_list = parsed.get('dags', []) if isinstance(parsed, dict) else []
                ml_dags = self._check_ml_dags(dags_list)
                if ml_dags:
                    detail += (f"\nML/AI-related DAGs found: "
                               f"{', '.join(ml_dags[:20])}")
                    if len(ml_dags) > 20:
                        detail += f" ... (+{len(ml_dags) - 20} more)"

            # Emit AI_DATA_PIPELINE_EXPOSED
            evt_pipeline = SpiderFootEvent(
                "AI_DATA_PIPELINE_EXPOSED", detail,
                self.__class__.__name__, event)
            self.notifyListeners(evt_pipeline)

            # Emit AI_INFRASTRUCTURE_DETECTED
            evt_infra = SpiderFootEvent(
                "AI_INFRASTRUCTURE_DETECTED",
                f"{service_name} on {host}:{port}",
                self.__class__.__name__, evt_pipeline)
            self.notifyListeners(evt_infra)

            # Emit AI_ENDPOINT_UNAUTHENTICATED
            evt_unauth = SpiderFootEvent(
                "AI_ENDPOINT_UNAUTHENTICATED",
                f"{service_name} accessible without authentication "
                f"on {host}:{port}",
                self.__class__.__name__, evt_pipeline)
            self.notifyListeners(evt_unauth)

            # If this service exposes training data, emit that too
            if has_training_data:
                training_detail = (f"{service_name} on {host}:{port} may "
                                   f"expose training/annotation data")
                evt_training = SpiderFootEvent(
                    "AI_TRAINING_DATA_EXPOSED", training_detail,
                    self.__class__.__name__, evt_pipeline)
                self.notifyListeners(evt_training)

            return True

        return False

    def _run_probes_for_host(self, host, port, event):
        """Run matching pipeline probes for a given host and port."""
        key = f"pipeline:{host}:{port}"
        if key in self.results:
            return
        self.results[key] = True

        matching_probes = [p for p in self.PIPELINE_PROBES if p[0] == port]
        if not matching_probes:
            return

        for probe_port, path, response_check, service_name, has_training_data in matching_probes:
            if self.checkForStop():
                return
            self._probe_pipeline(
                host, port, path, response_check, service_name,
                has_training_data, event)

    def _run_all_probes_for_host(self, host, event):
        """Run all pipeline probes against a host (used for INTERNET_NAME)."""
        # Collect unique ports from probes
        ports = list(dict.fromkeys(p[0] for p in self.PIPELINE_PROBES))

        for port in ports:
            if self.checkForStop():
                return

            key = f"pipeline:{host}:{port}"
            if key in self.results:
                continue
            self.results[key] = True

            matching_probes = [p for p in self.PIPELINE_PROBES if p[0] == port]
            for probe_port, path, response_check, service_name, has_training_data in matching_probes:
                if self.checkForStop():
                    return
                self._probe_pipeline(
                    host, port, path, response_check, service_name,
                    has_training_data, event)

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {event.module}")

        # Don't process our own events
        if event.module == self.__class__.__name__:
            return

        if eventName == "TCP_PORT_OPEN":
            host, port = self._extract_host_port(eventData)
            if not host or not port:
                return

            self._run_probes_for_host(host, port, event)

        elif eventName == "INTERNET_NAME":
            key = f"pipeline:hostname:{eventData}"
            if key in self.results:
                return
            self.results[key] = True

            self._run_all_probes_for_host(eventData, event)

        elif eventName == "AI_INFRASTRUCTURE_DETECTED":
            # Only process if it references a relevant pipeline service
            data_lower = eventData.lower()
            if not any(kw in data_lower for kw in ['airflow', 'mlflow', 'label', 'feast']):
                return

            host, port = self._extract_host_port(eventData)
            if not host:
                return

            if port:
                self._run_probes_for_host(host, port, event)
            else:
                # No port found in the data — try all pipeline ports
                self._run_all_probes_for_host(host, event)


# End of sfp_ai_data_pipeline class
