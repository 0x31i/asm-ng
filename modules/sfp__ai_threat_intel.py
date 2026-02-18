# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_ai_threat_intel
# Purpose:      Threat Intelligence Engine
#
# Author:       Enhancement Team
# Created:      2025-06-20
# Copyright:    (c) ASM-NG 2025
# License:      MIT
# -------------------------------------------------------------------------------

"""
Threat Intelligence Engine

This module implements threat intelligence capabilities:
- Pattern recognition for attack detection
- Trend analysis for threat forecasting
- Automated IOC correlation across data sources
- Heuristic-based threat scoring
- Text processing for unstructured data analysis
"""

import os
import time
import json
import threading
from typing import Dict, List, Optional, Any, Tuple, Union
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
import hashlib
import logging

log = logging.getLogger(f"spiderfoot.{__name__}")
import pickle
from datetime import datetime, timedelta
import re
import statistics

# Lightweight numpy-like functions for basic operations
def mean(values):
    """Calculate mean of values."""
    return sum(values) / len(values) if values else 0

def std_dev(values):
    """Calculate standard deviation."""
    if not values or len(values) < 2:
        return 0
    m = mean(values)
    variance = sum((x - m) ** 2 for x in values) / len(values)
    return variance ** 0.5

# Try to import ML libraries, fallback to basic implementations
try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False
    # Use our basic implementations
    class np:
        @staticmethod
        def array(data):
            return data
        @staticmethod
        def mean(data):
            return mean(data) if isinstance(data, list) else mean([data])
        @staticmethod
        def std(data):
            return std_dev(data) if isinstance(data, list) else 0

try:
    import sklearn
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.cluster import DBSCAN
    from sklearn.preprocessing import StandardScaler
    import pandas as pd
    HAS_ML_LIBS = True
except ImportError:
    HAS_ML_LIBS = False

try:
    import nltk
    from nltk.sentiment import SentimentIntensityAnalyzer
    from nltk.tokenize import word_tokenize
    from nltk.corpus import stopwords
    HAS_NLTK = True
except ImportError:
    HAS_NLTK = False

from spiderfoot import SpiderFootPlugin, SpiderFootEvent


@dataclass
class ThreatSignature:
    """Represents a threat signature with ML features."""
    signature_id: str
    threat_type: str
    confidence_score: float
    features: Dict[str, Any]
    indicators: List[str]
    created_at: datetime
    last_seen: datetime
    frequency: int = 1
    severity: str = "medium"
    false_positive_rate: float = 0.0


@dataclass
class ThreatPrediction:
    """Represents a threat prediction from ML models."""
    prediction_id: str
    threat_type: str
    probability: float
    risk_score: float
    time_horizon: int  # hours
    confidence_interval: Tuple[float, float]
    contributing_factors: List[str]
    recommended_actions: List[str]


@dataclass
class IOCCorrelation:
    """Represents correlated indicators of compromise."""
    correlation_id: str
    primary_ioc: str
    related_iocs: List[str]
    correlation_strength: float
    temporal_relationship: str  # "simultaneous", "sequential", "periodic"
    attack_chain_position: int
    campaign_id: Optional[str] = None


@dataclass
class CrossScanCorrelation:
    """Represents correlation findings across multiple scans."""
    correlation_id: str
    current_ioc: str
    historical_iocs: List[str]
    source_scans: List[Dict[str, Any]]  # [{scan_id, scan_name, scan_date}]
    correlation_type: str  # "exact_match", "related", "pattern"
    confidence: float
    first_seen: datetime
    last_seen: datetime
    occurrence_count: int
    trend: str  # "increasing", "decreasing", "stable", "new"


class PatternRecognitionEngine:
    """Pattern recognition for attack detection."""
    
    # Minimum samples needed before fitting the IsolationForest model
    MIN_TRAINING_SAMPLES = 50

    def __init__(self):
        self.models = {}
        self.feature_extractors = {}
        self.threat_signatures = {}
        self.model_lock = threading.RLock()
        self.training_data = defaultdict(list)
        self.anomaly_detector = None
        self._training_features = []
        self._model_fitted = False
        self._initialize_models()
    
    def _initialize_models(self):
        """Initialize ML models for pattern recognition."""
        if not HAS_ML_LIBS:
            log.warning("ML libraries not available, pattern recognition disabled")
            return
        
        try:
            # Anomaly detection model
            self.anomaly_detector = IsolationForest(
                contamination=0.1,
                random_state=42,
                n_estimators=100
            )
            
            # Threat classification model
            self.models['threat_classifier'] = RandomForestClassifier(
                n_estimators=200,
                max_depth=10,
                random_state=42
            )
            
            # Feature extractors
            self.feature_extractors['text'] = TfidfVectorizer(
                max_features=1000,
                stop_words='english',
                ngram_range=(1, 3)
            )            
            self.feature_extractors['scaler'] = StandardScaler()
            
            log.info("Pattern recognition models initialized successfully")
            
        except Exception as e:
            log.error(f"Failed to initialize ML models: {e}")
    
    def extract_features(self, event_data: Dict[str, Any]) -> List[float]:
        """Extract ML features from event data."""
        features = []
        
        # Temporal features
        timestamp = event_data.get('timestamp', time.time())
        dt = datetime.fromtimestamp(timestamp)
        features.extend([
            dt.hour,  # Hour of day
            dt.weekday(),  # Day of week
            dt.month,  # Month
            int(timestamp % 86400)  # Seconds since midnight
        ])
        
        # Event type features
        event_type = event_data.get('eventType', '')
        event_type_features = [
            1 if 'IP_ADDRESS' in event_type else 0,
            1 if 'DOMAIN' in event_type else 0,
            1 if 'URL' in event_type else 0,
            1 if 'HASH' in event_type else 0,
            1 if 'EMAIL' in event_type else 0,
            1 if 'MALWARE' in event_type else 0,
            1 if 'VULNERABILITY' in event_type else 0
        ]
        features.extend(event_type_features)
        
        # Data characteristics
        data = event_data.get('data', '')
        data_features = [
            len(data),  # Data length
            len(re.findall(r'\d+', data)),  # Number count
            len(re.findall(r'[a-zA-Z]+', data)),  # Word count
            len(re.findall(r'[!@#$%^&*(),.?":{}|<>]', data)),  # Special char count
            data.count('.'),  # Dot count (domains, IPs)
            data.count('/'),  # Slash count (URLs, paths)
            1 if re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', data) else 0,  # IP pattern
            1 if re.search(r'\b[A-Fa-f0-9]{32,}\b', data) else 0,  # Hash pattern
        ]
        features.extend(data_features)
        
        # Risk indicators
        risk_features = [
            event_data.get('risk', 0),
            event_data.get('confidence', 0),
            1 if event_data.get('sourceEventHash') != 'ROOT' else 0
        ]
        features.extend(risk_features)
        
        return features
    
    def detect_anomalies(self, events: List[Dict[str, Any]]) -> List[bool]:
        """Detect anomalous patterns in events using basic statistical methods."""
        if not events:
            return []

        with self.model_lock:
            try:
                # Extract features for all events
                features_matrix = [self.extract_features(event) for event in events]

                if not features_matrix:
                    return [False] * len(events)

                # Accumulate training data for the IsolationForest model
                if HAS_ML_LIBS and self.anomaly_detector and not self._model_fitted:
                    self._training_features.extend(features_matrix)
                    if len(self._training_features) >= self.MIN_TRAINING_SAMPLES:
                        try:
                            self.anomaly_detector.fit(self._training_features)
                            self._model_fitted = True
                            log.info(
                                f"IsolationForest model fitted with "
                                f"{len(self._training_features)} samples"
                            )
                        except Exception as e:
                            log.warning(f"Failed to fit IsolationForest model: {e}")

                # If we have ML libraries and the model has been fitted, use them
                if HAS_ML_LIBS and self.anomaly_detector and self._model_fitted:
                    predictions = self.anomaly_detector.predict(features_matrix)
                    return [pred == -1 for pred in predictions]

                # Fallback: basic statistical outlier detection
                if len(features_matrix) < 3:
                    return [False] * len(events)

                anomalies = []
                # Calculate z-scores for each feature
                num_features = len(features_matrix[0])
                for event_idx, features in enumerate(features_matrix):
                    is_anomaly = False

                    for feature_idx in range(num_features):
                        feature_values = [f[feature_idx] for f in features_matrix]
                        if len(set(feature_values)) <= 1:  # No variance
                            continue

                        feature_mean = mean(feature_values)
                        feature_std = std_dev(feature_values)

                        if feature_std > 0:
                            z_score = abs((features[feature_idx] - feature_mean) / feature_std)
                            if z_score > 2.5:  # 2.5 standard deviations
                                is_anomaly = True
                                break

                    anomalies.append(is_anomaly)

                return anomalies

            except Exception as e:
                log.error(f"Anomaly detection failed: {e}")
                return [False] * len(events)
    
    def identify_attack_patterns(self, events: List[Dict[str, Any]]) -> List[ThreatSignature]:
        """Identify sophisticated attack patterns."""
        signatures = []
        
        # Group events by source and time windows
        time_windows = self._group_events_by_time(events, window_minutes=30)
        
        for window_events in time_windows:
            # Check for common attack patterns
            signatures.extend(self._detect_brute_force_pattern(window_events))
            signatures.extend(self._detect_reconnaissance_pattern(window_events))
            signatures.extend(self._detect_lateral_movement_pattern(window_events))
            signatures.extend(self._detect_data_exfiltration_pattern(window_events))
            signatures.extend(self._detect_c2_communication_pattern(window_events))
        
        return signatures
    
    def _group_events_by_time(self, events: List[Dict[str, Any]], window_minutes: int = 30) -> List[List[Dict[str, Any]]]:
        """Group events into time windows."""
        if not events:
            return []
        
        # Sort events by timestamp
        sorted_events = sorted(events, key=lambda x: x.get('timestamp', 0))
        
        windows = []
        current_window = []
        window_start = sorted_events[0].get('timestamp', 0)
        window_size = window_minutes * 60
        
        for event in sorted_events:
            event_time = event.get('timestamp', 0)
            
            if event_time - window_start <= window_size:
                current_window.append(event)
            else:
                if current_window:
                    windows.append(current_window)
                current_window = [event]
                window_start = event_time
        
        if current_window:
            windows.append(current_window)
        
        return windows
    
    def _detect_brute_force_pattern(self, events: List[Dict[str, Any]]) -> List[ThreatSignature]:
        """Detect brute force attack patterns."""
        signatures = []
        
        # Look for multiple failed authentication attempts
        auth_events = [e for e in events if 'auth' in e.get('eventType', '').lower() or 'login' in e.get('data', '').lower()]
        
        if len(auth_events) >= 5:  # Threshold for brute force
            unique_sources = len(set(e.get('source', '') for e in auth_events))
            frequency = len(auth_events)
            
            confidence = min(0.9, frequency / 20.0)  # Higher frequency = higher confidence
            
            signature = ThreatSignature(
                signature_id=hashlib.md5(f"brute_force_{time.time()}".encode()).hexdigest(),
                threat_type="brute_force",
                confidence_score=confidence,
                features={
                    'event_count': frequency,
                    'unique_sources': unique_sources,
                    'time_span': events[-1].get('timestamp', 0) - events[0].get('timestamp', 0)
                },
                indicators=[e.get('data', '') for e in auth_events[:10]],  # Top 10
                created_at=datetime.now(),
                last_seen=datetime.now(),
                frequency=frequency,
                severity="high" if frequency > 15 else "medium"
            )
            signatures.append(signature)
        
        return signatures
    
    def _detect_reconnaissance_pattern(self, events: List[Dict[str, Any]]) -> List[ThreatSignature]:
        """Detect reconnaissance patterns."""
        signatures = []
        
        # Look for port scanning, DNS enumeration, etc.
        recon_indicators = ['scan', 'enum', 'probe', 'discovery', 'reconnaissance']
        recon_events = [
            e for e in events 
            if any(indicator in e.get('data', '').lower() for indicator in recon_indicators)
        ]
        
        if len(recon_events) >= 3:
            unique_targets = len(set(e.get('data', '') for e in recon_events))
            confidence = min(0.8, (len(recon_events) + unique_targets) / 15.0)
            
            signature = ThreatSignature(
                signature_id=hashlib.md5(f"reconnaissance_{time.time()}".encode()).hexdigest(),
                threat_type="reconnaissance",
                confidence_score=confidence,
                features={
                    'event_count': len(recon_events),
                    'unique_targets': unique_targets,
                    'diversity_score': unique_targets / len(recon_events)
                },
                indicators=[e.get('data', '') for e in recon_events],
                created_at=datetime.now(),
                last_seen=datetime.now(),
                frequency=len(recon_events),
                severity="medium"
            )
            signatures.append(signature)
        
        return signatures
    
    def _detect_lateral_movement_pattern(self, events: List[Dict[str, Any]]) -> List[ThreatSignature]:
        """Detect lateral movement patterns."""
        signatures = []
        
        # Look for network traversal, privilege escalation
        lateral_indicators = ['psexec', 'wmi', 'remote', 'lateral', 'pivot', 'escalation']
        lateral_events = [
            e for e in events 
            if any(indicator in e.get('data', '').lower() for indicator in lateral_indicators)
        ]
        
        if len(lateral_events) >= 2:
            confidence = min(0.85, len(lateral_events) / 8.0)
            
            signature = ThreatSignature(
                signature_id=hashlib.md5(f"lateral_movement_{time.time()}".encode()).hexdigest(),
                threat_type="lateral_movement",
                confidence_score=confidence,
                features={
                    'event_count': len(lateral_events),
                    'time_span': lateral_events[-1].get('timestamp', 0) - lateral_events[0].get('timestamp', 0)
                },
                indicators=[e.get('data', '') for e in lateral_events],
                created_at=datetime.now(),
                last_seen=datetime.now(),
                frequency=len(lateral_events),
                severity="high"
            )
            signatures.append(signature)
        
        return signatures
    
    def _detect_data_exfiltration_pattern(self, events: List[Dict[str, Any]]) -> List[ThreatSignature]:
        """Detect data exfiltration patterns."""
        signatures = []
        
        # Look for large data transfers, compression, encryption
        exfil_indicators = ['upload', 'transfer', 'exfil', 'compress', 'encrypt', 'archive']
        exfil_events = [
            e for e in events 
            if any(indicator in e.get('data', '').lower() for indicator in exfil_indicators)
        ]
        
        if len(exfil_events) >= 2:
            confidence = min(0.9, len(exfil_events) / 5.0)
            
            signature = ThreatSignature(
                signature_id=hashlib.md5(f"data_exfiltration_{time.time()}".encode()).hexdigest(),
                threat_type="data_exfiltration",
                confidence_score=confidence,
                features={
                    'event_count': len(exfil_events),
                    'data_volume': sum(len(e.get('data', '')) for e in exfil_events)
                },
                indicators=[e.get('data', '') for e in exfil_events],
                created_at=datetime.now(),
                last_seen=datetime.now(),
                frequency=len(exfil_events),
                severity="critical"
            )
            signatures.append(signature)
        
        return signatures
    
    def _detect_c2_communication_pattern(self, events: List[Dict[str, Any]]) -> List[ThreatSignature]:
        """Detect command and control communication patterns."""
        signatures = []
        
        # Look for beaconing, C2 communication
        c2_indicators = ['beacon', 'c2', 'command', 'control', 'callback', 'heartbeat']
        c2_events = [
            e for e in events 
            if any(indicator in e.get('data', '').lower() for indicator in c2_indicators)
        ]
        
        if len(c2_events) >= 3:
            # Check for periodic timing (beaconing)
            timestamps = [e.get('timestamp', 0) for e in c2_events]
            intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
            avg_interval = np.mean(intervals) if intervals else 0
            interval_variance = np.var(intervals) if intervals else float('inf')
            
            # Low variance indicates regular beaconing
            regularity_score = 1.0 / (1.0 + interval_variance / max(avg_interval, 1)) if avg_interval > 0 else 0
            confidence = min(0.95, (len(c2_events) / 10.0) + (regularity_score * 0.3))
            
            signature = ThreatSignature(
                signature_id=hashlib.md5(f"c2_communication_{time.time()}".encode()).hexdigest(),
                threat_type="c2_communication",
                confidence_score=confidence,
                features={
                    'event_count': len(c2_events),
                    'avg_interval': avg_interval,
                    'regularity_score': regularity_score
                },
                indicators=[e.get('data', '') for e in c2_events],
                created_at=datetime.now(),
                last_seen=datetime.now(),
                frequency=len(c2_events),
                severity="critical"
            )
            signatures.append(signature)
        
        return signatures


class PredictiveAnalyticsEngine:
    """Predictive analytics for threat forecasting."""
    
    def __init__(self):
        self.time_series_models = {}
        self.threat_history = defaultdict(list)
        self.prediction_cache = {}
        self.model_lock = threading.RLock()
    
    def record_threat_event(self, threat_type: str, timestamp: float, severity: str):
        """Record a threat event for predictive modeling."""
        with self.model_lock:
            self.threat_history[threat_type].append({
                'timestamp': timestamp,
                'severity': severity,
                'hour': datetime.fromtimestamp(timestamp).hour,
                'weekday': datetime.fromtimestamp(timestamp).weekday()
            })
            
            # Keep only recent history (last 90 days)
            cutoff = timestamp - (90 * 24 * 3600)
            self.threat_history[threat_type] = [
                event for event in self.threat_history[threat_type]
                if event['timestamp'] > cutoff
            ]
    
    def predict_threat_likelihood(self, threat_type: str, time_horizon_hours: int = 24) -> ThreatPrediction:
        """Predict likelihood of threat occurrence."""
        with self.model_lock:
            history = self.threat_history.get(threat_type, [])
            
            if len(history) < 10:  # Not enough data
                return ThreatPrediction(
                    prediction_id=hashlib.md5(f"{threat_type}_{time.time()}".encode()).hexdigest(),
                    threat_type=threat_type,
                    probability=0.1,  # Low default probability
                    risk_score=0.2,
                    time_horizon=time_horizon_hours,
                    confidence_interval=(0.0, 0.3),
                    contributing_factors=["Insufficient historical data"],
                    recommended_actions=["Collect more threat intelligence data"]
                )
            
            # Analyze historical patterns
            current_time = time.time()
            current_hour = datetime.fromtimestamp(current_time).hour
            current_weekday = datetime.fromtimestamp(current_time).weekday()
            
            # Calculate base probability from historical frequency
            recent_events = [e for e in history if current_time - e['timestamp'] < 7 * 24 * 3600]  # Last week
            base_probability = len(recent_events) / (7 * 24)  # Events per hour
            
            # Adjust for time-of-day patterns
            hour_events = [e for e in history if abs(e['hour'] - current_hour) <= 1]
            hour_factor = len(hour_events) / max(len(history), 1)
            
            # Adjust for day-of-week patterns
            weekday_events = [e for e in history if e['weekday'] == current_weekday]
            weekday_factor = len(weekday_events) / max(len(history), 1)
            
            # Calculate final probability
            probability = base_probability * (1 + hour_factor + weekday_factor)
            probability = min(probability, 0.95)  # Cap at 95%
            
            # Calculate risk score
            severity_weights = {'low': 0.3, 'medium': 0.6, 'high': 0.9, 'critical': 1.0}
            avg_severity = np.mean([severity_weights.get(e.get('severity', 'medium'), 0.6) for e in history])
            risk_score = probability * avg_severity
            
            # Confidence interval
            std_dev = np.std([e['timestamp'] for e in recent_events]) if recent_events else 0
            confidence_interval = (
                max(0, probability - std_dev * 0.1),
                min(1, probability + std_dev * 0.1)
            )
            
            # Contributing factors
            contributing_factors = []
            if hour_factor > 0.2:
                contributing_factors.append(f"Higher activity during hour {current_hour}")
            if weekday_factor > 0.2:
                day_names = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
                contributing_factors.append(f"Higher activity on {day_names[current_weekday]}")
            if base_probability > 0.1:
                contributing_factors.append("Recent increase in threat activity")
            
            # Recommended actions
            recommended_actions = []
            if probability > 0.7:
                recommended_actions.extend([
                    "Increase monitoring and alerting",
                    "Review and update security controls",
                    "Prepare incident response team"
                ])
            elif probability > 0.4:
                recommended_actions.extend([
                    "Enhanced monitoring recommended",
                    "Review recent security events"
                ])
            else:
                recommended_actions.append("Maintain standard monitoring posture")
            
            return ThreatPrediction(
                prediction_id=hashlib.md5(f"{threat_type}_{current_time}".encode()).hexdigest(),
                threat_type=threat_type,
                probability=probability,
                risk_score=risk_score,
                time_horizon=time_horizon_hours,
                confidence_interval=confidence_interval,
                contributing_factors=contributing_factors,
                recommended_actions=recommended_actions
            )


class IOCCorrelationEngine:
    """Automated IOC correlation across data sources."""
    
    def __init__(self):
        self.ioc_graph = defaultdict(set)
        self.temporal_relationships = {}
        self.correlation_cache = {}
        self.correlation_lock = threading.RLock()
    
    def add_ioc_relationship(self, ioc1: str, ioc2: str, relationship_type: str = "related", timestamp: float = None):
        """Add a relationship between two IOCs."""
        with self.correlation_lock:
            self.ioc_graph[ioc1].add(ioc2)
            self.ioc_graph[ioc2].add(ioc1)
            
            if timestamp:
                key = tuple(sorted([ioc1, ioc2]))
                if key not in self.temporal_relationships:
                    self.temporal_relationships[key] = []
                self.temporal_relationships[key].append({
                    'type': relationship_type,
                    'timestamp': timestamp
                })
    
    def find_related_iocs(self, primary_ioc: str, max_depth: int = 3) -> IOCCorrelation:
        """Find IOCs related to the primary IOC."""
        with self.correlation_lock:
            related_iocs = set()
            visited = set()
            queue = [(primary_ioc, 0)]
            
            while queue:
                current_ioc, depth = queue.pop(0)
                
                if current_ioc in visited or depth >= max_depth:
                    continue
                
                visited.add(current_ioc)
                
                for related_ioc in self.ioc_graph.get(current_ioc, set()):
                    if related_ioc != primary_ioc and related_ioc not in visited:
                        related_iocs.add(related_ioc)
                        if depth + 1 < max_depth:
                            queue.append((related_ioc, depth + 1))
            
            # Calculate correlation strength
            total_possible = len(self.ioc_graph)
            correlation_strength = len(related_iocs) / max(total_possible, 1) if total_possible > 0 else 0
            
            # Determine temporal relationship
            temporal_relationship = self._analyze_temporal_relationship(primary_ioc, list(related_iocs))
            
            return IOCCorrelation(
                correlation_id=hashlib.md5(f"{primary_ioc}_{time.time()}".encode()).hexdigest(),
                primary_ioc=primary_ioc,
                related_iocs=list(related_iocs),
                correlation_strength=correlation_strength,
                temporal_relationship=temporal_relationship,
                attack_chain_position=self._estimate_attack_chain_position(primary_ioc, list(related_iocs))
            )
    
    def _analyze_temporal_relationship(self, primary_ioc: str, related_iocs: List[str]) -> str:
        """Analyze temporal relationships between IOCs."""
        if not related_iocs:
            return "isolated"
        
        timestamps = []
        for related_ioc in related_iocs:
            key = tuple(sorted([primary_ioc, related_ioc]))
            if key in self.temporal_relationships:
                timestamps.extend([r['timestamp'] for r in self.temporal_relationships[key]])
        
        if not timestamps:
            return "unknown"
        
        timestamps.sort()
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        
        if not intervals:
            return "simultaneous"
        
        avg_interval = np.mean(intervals)
        std_interval = np.std(intervals)
        
        if std_interval / max(avg_interval, 1) < 0.2:  # Low variance = periodic
            return "periodic"
        elif avg_interval < 300:  # Less than 5 minutes = simultaneous
            return "simultaneous"
        else:
            return "sequential"
    
    def _estimate_attack_chain_position(self, primary_ioc: str, related_iocs: List[str]) -> int:
        """Estimate position in attack chain based on IOC relationships."""
        # Simple heuristic based on IOC type and relationships
        ioc_type_weights = {
            'ip': 1,      # Usually early (reconnaissance, initial access)
            'domain': 2,  # Early to mid (C2, delivery)
            'url': 3,     # Mid (exploitation, delivery)
            'hash': 4,    # Mid to late (payload, persistence)
            'email': 2,   # Early (initial access)
        }
        
        # Determine IOC type
        primary_type = self._classify_ioc_type(primary_ioc)
        base_position = ioc_type_weights.get(primary_type, 3)
        
        # Adjust based on relationships
        related_types = [self._classify_ioc_type(ioc) for ioc in related_iocs]
        avg_related_position = np.mean([ioc_type_weights.get(t, 3) for t in related_types]) if related_types else 3
        
        # Final position is weighted average
        position = int((base_position * 0.7) + (avg_related_position * 0.3))
        return max(1, min(position, 7))  # Clamp to 1-7
    
    def _classify_ioc_type(self, ioc: str) -> str:
        """Classify IOC type based on pattern matching."""
        ioc = ioc.lower().strip()
        
        # IP address pattern
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ioc):
            return 'ip'
        
        # Hash patterns
        if re.match(r'^[a-f0-9]{32}$', ioc):  # MD5
            return 'hash'
        if re.match(r'^[a-f0-9]{40}$', ioc):  # SHA1
            return 'hash'
        if re.match(r'^[a-f0-9]{64}$', ioc):  # SHA256
            return 'hash'
        
        # Email pattern
        if re.match(r'^[^@]+@[^@]+\.[^@]+$', ioc):
            return 'email'
        
        # URL pattern
        if ioc.startswith(('http://', 'https://', 'ftp://')):
            return 'url'
        
        # Domain pattern (simple heuristic)
        if '.' in ioc and not ioc.startswith('http') and not re.search(r'[^a-zA-Z0-9.-]', ioc):
            return 'domain'
        
        return 'unknown'


class ThreatScoringEngine:
    """Heuristic-based threat scoring."""
    
    def __init__(self):
        self.scoring_models = {}
        self.feature_weights = {
            'confidence': 0.25,
            'risk': 0.20,
            'frequency': 0.15,
            'recency': 0.15,
            'correlation': 0.15,
            'reputation': 0.10
        }
        self.threat_scores = {}
        self.scoring_lock = threading.RLock()
    
    def calculate_threat_score(self, event_data: Dict[str, Any], signatures: List[ThreatSignature], 
                             correlations: List[IOCCorrelation]) -> float:
        """Calculate dynamic threat score for an event."""
        with self.scoring_lock:
            base_score = 0.0
            
            # Base score from event confidence and risk
            confidence = event_data.get('confidence', 50) / 100.0
            risk = event_data.get('risk', 0) / 100.0 if event_data.get('risk', 0) > 0 else 0.3
            
            base_score += confidence * self.feature_weights['confidence']
            base_score += risk * self.feature_weights['risk']
            
            # Signature-based scoring
            signature_score = 0.0
            if signatures:
                max_sig_confidence = max(sig.confidence_score for sig in signatures)
                avg_sig_confidence = np.mean([sig.confidence_score for sig in signatures])
                signature_score = (max_sig_confidence * 0.7) + (avg_sig_confidence * 0.3)
            
            # Correlation-based scoring
            correlation_score = 0.0
            if correlations:
                max_corr_strength = max(corr.correlation_strength for corr in correlations)
                correlation_score = max_corr_strength
            
            # Frequency scoring (how often this type of event occurs)
            event_type = event_data.get('eventType', '')
            frequency_score = self._calculate_frequency_score(event_type)
            
            # Recency scoring (how recent similar threats were seen)
            recency_score = self._calculate_recency_score(event_type)
            
            # Reputation scoring (if available)
            reputation_score = self._calculate_reputation_score(event_data.get('data', ''))
            
            # Combine all scores
            total_score = (
                base_score +
                (signature_score * self.feature_weights['frequency']) +
                (correlation_score * self.feature_weights['correlation']) +
                (frequency_score * self.feature_weights['frequency']) +
                (recency_score * self.feature_weights['recency']) +
                (reputation_score * self.feature_weights['reputation'])
            )
            
            # Normalize to 0-100
            final_score = min(100, max(0, total_score * 100))
            
            # Store for future frequency calculations
            self._record_score(event_type, final_score)
            
            return final_score
    
    def _calculate_frequency_score(self, event_type: str) -> float:
        """Calculate score based on event frequency."""
        # Higher frequency = lower uniqueness = potentially lower threat
        # But also consider that high frequency could indicate ongoing campaign
        historical_scores = self.threat_scores.get(event_type, [])
        
        if not historical_scores:
            return 0.5  # Neutral score for unknown event types
        
        frequency = len(historical_scores)
        if frequency < 5:
            return 0.7  # Rare events get higher score
        elif frequency < 20:
            return 0.5  # Moderate frequency
        else:
            return 0.3  # Common events get lower score
    
    def _calculate_recency_score(self, event_type: str) -> float:
        """Calculate score based on recency of similar threats."""
        current_time = time.time()
        historical_scores = self.threat_scores.get(event_type, [])
        
        if not historical_scores:
            return 0.5  # Neutral score
        
        # Get most recent scores (last 24 hours)
        recent_threshold = current_time - (24 * 3600)
        recent_scores = [
            score for score, timestamp in historical_scores 
            if timestamp > recent_threshold
        ]
        
        if not recent_scores:
            return 0.3  # No recent activity
        
        avg_recent_score = np.mean(recent_scores)
        return avg_recent_score / 100.0  # Normalize to 0-1
    
    def _calculate_reputation_score(self, ioc_data: str) -> float:
        """Calculate score based on IOC reputation (placeholder for external feeds)."""
        # This would integrate with external threat intelligence feeds
        # For now, simple heuristics
        
        reputation_indicators = {
            'known_bad': 1.0,
            'suspicious': 0.7,
            'unknown': 0.5,
            'whitelist': 0.1
        }
        
        # Simple pattern matching for demo
        if any(bad in ioc_data.lower() for bad in ['malware', 'trojan', 'botnet', 'exploit']):
            return reputation_indicators['known_bad']
        elif any(sus in ioc_data.lower() for sus in ['suspicious', 'potentially', 'unusual']):
            return reputation_indicators['suspicious']
        else:
            return reputation_indicators['unknown']
    
    def _record_score(self, event_type: str, score: float):
        """Record a threat score for historical analysis."""
        current_time = time.time()
        
        if event_type not in self.threat_scores:
            self.threat_scores[event_type] = deque(maxlen=1000)  # Keep last 1000 scores
        
        self.threat_scores[event_type].append((score, current_time))


class NLPThreatAnalyzer:
    """Natural language processing for unstructured threat data."""
    
    def __init__(self):
        self.sentiment_analyzer = None
        self.text_vectorizer = None
        self.threat_keywords = {
            'malware': ['virus', 'trojan', 'worm', 'ransomware', 'backdoor', 'rootkit'],
            'phishing': ['phishing', 'spear', 'whaling', 'credential', 'harvest'],
            'vulnerability': ['exploit', 'vulnerability', 'cve', 'zero-day', 'rce'],
            'attack': ['attack', 'breach', 'compromise', 'intrusion', 'penetration'],
            'c2': ['command', 'control', 'c2', 'beacon', 'callback', 'communication']
        }
        self._initialize_nlp()
    
    def _initialize_nlp(self):
        """Initialize NLP components."""
        if HAS_NLTK:
            try:
                # Download required NLTK data
                import ssl
                try:
                    _create_unverified_https_context = ssl._create_unverified_context
                except AttributeError:
                    pass
                else:
                    ssl._create_default_https_context = _create_unverified_https_context
                
                nltk.download('vader_lexicon', quiet=True)
                nltk.download('punkt', quiet=True)
                nltk.download('stopwords', quiet=True)
                
                self.sentiment_analyzer = SentimentIntensityAnalyzer()
                log.info("NLP components initialized successfully")
                
            except Exception as e:
                log.warning(f"Failed to initialize NLP components: {e}")
        
        if HAS_ML_LIBS:
            try:
                self.text_vectorizer = TfidfVectorizer(
                    max_features=500,
                    stop_words='english',
                    ngram_range=(1, 2)
                )
            except Exception as e:
                log.warning(f"Failed to initialize text vectorizer: {e}")
    
    def analyze_threat_text(self, text_data: str) -> Dict[str, Any]:
        """Analyze unstructured text for threat intelligence."""
        results = {
            'threat_categories': [],
            'sentiment_score': 0.0,
            'urgency_level': 'low',
            'extracted_iocs': [],
            'confidence': 0.0
        }
        
        if not text_data:
            return results
        
        text_lower = text_data.lower()
        
        # Categorize threats based on keywords
        for category, keywords in self.threat_keywords.items():
            if any(keyword in text_lower for keyword in keywords):
                results['threat_categories'].append(category)
        
        # Sentiment analysis
        if self.sentiment_analyzer:
            try:
                sentiment = self.sentiment_analyzer.polarity_scores(text_data)
                # Negative sentiment often indicates threats
                results['sentiment_score'] = sentiment['compound']
                
                # Determine urgency based on sentiment and keywords
                urgency_keywords = ['urgent', 'critical', 'immediate', 'emergency', 'severe']
                has_urgency = any(word in text_lower for word in urgency_keywords)
                
                if sentiment['compound'] < -0.5 or has_urgency:
                    results['urgency_level'] = 'high'
                elif sentiment['compound'] < -0.2:
                    results['urgency_level'] = 'medium'
                    
            except Exception as e:
                log.warning(f"Sentiment analysis failed: {e}")
        
        # Extract potential IOCs
        results['extracted_iocs'] = self._extract_iocs_from_text(text_data)
        
        # Calculate confidence based on multiple factors
        confidence_factors = []
        
        # More threat categories = higher confidence
        confidence_factors.append(min(len(results['threat_categories']) / 3.0, 1.0))
        
        # Negative sentiment = higher confidence for threats
        if results['sentiment_score'] < 0:
            confidence_factors.append(abs(results['sentiment_score']))
        
        # IOCs found = higher confidence
        if results['extracted_iocs']:
            confidence_factors.append(min(len(results['extracted_iocs']) / 5.0, 1.0))
        
        results['confidence'] = np.mean(confidence_factors) if confidence_factors else 0.0
        
        return results
    
    def _extract_iocs_from_text(self, text: str) -> List[str]:
        """Extract IOCs from unstructured text."""
        iocs = []
        
        # IP addresses
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        iocs.extend(re.findall(ip_pattern, text))
        
        # Domain names
        domain_pattern = r'\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.([a-zA-Z]{2,})\b'
        potential_domains = re.findall(domain_pattern, text)
        for domain_parts in potential_domains:
            domain = '.'.join(domain_parts)
            if not domain.endswith(('.jpg', '.png', '.gif', '.pdf', '.doc', '.txt')):  # Filter file extensions
                iocs.append(domain)
        
        # Email addresses
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        iocs.extend(re.findall(email_pattern, text))
        
        # File hashes (MD5, SHA1, SHA256)
        hash_patterns = [
            r'\b[a-fA-F0-9]{32}\b',  # MD5
            r'\b[a-fA-F0-9]{40}\b',  # SHA1
            r'\b[a-fA-F0-9]{64}\b'   # SHA256
        ]
        for pattern in hash_patterns:
            iocs.extend(re.findall(pattern, text))
        
        # URLs
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        iocs.extend(re.findall(url_pattern, text))
        
        return list(set(iocs))  # Remove duplicates


class sfp__ai_threat_intel(SpiderFootPlugin):
    """Threat Intelligence Engine."""

    meta = {
        'name': "Threat Intelligence Engine",
        'summary': "Threat intelligence with pattern recognition, trend analysis, and automated IOC correlation.",
        'flags': []
    }

    _priority = 1  # High priority for threat intelligence

    # Default options
    opts = {
        'enable_pattern_recognition': True,
        'enable_predictive_analytics': True,
        'enable_ioc_correlation': True,
        'enable_threat_scoring': True,
        'enable_nlp_analysis': True,
        'enable_cross_scan_correlation': True,
        'max_historical_scans': 10,
        'historical_lookback_days': 90,
        'anomaly_detection_threshold': 0.1,
        'threat_score_threshold': 70,
        'correlation_min_strength': 0.3,
        'prediction_time_horizon': 24,  # hours
        'ml_model_update_interval': 3600  # seconds
    }

    # Option descriptions
    optdescs = {
        'enable_pattern_recognition': "Enable attack pattern recognition",
        'enable_predictive_analytics': "Enable predictive threat analytics",
        'enable_ioc_correlation': "Enable automated IOC correlation",
        'enable_threat_scoring': "Enable heuristic-based threat scoring",
        'enable_nlp_analysis': "Enable text processing for threat analysis",
        'enable_cross_scan_correlation': "Enable correlation with historical scan data for the same target",
        'max_historical_scans': "Maximum number of historical scans to include (0 = unlimited)",
        'historical_lookback_days': "Only include scans from the last N days",
        'anomaly_detection_threshold': "Threshold for anomaly detection (0.0-1.0)",
        'threat_score_threshold': "Minimum threat score to trigger alerts (0-100)",
        'correlation_min_strength': "Minimum correlation strength for IOC relationships",
        'prediction_time_horizon': "Time horizon for threat predictions (hours)",
        'ml_model_update_interval': "Interval for ML model updates (seconds)"
    }

    def setup(self, sfc, userOpts=dict()):
        """Set up the threat intelligence module."""
        self.sf = sfc
        self.errorState = False
        self._historical_data_loaded = False  # Flag for lazy loading of historical data

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

        # Check for required libraries
        if not HAS_ML_LIBS:
            self.error("Required ML libraries (tensorflow, sklearn, pandas, numpy) not available")
            self.errorState = True
            return

        # Initialize engines
        try:
            if self.opts['enable_pattern_recognition']:
                self.pattern_engine = PatternRecognitionEngine()

            if self.opts['enable_predictive_analytics']:
                self.predictive_engine = PredictiveAnalyticsEngine()

            if self.opts['enable_ioc_correlation']:
                self.correlation_engine = IOCCorrelationEngine()

            if self.opts['enable_threat_scoring']:
                self.scoring_engine = ThreatScoringEngine()

            if self.opts['enable_nlp_analysis']:
                self.nlp_analyzer = NLPThreatAnalyzer()

            self.debug("Threat Intelligence Engine initialized successfully")

        except Exception as e:
            self.error(f"Failed to initialize engines: {e}")
            self.errorState = True

    def watchedEvents(self):
        """Define the events this module is interested in."""
        return ["*"]  # Process all events for comprehensive analysis

    def producedEvents(self):
        """Define the events this module produces."""
        return [
            "AI_THREAT_SIGNATURE",
            "AI_THREAT_PREDICTION",
            "AI_IOC_CORRELATION",
            "AI_THREAT_SCORE",
            "AI_ANOMALY_DETECTED",
            "AI_NLP_ANALYSIS",
            "AI_CROSS_SCAN_CORRELATION"
        ]

    # Event types produced by AI/analysis modules. Processing these would
    # create a circular dependency (AI modules re-analysing each other's
    # output), so they must be skipped.
    _AI_GENERATED_EVENT_TYPES = frozenset({
        "AI_THREAT_SIGNATURE", "AI_THREAT_PREDICTION", "AI_IOC_CORRELATION",
        "AI_THREAT_SCORE", "AI_ANOMALY_DETECTED", "AI_NLP_ANALYSIS",
        "AI_CROSS_SCAN_CORRELATION", "AI_SINGLE_SCAN_CORRELATION",
        "SECURITY_AUDIT_EVENT", "SECURITY_VIOLATION", "SUSPICIOUS_ACTIVITY",
        "ZERO_TRUST_VIOLATION", "AUTHENTICATION_FAILURE", "AUTHORIZATION_DENIED",
        "THREAT_INTEL_SUMMARY",
    })

    def handleEvent(self, sfEvent):
        """Handle events with threat analysis."""
        if self.errorState:
            return

        # Skip events produced by AI/analysis modules to prevent circular
        # dependency loops (AI modules re-analysing each other's output).
        if sfEvent.eventType in self._AI_GENERATED_EVENT_TYPES:
            return

        # Lazy load historical data on first event (when scan ID and DB are available)
        if not self._historical_data_loaded and self.opts.get('enable_cross_scan_correlation', True):
            self._historical_data_loaded = True
            try:
                self._load_historical_data()
            except Exception as e:
                self.error(f"Failed to load historical data for cross-scan correlation: {e}")

        # Convert event to analysis format
        event_data = {
            'eventType': sfEvent.eventType,
            'data': sfEvent.data,
            'confidence': sfEvent.confidence,
            'risk': sfEvent.risk,
            'timestamp': time.time(),
            'sourceEventHash': sfEvent.sourceEventHash,
            'module': sfEvent.module
        }

        # Perform analysis
        self._analyze_event(sfEvent, event_data)

    def _analyze_event(self, sfEvent, event_data):
        """Perform comprehensive analysis on the event."""

        # 1. Pattern Recognition
        if self.checkForStop():
            return
        if hasattr(self, 'pattern_engine') and self.opts['enable_pattern_recognition']:
            try:
                # Detect anomalies
                is_anomaly = self.pattern_engine.detect_anomalies([event_data])[0]
                if is_anomaly:
                    anomaly_event = SpiderFootEvent(
                        "AI_ANOMALY_DETECTED",
                        f"Anomalous pattern detected: {sfEvent.data}",
                        self.__name__,
                        sfEvent
                    )
                    self.notifyListeners(anomaly_event)

                # Identify attack patterns (batch processing for efficiency)
                signatures = self.pattern_engine.identify_attack_patterns([event_data])
                for signature in signatures:
                    if signature.confidence_score > 0.5:  # Threshold for reporting
                        sig_event = SpiderFootEvent(
                            "AI_THREAT_SIGNATURE",
                            json.dumps(asdict(signature), default=str),
                            self.__name__,
                            sfEvent
                        )
                        self.notifyListeners(sig_event)

            except Exception as e:
                self.error(f"Pattern recognition failed: {e}")

        # 2. Predictive Analytics
        if self.checkForStop():
            return
        if hasattr(self, 'predictive_engine') and self.opts['enable_predictive_analytics']:
            try:
                # Record this threat event
                self.predictive_engine.record_threat_event(
                    sfEvent.eventType,
                    event_data['timestamp'],
                    "medium"  # Default severity
                )

                # Generate prediction
                prediction = self.predictive_engine.predict_threat_likelihood(
                    sfEvent.eventType,
                    self.opts['prediction_time_horizon']
                )

                if prediction.probability > 0.5:  # Significant probability
                    pred_event = SpiderFootEvent(
                        "AI_THREAT_PREDICTION",
                        json.dumps(asdict(prediction), default=str),
                        self.__name__,
                        sfEvent
                    )
                    self.notifyListeners(pred_event)

            except Exception as e:
                self.error(f"Predictive analytics failed: {e}")

        # 3. IOC Correlation
        if self.checkForStop():
            return
        if hasattr(self, 'correlation_engine') and self.opts['enable_ioc_correlation']:
            try:
                # Find correlations for this IOC
                correlation = self.correlation_engine.find_related_iocs(sfEvent.data)
                
                if (correlation.related_iocs and 
                    correlation.correlation_strength >= self.opts['correlation_min_strength']):
                    
                    corr_event = SpiderFootEvent(
                        "AI_IOC_CORRELATION",
                        json.dumps(asdict(correlation), default=str),
                        self.__name__,
                        sfEvent
                    )
                    self.notifyListeners(corr_event)

            except Exception as e:
                self.error(f"IOC correlation failed: {e}")

        # 4. Threat Scoring
        if self.checkForStop():
            return
        if hasattr(self, 'scoring_engine') and self.opts['enable_threat_scoring']:
            try:
                # Get signatures and correlations for scoring
                signatures = getattr(self, '_current_signatures', [])
                correlations = getattr(self, '_current_correlations', [])
                
                threat_score = self.scoring_engine.calculate_threat_score(
                    event_data, signatures, correlations
                )

                if threat_score >= self.opts['threat_score_threshold']:
                    score_event = SpiderFootEvent(
                        "AI_THREAT_SCORE",
                        f"Threat Score: {threat_score:.1f}/100 for {sfEvent.data}",
                        self.__name__,
                        sfEvent
                    )
                    self.notifyListeners(score_event)

            except Exception as e:
                self.error(f"Threat scoring failed: {e}")

        # 5. NLP Analysis
        if self.checkForStop():
            return
        if hasattr(self, 'nlp_analyzer') and self.opts['enable_nlp_analysis']:
            try:
                # Only analyze text-heavy events
                if len(sfEvent.data) > 50:  # Minimum text length
                    nlp_results = self.nlp_analyzer.analyze_threat_text(sfEvent.data)
                    
                    if (nlp_results['threat_categories'] and 
                        nlp_results['confidence'] > 0.5):
                        
                        nlp_event = SpiderFootEvent(
                            "AI_NLP_ANALYSIS",
                            json.dumps(nlp_results),
                            self.__name__,
                            sfEvent
                        )
                        self.notifyListeners(nlp_event)

            except Exception as e:
                self.error(f"NLP analysis failed: {e}")

        # 6. Cross-Scan Correlation
        if self.checkForStop():
            return
        if self.opts.get('enable_cross_scan_correlation', True) and hasattr(self, '_historical_iocs'):
            try:
                self._check_cross_scan_correlation(sfEvent, event_data)
            except Exception as e:
                self.error(f"Cross-scan correlation failed: {e}")

    def _load_historical_data(self):
        """Pre-populate engines with historical scan data for the same target.

        This method queries the database for previous scans against the same target
        and loads their IOCs into the correlation engine for cross-scan analysis.
        """
        if not self.opts.get('enable_cross_scan_correlation', True):
            self.debug("Cross-scan correlation disabled")
            return

        # Initialize historical data storage
        self._historical_iocs = {}  # {ioc_data: [{scan_id, scan_name, scan_date, event_type}]}
        self._historical_scans = []  # List of historical scan info
        self._historical_events_loaded = 0

        try:
            # Get current scan info (target)
            scan_info = self.__sfdb__.scanInstanceGet(self.__scanId__)
            if not scan_info:
                self.debug("Could not get scan info for cross-scan correlation")
                return

            target = scan_info[1]  # seed_target
            self.debug(f"Loading historical data for target: {target}")

            # Get historical scans for this target
            historical_scans = self._get_historical_scans(target)

            if not historical_scans:
                self.debug("No historical scans found for this target")
                return

            self._historical_scans = historical_scans
            self.info(f"Found {len(historical_scans)} historical scan(s) for cross-scan correlation")

            # Load historical events and populate engines
            for scan_id, scan_name, scan_started in historical_scans:
                events_loaded = self._populate_engines_from_scan(scan_id, scan_name, scan_started)
                self._historical_events_loaded += events_loaded

            self.info(f"Loaded {self._historical_events_loaded} historical IOCs for cross-scan correlation")

        except Exception as e:
            self.error(f"Failed to load historical data: {e}")

    def _get_historical_scans(self, target: str) -> List[Tuple[str, str, str]]:
        """Get list of historical scan IDs for the same target.

        Args:
            target: The scan target (domain, IP, etc.)

        Returns:
            List of tuples: [(scan_id, scan_name, scan_started), ...]
        """
        historical_scans = []

        try:
            # Calculate cutoff date
            lookback_days = self.opts.get('historical_lookback_days', 90)
            cutoff_timestamp = time.time() - (lookback_days * 24 * 3600)

            # Get max scans limit
            max_scans = self.opts.get('max_historical_scans', 10)

            # Query the database directly for historical scans
            # Note: Using the internal database handle
            qry = """SELECT guid, name, started FROM tbl_scan_instance
                WHERE seed_target = ? AND guid != ? AND status = 'FINISHED'
                ORDER BY started DESC"""

            if max_scans > 0:
                qry += f" LIMIT {max_scans}"

            with self.__sfdb__.dbhLock:
                self.__sfdb__.dbh.execute(qry, [target, self.__scanId__])
                rows = self.__sfdb__.dbh.fetchall()

                for row in rows:
                    scan_id = row[0]
                    scan_name = row[1]
                    scan_started = row[2]

                    # Check if scan is within lookback period
                    # scan_started is typically a timestamp or datetime string
                    try:
                        if isinstance(scan_started, (int, float)):
                            scan_timestamp = scan_started
                        else:
                            # Try parsing as datetime string
                            scan_timestamp = datetime.strptime(
                                str(scan_started)[:19],
                                '%Y-%m-%d %H:%M:%S'
                            ).timestamp()

                        if scan_timestamp >= cutoff_timestamp:
                            historical_scans.append((scan_id, scan_name, scan_started))
                    except (ValueError, TypeError):
                        # Include scan if we can't parse the date
                        historical_scans.append((scan_id, scan_name, scan_started))

        except Exception as e:
            self.error(f"Failed to get historical scans: {e}")

        return historical_scans

    def _populate_engines_from_scan(self, scan_id: str, scan_name: str, scan_started: str) -> int:
        """Load events from a historical scan into engines.

        Args:
            scan_id: Historical scan instance ID
            scan_name: Name of the historical scan
            scan_started: When the historical scan started

        Returns:
            Number of events loaded
        """
        events_loaded = 0

        try:
            # Get events from the historical scan
            events = self.__sfdb__.scanResultEvent(scan_id, 'ALL')

            if not events:
                return 0

            for event in events:
                # Event format from scanResultEvent:
                # [0]=generated, [1]=data, [2]=module, [3]=source_event_hash,
                # [4]=type, [5]=confidence, [6]=visibility, [7]=risk, [8]=false_positive

                event_type = event[4]
                event_data = event[1]
                event_timestamp = event[0]
                confidence = event[5] if len(event) > 5 else 50
                risk = event[7] if len(event) > 7 else 0
                false_positive = event[8] if len(event) > 8 else 0

                # Skip ROOT events, empty data, and false positives
                if event_type == 'ROOT' or not event_data:
                    continue

                # Skip false positives - they should not be included in correlation
                if false_positive:
                    continue

                # Store in historical IOCs dictionary
                if event_data not in self._historical_iocs:
                    self._historical_iocs[event_data] = []

                self._historical_iocs[event_data].append({
                    'scan_id': scan_id,
                    'scan_name': scan_name,
                    'scan_date': scan_started,
                    'event_type': event_type,
                    'timestamp': event_timestamp,
                    'confidence': confidence,
                    'risk': risk
                })

                # Populate IOC correlation engine with relationships
                if hasattr(self, 'correlation_engine'):
                    # Convert timestamp to float if needed
                    try:
                        if isinstance(event_timestamp, (int, float)):
                            ts = float(event_timestamp)
                        else:
                            ts = datetime.strptime(
                                str(event_timestamp)[:19],
                                '%Y-%m-%d %H:%M:%S'
                            ).timestamp()
                    except (ValueError, TypeError):
                        ts = time.time()

                    self.correlation_engine.add_ioc_relationship(
                        event_data,
                        f"historical:{scan_id}",
                        'historical_scan',
                        ts
                    )

                # Record in predictive engine for threat forecasting
                if hasattr(self, 'predictive_engine'):
                    try:
                        if isinstance(event_timestamp, (int, float)):
                            ts = float(event_timestamp)
                        else:
                            ts = datetime.strptime(
                                str(event_timestamp)[:19],
                                '%Y-%m-%d %H:%M:%S'
                            ).timestamp()
                    except (ValueError, TypeError):
                        ts = time.time()

                    # Determine severity from risk score
                    if risk >= 80:
                        severity = 'critical'
                    elif risk >= 60:
                        severity = 'high'
                    elif risk >= 40:
                        severity = 'medium'
                    else:
                        severity = 'low'

                    self.predictive_engine.record_threat_event(
                        event_type,
                        ts,
                        severity
                    )

                events_loaded += 1

        except Exception as e:
            self.error(f"Failed to populate engines from scan {scan_id}: {e}")

        return events_loaded

    def _check_cross_scan_correlation(self, sfEvent, event_data: Dict[str, Any]):
        """Check if current event correlates with historical scan data.

        Args:
            sfEvent: The SpiderFoot event object
            event_data: Processed event data dictionary
        """
        current_ioc = sfEvent.data

        if not current_ioc or current_ioc == 'ROOT':
            return

        # Skip false positives - they should not generate correlation events
        if getattr(sfEvent, 'false_positive', False):
            return

        # Check for exact match in historical IOCs
        if current_ioc in self._historical_iocs:
            historical_matches = self._historical_iocs[current_ioc]

            # Build cross-scan correlation result
            source_scans = []
            seen_scans = set()
            timestamps = []

            for match in historical_matches:
                if match['scan_id'] not in seen_scans:
                    seen_scans.add(match['scan_id'])
                    source_scans.append({
                        'scan_id': match['scan_id'],
                        'scan_name': match['scan_name'],
                        'scan_date': str(match['scan_date'])
                    })

                # Collect timestamps for trend analysis
                try:
                    if isinstance(match['timestamp'], (int, float)):
                        timestamps.append(float(match['timestamp']))
                    else:
                        ts = datetime.strptime(
                            str(match['timestamp'])[:19],
                            '%Y-%m-%d %H:%M:%S'
                        ).timestamp()
                        timestamps.append(ts)
                except (ValueError, TypeError):
                    pass

            # Determine trend
            occurrence_count = len(historical_matches) + 1  # +1 for current
            if not timestamps:
                trend = "new"
            elif occurrence_count <= 2:
                trend = "stable"
            else:
                # Simple trend analysis based on time intervals
                timestamps.sort()
                if len(timestamps) >= 2:
                    intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
                    avg_interval = sum(intervals) / len(intervals)
                    recent_interval = time.time() - timestamps[-1]

                    if recent_interval < avg_interval * 0.5:
                        trend = "increasing"
                    elif recent_interval > avg_interval * 1.5:
                        trend = "decreasing"
                    else:
                        trend = "stable"
                else:
                    trend = "stable"

            # Calculate confidence based on occurrence count and scan diversity
            confidence = min(0.95, 0.5 + (len(seen_scans) * 0.1) + (occurrence_count * 0.05))

            # Determine first and last seen
            if timestamps:
                first_seen = datetime.fromtimestamp(min(timestamps))
                last_seen = datetime.fromtimestamp(max(timestamps))
            else:
                first_seen = datetime.now()
                last_seen = datetime.now()

            # Create correlation object
            correlation = CrossScanCorrelation(
                correlation_id=hashlib.md5(f"{current_ioc}_{time.time()}".encode()).hexdigest(),
                current_ioc=current_ioc,
                historical_iocs=[current_ioc],  # Exact match
                source_scans=source_scans,
                correlation_type="exact_match",
                confidence=confidence,
                first_seen=first_seen,
                last_seen=last_seen,
                occurrence_count=occurrence_count,
                trend=trend
            )

            # Generate cross-scan correlation event
            correlation_data = {
                'correlation_id': correlation.correlation_id,
                'ioc': correlation.current_ioc,
                'event_type': sfEvent.eventType,
                'historical_occurrences': occurrence_count - 1,
                'scans_involved': len(source_scans),
                'source_scans': source_scans,
                'first_seen': correlation.first_seen.isoformat(),
                'last_seen': correlation.last_seen.isoformat(),
                'trend': correlation.trend,
                'confidence': correlation.confidence,
                'analysis': self._generate_cross_scan_analysis(correlation, sfEvent.eventType)
            }

            cross_scan_event = SpiderFootEvent(
                "AI_CROSS_SCAN_CORRELATION",
                json.dumps(correlation_data, default=str),
                self.__name__,
                sfEvent
            )
            self.notifyListeners(cross_scan_event)

    def _generate_cross_scan_analysis(self, correlation: CrossScanCorrelation, event_type: str) -> str:
        """Generate human-readable analysis for cross-scan correlation.

        Args:
            correlation: The CrossScanCorrelation object
            event_type: The type of event

        Returns:
            Analysis string
        """
        analysis_parts = []

        # Basic finding
        analysis_parts.append(
            f"IOC '{correlation.current_ioc}' has been observed in "
            f"{correlation.occurrence_count} scan(s) across {len(correlation.source_scans)} "
            f"historical scan session(s)."
        )

        # Time span
        time_span = correlation.last_seen - correlation.first_seen
        if time_span.days > 0:
            analysis_parts.append(
                f"First seen {time_span.days} days ago, indicating persistent presence."
            )

        # Trend analysis
        if correlation.trend == "increasing":
            analysis_parts.append(
                "Frequency is INCREASING - this IOC is appearing more often in recent scans."
            )
        elif correlation.trend == "decreasing":
            analysis_parts.append(
                "Frequency is DECREASING - this IOC is appearing less often recently."
            )
        elif correlation.trend == "stable":
            analysis_parts.append(
                "Frequency is STABLE - this IOC appears consistently across scans."
            )

        # Confidence and recommendation
        if correlation.confidence >= 0.8:
            analysis_parts.append(
                "HIGH CONFIDENCE: Strong correlation across multiple scans suggests "
                "this is a significant indicator requiring attention."
            )
        elif correlation.confidence >= 0.6:
            analysis_parts.append(
                "MEDIUM CONFIDENCE: Correlation found across scans. "
                "Consider investigating further."
            )

        return " ".join(analysis_parts)

# End of Threat Intelligence Engine
