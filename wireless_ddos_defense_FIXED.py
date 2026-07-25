#!/usr/bin/env python3
"""
================================================================================
WIRELESS NETWORK DEFENSE SYSTEM AGAINST DISTRIBUTED DENIAL-OF-SERVICE ATTACKS
================================================================================
With Machine Learning Integration (Random Forest, XGBoost, SVM, Isolation Forest)

A Single-File Student Project for Network Security Course

FIXED VERSION - Works on any PC without hardcoded paths
================================================================================
"""

import socket
import struct
import time
import threading
import json
import os
import random
import math
import pickle
from collections import defaultdict, deque, Counter
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass

# ============================================================
# OPTIONAL IMPORTS - GRACEFUL DEGRADATION
# ============================================================
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False
    print("WARNING: numpy not installed. ML features limited. Run: pip install numpy")

try:
    from sklearn.ensemble import RandomForestClassifier, IsolationForest
    from sklearn.svm import SVC
    from sklearn.preprocessing import StandardScaler
    from sklearn.model_selection import cross_val_score
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    print("WARNING: scikit-learn not installed. Advanced ML disabled. Run: pip install scikit-learn")

try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False
    print("WARNING: xgboost not installed. XGBoost model disabled. Run: pip install xgboost")

# ============================================================
# CONFIGURATION
# ============================================================
CONFIG = {
    "network_interface": "wlan0",
    "monitor_mode": False,
    "syn_flood_threshold": 100,
    "udp_flood_threshold": 500,
    "icmp_flood_threshold": 50,
    "http_flood_threshold": 300,
    "rate_limit_pps": 1000,
    "blacklist_duration": 300,
    "whitelist": ["127.0.0.1", "192.168.1.1"],
    "alert_threshold": "medium",
    "log_file": "defense_logs.txt",
    "enable_iptables": False,

    # ML Configuration
    "ml_enabled": True,
    "ml_training_mode": True,
    "ml_min_samples": 1000,
    "ml_voting": "majority",
    "ml_confidence_threshold": 0.7,
    "ml_contamination": 0.05,
}

# ============================================================
# LOGGING SETUP
# ============================================================
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)-8s | %(message)s',
    handlers=[
        logging.FileHandler(CONFIG["log_file"]),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('WDDDS')

# ============================================================
# DATA STRUCTURES
# ============================================================
class PacketInfo:
    def __init__(self, timestamp, src_ip, dst_ip, src_port, dst_port, 
                 protocol, length, flags="", ttl=64):
        self.timestamp = timestamp
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.length = length
        self.flags = flags
        self.ttl = ttl

class BlacklistEntry:
    def __init__(self, ip, reason, severity, expiry):
        self.ip = ip
        self.reason = reason
        self.severity = severity
        self.first_seen = time.time()
        self.last_seen = time.time()
        self.expiry = expiry
        self.hit_count = 0

@dataclass
class DetectionResult:
    algorithm: str
    is_attack: bool
    confidence: float
    feature_importance: Dict[str, float]
    prediction_time_ms: float

# ============================================================
# FEATURE EXTRACTOR FOR ML
# ============================================================
class FeatureExtractor:
    FEATURE_NAMES = [
        'packet_rate', 'byte_rate', 'syn_ratio', 'udp_ratio', 'icmp_ratio', 'tcp_ratio',
        'unique_src_ips', 'unique_dst_ips', 'unique_dst_ports', 'avg_packet_size',
        'std_packet_size', 'entropy_src_ip', 'entropy_dst_port', 'flow_count',
        'packets_per_flow', 'bytes_per_flow', 'incoming_ratio', 'flag_entropy'
    ]

    def extract(self, traffic_window, window_seconds=5.0):
        if not traffic_window or len(traffic_window) < 10:
            return None

        total = len(traffic_window)
        packet_rate = total / window_seconds
        byte_rate = sum(p.get('length', 0) for p in traffic_window) / window_seconds

        syn_count = sum(1 for p in traffic_window 
                       if p.get('protocol') == 'TCP' and 'S' in p.get('flags', ''))
        udp_count = sum(1 for p in traffic_window if p.get('protocol') == 'UDP')
        icmp_count = sum(1 for p in traffic_window if p.get('protocol') == 'ICMP')
        tcp_count = sum(1 for p in traffic_window if p.get('protocol') == 'TCP')

        syn_ratio = syn_count / total
        udp_ratio = udp_count / total
        icmp_ratio = icmp_count / total
        tcp_ratio = tcp_count / total

        src_ips = [p.get('src_ip') for p in traffic_window]
        dst_ips = [p.get('dst_ip') for p in traffic_window]
        dst_ports = [p.get('dst_port', 0) for p in traffic_window]

        unique_src_ips = len(set(src_ips))
        unique_dst_ips = len(set(dst_ips))
        unique_dst_ports = len(set(dst_ports))

        sizes = [p.get('length', 0) for p in traffic_window]
        avg_packet_size = sum(sizes) / len(sizes)
        std_packet_size = (sum((x - avg_packet_size) ** 2 for x in sizes) / len(sizes)) ** 0.5 if len(sizes) > 1 else 0

        entropy_src_ip = self._calculate_entropy(src_ips)
        entropy_dst_port = self._calculate_entropy(dst_ports)

        flows = {}
        for p in traffic_window:
            flow_key = (p.get('src_ip'), p.get('dst_ip'), p.get('dst_port'), p.get('protocol'))
            if flow_key not in flows:
                flows[flow_key] = {'count': 0, 'bytes': 0}
            flows[flow_key]['count'] += 1
            flows[flow_key]['bytes'] += p.get('length', 0)

        flow_count = len(flows)
        packets_per_flow = sum(f['count'] for f in flows.values()) / len(flows) if flows else 0
        bytes_per_flow = sum(f['bytes'] for f in flows.values()) / len(flows) if flows else 0

        local_prefixes = ('192.168.', '10.', '172.16.')
        incoming = sum(1 for p in traffic_window 
                      if not p.get('src_ip', '').startswith(local_prefixes))
        incoming_ratio = incoming / total if total > 0 else 0

        flags = [p.get('flags', '') for p in traffic_window if p.get('protocol') == 'TCP']
        flag_entropy = self._calculate_entropy(flags) if flags else 0

        features = [
            packet_rate, byte_rate, syn_ratio, udp_ratio, icmp_ratio, tcp_ratio,
            unique_src_ips, unique_dst_ips, unique_dst_ports, avg_packet_size,
            std_packet_size, entropy_src_ip, entropy_dst_port, flow_count,
            packets_per_flow, bytes_per_flow, incoming_ratio, flag_entropy
        ]

        if NUMPY_AVAILABLE:
            return np.array(features).reshape(1, -1)
        return [features]

    def _calculate_entropy(self, values):
        if not values:
            return 0.0
        counts = Counter(values)
        total = len(values)
        entropy = 0.0
        for count in counts.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)
        max_entropy = math.log2(len(counts)) if len(counts) > 1 else 1
        return entropy / max_entropy if max_entropy > 0 else 0

# ============================================================
# ML MODELS
# ============================================================
class BaseMLModel:
    def __init__(self, name, model_path):
        self.name = name
        self.model_path = model_path
        self.model = None
        self.is_trained = False
        self.scaler = None

    def train(self, X, y):
        raise NotImplementedError

    def predict(self, X):
        raise NotImplementedError

    def save(self):
        if self.model is not None:
            try:
                data = {'model': self.model, 'scaler': self.scaler}
                os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
                with open(self.model_path, 'wb') as f:
                    pickle.dump(data, f)
                logger.info(f"{self.name} model saved")
            except Exception as e:
                logger.error(f"Failed to save {self.name}: {e}")

    def load(self):
        if os.path.exists(self.model_path):
            try:
                with open(self.model_path, 'rb') as f:
                    data = pickle.load(f)
                self.model = data['model']
                self.scaler = data.get('scaler')
                self.is_trained = True
                logger.info(f"{self.name} model loaded")
                return True
            except Exception as e:
                logger.error(f"Failed to load {self.name}: {e}")
        return False

class RandomForestModel(BaseMLModel):
    def __init__(self, model_path="models/rf_model.pkl"):
        super().__init__("RandomForest", model_path)

    def train(self, X, y):
        if not SKLEARN_AVAILABLE:
            return False
        try:
            logger.info(f"Training Random Forest on {len(X)} samples...")
            self.model = RandomForestClassifier(
                n_estimators=100, max_depth=15, random_state=42, n_jobs=-1, class_weight='balanced'
            )
            self.model.fit(X, y)
            scores = cross_val_score(self.model, X, y, cv=5)
            logger.info(f"Random Forest CV accuracy: {scores.mean():.3f}")
            self.is_trained = True
            self.save()
            return True
        except Exception as e:
            logger.error(f"Random Forest training failed: {e}")
            return False

    def predict(self, X):
        if not self.is_trained:
            return False, 0.0
        proba = self.model.predict_proba(X)[0]
        attack_prob = proba[1] if len(proba) > 1 else proba[0]
        return attack_prob > 0.5, float(attack_prob)

    def get_feature_importance(self):
        if not self.is_trained:
            return {}
        importance = self.model.feature_importances_
        return {name: round(float(imp), 4) for name, imp in zip(FeatureExtractor.FEATURE_NAMES, importance)}

class XGBoostModel(BaseMLModel):
    def __init__(self, model_path="models/xgb_model.pkl"):
        super().__init__("XGBoost", model_path)

    def train(self, X, y):
        if not XGBOOST_AVAILABLE:
            logger.error("XGBoost not installed. Run: pip install xgboost")
            return False
        try:
            logger.info(f"Training XGBoost on {len(X)} samples...")
            self.model = xgb.XGBClassifier(
                n_estimators=100, max_depth=6, learning_rate=0.1,
                random_state=42, n_jobs=-1, scale_pos_weight=10
            )
            self.model.fit(X, y)
            scores = cross_val_score(self.model, X, y, cv=5)
            logger.info(f"XGBoost CV accuracy: {scores.mean():.3f}")
            self.is_trained = True
            self.save()
            return True
        except Exception as e:
            logger.error(f"XGBoost training failed: {e}")
            return False

    def predict(self, X):
        if not self.is_trained:
            return False, 0.0
        attack_prob = self.model.predict_proba(X)[0][1]
        return attack_prob > 0.5, float(attack_prob)

    def get_feature_importance(self):
        if not self.is_trained:
            return {}
        importance = self.model.feature_importances_
        return {name: round(float(imp), 4) for name, imp in zip(FeatureExtractor.FEATURE_NAMES, importance)}

class SVMModel(BaseMLModel):
    def __init__(self, model_path="models/svm_model.pkl"):
        super().__init__("SVM", model_path)

    def train(self, X, y):
        if not SKLEARN_AVAILABLE:
            return False
        try:
            logger.info(f"Training SVM on {len(X)} samples...")
            self.scaler = StandardScaler()
            X_scaled = self.scaler.fit_transform(X)
            self.model = SVC(kernel='rbf', C=1.0, probability=True, random_state=42, class_weight='balanced')
            self.model.fit(X_scaled, y)
            self.is_trained = True
            self.save()
            logger.info("SVM trained successfully")
            return True
        except Exception as e:
            logger.error(f"SVM training failed: {e}")
            return False

    def predict(self, X):
        if not self.is_trained or self.scaler is None:
            return False, 0.0
        X_scaled = self.scaler.transform(X)
        attack_prob = self.model.predict_proba(X_scaled)[0][1]
        return attack_prob > 0.5, float(attack_prob)

class IsolationForestModel(BaseMLModel):
    def __init__(self, model_path="models/if_model.pkl"):
        super().__init__("IsolationForest", model_path)
        self.contamination = 0.1

    def train(self, X, y=None):
        if not SKLEARN_AVAILABLE:
            return False
        try:
            logger.info(f"Training Isolation Forest on {len(X)} samples...")
            self.model = IsolationForest(
                n_estimators=100, contamination=self.contamination,
                random_state=42, n_jobs=-1
            )
            self.model.fit(X)
            self.is_trained = True
            self.save()
            return True
        except Exception as e:
            logger.error(f"Isolation Forest training failed: {e}")
            return False

    def predict(self, X):
        if not self.is_trained:
            return False, 0.0
        prediction = self.model.predict(X)[0]
        score = -self.model.score_samples(X)[0]
        is_anomaly = (prediction == -1)
        return is_anomaly, float(score)

# ============================================================
# ENSEMBLE DETECTOR
# ============================================================
class EnsembleDetector:
    def __init__(self, models_dir="models"):
        self.models_dir = models_dir
        os.makedirs(models_dir, exist_ok=True)

        self.feature_extractor = FeatureExtractor()
        self.models = {}

        if SKLEARN_AVAILABLE:
            self.models['random_forest'] = RandomForestModel(f"{models_dir}/rf_model.pkl")
            self.models['svm'] = SVMModel(f"{models_dir}/svm_model.pkl")
            self.models['isolation_forest'] = IsolationForestModel(f"{models_dir}/if_model.pkl")

        if XGBOOST_AVAILABLE:
            self.models['xgboost'] = XGBoostModel(f"{models_dir}/xgb_model.pkl")

        self.training_buffer_X = []
        self.training_buffer_y = []
        self.min_training_samples = CONFIG.get("ml_min_samples", 1000)

        for name, model in self.models.items():
            model.load()

    def extract_features(self, traffic_window):
        return self.feature_extractor.extract(traffic_window)

    def add_training_sample(self, features, is_attack):
        if NUMPY_AVAILABLE:
            self.training_buffer_X.append(features[0])
        else:
            self.training_buffer_X.append(features[0] if isinstance(features, list) else features)
        self.training_buffer_y.append(1 if is_attack else 0)

    def train_all_models(self):
        if len(self.training_buffer_X) < self.min_training_samples:
            logger.warning(f"Need {self.min_training_samples} samples, have {len(self.training_buffer_X)}")
            return {}

        X = np.array(self.training_buffer_X) if NUMPY_AVAILABLE else self.training_buffer_X
        y = np.array(self.training_buffer_y) if NUMPY_AVAILABLE else self.training_buffer_y

        results = {}
        for name, model in self.models.items():
            logger.info(f"Training {name}...")
            success = model.train(X, y)
            results[name] = success

        return results

    def detect(self, traffic_window, voting='majority'):
        features = self.extract_features(traffic_window)
        if features is None:
            return None

        predictions = {}
        confidences = {}

        for name, model in self.models.items():
            if model.is_trained:
                is_attack, confidence = model.predict(features)
                predictions[name] = is_attack
                confidences[name] = confidence

        if not predictions:
            return None

        if voting == 'majority':
            attack_votes = sum(1 for v in predictions.values() if v)
            is_attack = attack_votes > len(predictions) / 2
            avg_confidence = sum(confidences.values()) / len(confidences)
        elif voting == 'unanimous':
            is_attack = all(predictions.values())
            avg_confidence = min(confidences.values())
        else:
            weighted_sum = sum(confidences.values())
            avg_confidence = weighted_sum / len(confidences)
            is_attack = avg_confidence > 0.5

        feature_importance = {}
        if 'random_forest' in self.models and self.models['random_forest'].is_trained:
            feature_importance = self.models['random_forest'].get_feature_importance()

        return DetectionResult(
            algorithm=f"ensemble_{voting}",
            is_attack=is_attack,
            confidence=round(float(avg_confidence), 4),
            feature_importance=feature_importance,
            prediction_time_ms=0.0
        )

    def get_model_status(self):
        return {name: model.is_trained for name, model in self.models.items()}

# ============================================================
# MAIN DEFENSE SYSTEM
# ============================================================
class WirelessDDoSDefenseSystem:
    def __init__(self, config):
        self.config = config
        self.is_running = False

        self.ip_packet_counts = defaultdict(int)
        self.ip_byte_counts = defaultdict(int)
        self.ip_timestamps = defaultdict(lambda: deque(maxlen=1000))

        self.syn_counts = defaultdict(int)
        self.udp_counts = defaultdict(int)
        self.icmp_counts = defaultdict(int)
        self.http_counts = defaultdict(int)

        self.flows = {}
        self.port_scan_tracker = defaultdict(set)

        self.blacklist = {}
        self.whitelist = set(config.get("whitelist", []))

        self.rate_limit_buckets = {}
        self.rate_limit_last_update = {}

        self.total_packets = 0
        self.total_bytes = 0
        self.attacks_detected = 0
        self.packets_dropped = 0
        self.ips_blocked = 0

        self.detection_log = deque(maxlen=100)
        self.defense_log = deque(maxlen=100)
        self.packet_rate_history = deque(maxlen=60)

        self.lock = threading.Lock()
        self.start_time = time.time()

        # ML Integration
        self.ml_enabled = config.get("ml_enabled", True) and (SKLEARN_AVAILABLE or XGBOOST_AVAILABLE)
        self.ml_detector = None
        self.ml_traffic_buffer = deque(maxlen=1000)
        self.ml_training_mode = config.get("ml_training_mode", True)
        self.ml_attack_count = 0
        self.ml_normal_count = 0

        if self.ml_enabled:
            self.setup_ml_ensemble()

        logger.info("=" * 60)
        logger.info("WIRELESS NETWORK DEFENSE SYSTEM INITIALIZED")
        logger.info("=" * 60)
        logger.info(f"Interface: {config['network_interface']}")
        logger.info(f"ML Enabled: {self.ml_enabled}")
        if self.ml_enabled and self.ml_detector:
            logger.info(f"ML Models: {list(self.ml_detector.models.keys())}")
        logger.info("=" * 60)

    def setup_ml_ensemble(self):
        try:
            self.ml_detector = EnsembleDetector(models_dir="models")
            status = self.ml_detector.get_model_status()
            logger.info(f"ML Models status: {status}")

            if not any(status.values()):
                logger.info("ML models not trained. Entering training mode...")
                self.ml_training_mode = True
            else:
                self.ml_training_mode = False
        except Exception as e:
            logger.error(f"ML setup failed: {e}")
            self.ml_enabled = False

    def capture_packets(self):
        interface = self.config["network_interface"]
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            sock.bind((interface, 0))
            sock.settimeout(1)
            logger.info(f"Raw socket capture started on {interface}")

            while self.is_running:
                try:
                    raw_data, addr = sock.recvfrom(65535)
                    packet = self.parse_ethernet_frame(raw_data)
                    if packet:
                        self.process_packet(packet)
                except socket.timeout:
                    continue
                except Exception as e:
                    logger.error(f"Capture error: {e}")
        except PermissionError:
            logger.warning("Permission denied. Running SIMULATION mode.")
            self.simulate_traffic()
        except Exception as e:
            logger.error(f"Capture setup failed: {e}")
            self.simulate_traffic()

    def parse_ethernet_frame(self, data):
        eth_header = data[:14]
        eth_type = struct.unpack('!H', eth_header[12:14])[0]

        if eth_type != 0x0800:
            return None

        ip_header = data[14:34]
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

        version_ihl = iph[0]
        ihl = version_ihl & 0xF
        iph_length = ihl * 4

        protocol = iph[6]
        src_ip = socket.inet_ntoa(iph[8])
        dst_ip = socket.inet_ntoa(iph[9])
        ttl = iph[5]

        src_port = 0
        dst_port = 0
        flags = ""
        proto_name = "OTHER"

        if protocol == 6:
            proto_name = "TCP"
            tcp_header = data[14 + iph_length:14 + iph_length + 20]
            if len(tcp_header) >= 20:
                tcph = struct.unpack('!HHLLBBHHH', tcp_header)
                src_port = tcph[0]
                dst_port = tcph[1]
                flags = self.parse_tcp_flags(tcph[5])
        elif protocol == 17:
            proto_name = "UDP"
            udp_header = data[14 + iph_length:14 + iph_length + 8]
            if len(udp_header) >= 8:
                udph = struct.unpack('!HHHH', udp_header)
                src_port = udph[0]
                dst_port = udph[1]
        elif protocol == 1:
            proto_name = "ICMP"

        return PacketInfo(
            timestamp=time.time(), src_ip=src_ip, dst_ip=dst_ip,
            src_port=src_port, dst_port=dst_port, protocol=proto_name,
            length=len(data), flags=flags, ttl=ttl
        )

    def parse_tcp_flags(self, flag_byte):
        flags = []
        if flag_byte & 0x01: flags.append('F')
        if flag_byte & 0x02: flags.append('S')
        if flag_byte & 0x04: flags.append('R')
        if flag_byte & 0x08: flags.append('P')
        if flag_byte & 0x10: flags.append('A')
        if flag_byte & 0x20: flags.append('U')
        return ''.join(flags) if flags else '-'

    def simulate_traffic(self):
        logger.info("Running SIMULATION MODE")
        normal_ips = [f"192.168.1.{i}" for i in range(2, 50)]
        attack_ips = [f"10.0.0.{i}" for i in range(1, 20)]
        protocols = ["TCP", "UDP", "ICMP"]

        while self.is_running:
            is_attack = random.random() < 0.1

            if is_attack:
                attacker = random.choice(attack_ips)
                attack_type = random.choice(["syn", "udp", "icmp", "http"])

                for _ in range(random.randint(20, 100)):
                    if attack_type == "syn":
                        pkt = PacketInfo(time.time(), attacker, "192.168.1.1",
                                       random.randint(1024, 65535), 80, "TCP",
                                       random.randint(64, 150), "S")
                    elif attack_type == "udp":
                        pkt = PacketInfo(time.time(), attacker, "192.168.1.1",
                                       random.randint(1024, 65535),
                                       random.choice([53, 80, 443]), "UDP",
                                       random.randint(64, 1500))
                    elif attack_type == "icmp":
                        pkt = PacketInfo(time.time(), attacker, "192.168.1.1",
                                       0, 0, "ICMP", random.randint(64, 100))
                    else:
                        pkt = PacketInfo(time.time(), attacker, "192.168.1.1",
                                       random.randint(1024, 65535), 80, "TCP",
                                       random.randint(200, 800), "PA")
                    self.process_packet(pkt)
            else:
                pkt = PacketInfo(
                    time.time(), random.choice(normal_ips), random.choice(normal_ips),
                    random.randint(1024, 65535), random.choice([80, 443, 53, 22]),
                    random.choice(protocols), random.randint(64, 1500)
                )
                self.process_packet(pkt)

            time.sleep(0.01)

    def process_packet(self, packet):
        src_ip = packet.src_ip

        if src_ip in self.whitelist:
            return

        if self.is_blacklisted(src_ip):
            self.packets_dropped += 1
            return

        if not self.check_rate_limit(src_ip):
            self.packets_dropped += 1
            return

        with self.lock:
            self.total_packets += 1
            self.total_bytes += packet.length
            self.ip_packet_counts[src_ip] += 1
            self.ip_byte_counts[src_ip] += packet.length
            self.ip_timestamps[src_ip].append(packet.timestamp)

        if packet.protocol == "TCP":
            self.track_tcp_packet(packet)
        elif packet.protocol == "UDP":
            self.track_udp_packet(packet)
        elif packet.protocol == "ICMP":
            self.track_icmp_packet(packet)

        self.track_flow(packet)
        self.detect_port_scan(packet)

        # ML Processing
        if self.ml_enabled and self.ml_detector:
            self.ml_traffic_buffer.append({
                'timestamp': packet.timestamp,
                'src_ip': packet.src_ip,
                'dst_ip': packet.dst_ip,
                'src_port': packet.src_port,
                'dst_port': packet.dst_port,
                'protocol': packet.protocol,
                'length': packet.length,
                'flags': packet.flags
            })

            if len(self.ml_traffic_buffer) >= 100:
                self.run_ml_detection()

    def track_tcp_packet(self, packet):
        src_ip = packet.src_ip

        if 'S' in packet.flags and 'A' not in packet.flags:
            with self.lock:
                self.syn_counts[src_ip] += 1

            if self.syn_counts[src_ip] > self.config["syn_flood_threshold"]:
                self.report_attack("SYN_FLOOD", src_ip, {
                    "syn_count": self.syn_counts[src_ip],
                    "target_port": packet.dst_port
                }, "high")
                self.syn_counts[src_ip] = 0

        if packet.dst_port in [80, 443, 8080]:
            with self.lock:
                self.http_counts[src_ip] += 1

            if self.http_counts[src_ip] > self.config["http_flood_threshold"]:
                self.report_attack("HTTP_FLOOD", src_ip, {
                    "request_count": self.http_counts[src_ip],
                    "target_port": packet.dst_port
                }, "high")
                self.http_counts[src_ip] = 0

    def track_udp_packet(self, packet):
        src_ip = packet.src_ip

        with self.lock:
            self.udp_counts[src_ip] += 1

        if self.udp_counts[src_ip] > self.config["udp_flood_threshold"]:
            self.report_attack("UDP_FLOOD", src_ip, {
                "packet_count": self.udp_counts[src_ip],
                "target_port": packet.dst_port,
                "packet_size": packet.length
            }, "high")
            self.udp_counts[src_ip] = 0

    def track_icmp_packet(self, packet):
        src_ip = packet.src_ip

        with self.lock:
            self.icmp_counts[src_ip] += 1

        if self.icmp_counts[src_ip] > self.config["icmp_flood_threshold"]:
            self.report_attack("ICMP_FLOOD", src_ip, {
                "packet_count": self.icmp_counts[src_ip]
            }, "medium")
            self.icmp_counts[src_ip] = 0

    def track_flow(self, packet):
        flow_key = f"{packet.src_ip}:{packet.dst_ip}:{packet.dst_port}:{packet.protocol}"

        with self.lock:
            if flow_key not in self.flows:
                self.flows[flow_key] = {
                    "packet_count": 0, "byte_count": 0,
                    "start_time": packet.timestamp, "last_seen": packet.timestamp
                }
            self.flows[flow_key]["packet_count"] += 1
            self.flows[flow_key]["byte_count"] += packet.length
            self.flows[flow_key]["last_seen"] = packet.timestamp

    def detect_port_scan(self, packet):
        src_ip = packet.src_ip
        self.port_scan_tracker[src_ip].add(packet.dst_port)

        if len(self.port_scan_tracker[src_ip]) > 20:
            self.report_attack("PORT_SCAN", src_ip, {
                "unique_ports": len(self.port_scan_tracker[src_ip]),
                "ports_scanned": sorted(list(self.port_scan_tracker[src_ip]))[:10]
            }, "medium")
            self.port_scan_tracker[src_ip].clear()

    def check_rate_limit(self, src_ip):
        current_time = time.time()
        max_tokens = self.config["rate_limit_pps"] * 2
        refill_rate = self.config["rate_limit_pps"]

        with self.lock:
            if src_ip not in self.rate_limit_buckets:
                self.rate_limit_buckets[src_ip] = max_tokens
                self.rate_limit_last_update[src_ip] = current_time

            time_delta = current_time - self.rate_limit_last_update[src_ip]
            self.rate_limit_buckets[src_ip] = min(
                max_tokens,
                self.rate_limit_buckets[src_ip] + time_delta * refill_rate
            )
            self.rate_limit_last_update[src_ip] = current_time

            if self.rate_limit_buckets[src_ip] >= 1:
                self.rate_limit_buckets[src_ip] -= 1
                return True
            else:
                self.report_attack("RATE_LIMIT_EXCEEDED", src_ip, {
                    "threshold": self.config["rate_limit_pps"]
                }, "low")
                return False

    def is_blacklisted(self, ip):
        if ip in self.blacklist:
            entry = self.blacklist[ip]
            if time.time() > entry.expiry:
                del self.blacklist[ip]
                logger.info(f"Blacklist entry expired for {ip}")
                return False
            entry.hit_count += 1
            entry.last_seen = time.time()
            return True
        return False

    def add_to_blacklist(self, ip, reason, severity="high", duration=None):
        if ip in self.whitelist:
            logger.warning(f"Cannot blacklist whitelisted IP: {ip}")
            return False

        if duration is None:
            duration = self.config["blacklist_duration"]

        with self.lock:
            if ip in self.blacklist:
                self.blacklist[ip].last_seen = time.time()
                self.blacklist[ip].expiry = time.time() + duration
                self.blacklist[ip].hit_count += 1
            else:
                self.blacklist[ip] = BlacklistEntry(ip, reason, severity, time.time() + duration)
                self.ips_blocked += 1

        logger.warning(f"🚫 IP {ip} BLACKLISTED | Reason: {reason} | Duration: {duration}s")

        defense_action = {
            "timestamp": datetime.now().isoformat(),
            "action_type": "BLACKLIST",
            "target_ip": ip,
            "reason": reason,
            "duration": duration,
            "success": True
        }
        self.defense_log.append(defense_action)

        if self.config["enable_iptables"]:
            self.apply_iptables_rule(ip, "DROP")

        return True

    def remove_from_blacklist(self, ip):
        with self.lock:
            if ip in self.blacklist:
                del self.blacklist[ip]
                logger.info(f"IP {ip} removed from blacklist")
                if self.config["enable_iptables"]:
                    self.remove_iptables_rule(ip, "DROP")
                return True
        return False

    def apply_iptables_rule(self, ip, action):
        import subprocess
        try:
            subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", action],
                         capture_output=True, timeout=5)
            logger.info(f"iptables rule applied: {ip} -> {action}")
        except Exception as e:
            logger.error(f"iptables error: {e}")

    def remove_iptables_rule(self, ip, action):
        import subprocess
        try:
            subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", action],
                         capture_output=True, timeout=5)
            logger.info(f"iptables rule removed for {ip}")
        except Exception as e:
            logger.error(f"iptables removal error: {e}")

    def report_attack(self, attack_type, source_ip, details, severity):
        self.attacks_detected += 1

        logger.critical(f"🚨 ATTACK DETECTED: {attack_type} from {source_ip} [{severity}]")
        logger.critical(f"   Details: {json.dumps(details, indent=2)}")

        detection = {
            "timestamp": datetime.now().isoformat(),
            "attack_type": attack_type,
            "source_ip": source_ip,
            "severity": severity,
            "details": details,
            "mitigated": False
        }
        self.detection_log.append(detection)

        if severity in ["high", "critical"]:
            self.mitigate_attack(source_ip, attack_type, severity)
            detection["mitigated"] = True

    def mitigate_attack(self, source_ip, attack_type, severity):
        logger.info(f"Applying mitigation for {attack_type} from {source_ip}")

        duration = self.config["blacklist_duration"]
        if severity == "critical":
            duration *= 4
        elif severity == "high":
            duration *= 2

        self.add_to_blacklist(source_ip, attack_type, severity, duration)

        if "SYN" in attack_type:
            self.enable_syn_cookies()

        self.save_attack_report(source_ip, attack_type, severity)

    def enable_syn_cookies(self):
        try:
            import subprocess
            result = subprocess.run(["sysctl", "net.ipv4.tcp_syncookies"],
                                  capture_output=True, text=True, timeout=5)
            if "= 1" not in result.stdout:
                subprocess.run(["sysctl", "-w", "net.ipv4.tcp_syncookies=1"],
                             capture_output=True, timeout=5)
                logger.info("TCP SYN cookies enabled")
        except Exception as e:
            logger.debug(f"Could not enable SYN cookies: {e}")

    def save_attack_report(self, source_ip, attack_type, severity):
        report = {
            "timestamp": datetime.now().isoformat(),
            "source_ip": source_ip,
            "attack_type": attack_type,
            "severity": severity,
            "system_stats": self.get_statistics()
        }

        filename = f"attack_report_{int(time.time())}.json"
        try:
            with open(filename, "w") as f:
                json.dump(report, f, indent=2)
            logger.info(f"Attack report saved: {filename}")
        except Exception as e:
            logger.error(f"Failed to save report: {e}")

    def run_ml_detection(self):
        if not self.ml_detector:
            return

        try:
            window = list(self.ml_traffic_buffer)

            if self.ml_training_mode:
                is_attack = (self.attacks_detected > self.ml_attack_count)

                features = self.ml_detector.extract_features(window)
                if features is not None:
                    self.ml_detector.add_training_sample(features, is_attack)

                    if is_attack:
                        self.ml_attack_count = self.attacks_detected
                    else:
                        self.ml_normal_count += 1

                    total_samples = len(self.ml_detector.training_buffer_X)
                    if total_samples >= self.ml_detector.min_training_samples:
                        logger.info(f"Training ML models with {total_samples} samples...")
                        results = self.ml_detector.train_all_models()
                        if any(results.values()):
                            self.ml_training_mode = False
                            logger.info("ML models trained! Detection mode active.")

            else:
                result = self.ml_detector.detect(window, voting=self.config.get("ml_voting", "majority"))

                if result and result.is_attack and result.confidence > self.config.get("ml_confidence_threshold", 0.7):
                    ip_counts = Counter(p.get('src_ip') for p in window)
                    attacker = ip_counts.most_common(1)[0][0]

                    self.report_attack("ML_ENSEMBLE_DETECTED", attacker, {
                        "confidence": result.confidence,
                        "algorithm": result.algorithm,
                        "top_features": dict(sorted(
                            result.feature_importance.items(),
                            key=lambda x: x[1],
                            reverse=True
                        )[:5])
                    }, "high")

                    self.ml_traffic_buffer.clear()

        except Exception as e:
            logger.error(f"ML detection error: {e}")

    def periodic_analysis(self):
        while self.is_running:
            time.sleep(5)
            if not self.is_running:
                break

            try:
                self.analyze_traffic_patterns()
                self.cleanup_expired_entries()
            except Exception as e:
                logger.error(f"Periodic analysis error: {e}")

    def analyze_traffic_patterns(self):
        current_time = time.time()

        with self.lock:
            for ip, timestamps in list(self.ip_timestamps.items()):
                recent_count = sum(1 for t in timestamps if current_time - t < 1)

                if recent_count > self.config["rate_limit_pps"]:
                    self.report_attack("HIGH_VOLUME_TRAFFIC", ip, {
                        "packets_per_second": recent_count,
                        "threshold": self.config["rate_limit_pps"]
                    }, "medium")

            expired_flows = [
                key for key, flow in self.flows.items()
                if current_time - flow["last_seen"] > 300
            ]
            for key in expired_flows:
                del self.flows[key]

    def cleanup_expired_entries(self):
        current_time = time.time()

        with self.lock:
            expired = [
                ip for ip, entry in self.blacklist.items()
                if current_time > entry.expiry
            ]
            for ip in expired:
                del self.blacklist[ip]
                logger.info(f"Expired blacklist entry removed: {ip}")

    def get_statistics(self):
        with self.lock:
            uptime = time.time() - self.start_time
            return {
                "uptime_seconds": int(uptime),
                "total_packets": self.total_packets,
                "total_bytes": self.total_bytes,
                "packets_per_second": self.total_packets / max(uptime, 1),
                "attacks_detected": self.attacks_detected,
                "packets_dropped": self.packets_dropped,
                "ips_blocked": len(self.blacklist),
                "active_flows": len(self.flows),
                "unique_sources": len(self.ip_packet_counts),
                "blacklist_size": len(self.blacklist)
            }

    def get_ml_status(self):
        if not self.ml_detector:
            return {"enabled": False}

        return {
            "enabled": True,
            "training_mode": self.ml_training_mode,
            "models_trained": self.ml_detector.get_model_status(),
            "training_samples": len(self.ml_detector.training_buffer_X),
            "samples_needed": self.ml_detector.min_training_samples
        }

    def print_status(self):
        stats = self.get_statistics()

        separator = "=" * 50
        print()
        print(separator)
        print("SYSTEM STATUS REPORT")
        print(separator)
        print(f"Uptime: {stats['uptime_seconds']} seconds")
        print(f"Total Packets: {stats['total_packets']:,}")
        print(f"Attacks Detected: {stats['attacks_detected']}")
        print(f"Packets Dropped: {stats['packets_dropped']}")
        print(f"IPs Blocked: {stats['ips_blocked']}")
        if self.ml_enabled:
            ml = self.get_ml_status()
            print(f"ML Status: {'Training' if ml['training_mode'] else 'Active'}")
            print(f"ML Models: {ml['models_trained']}")
        print(separator)
        print()

    def start(self):
        self.is_running = True
        self.start_time = time.time()

        logger.info("=" * 60)
        logger.info("DEFENSE SYSTEM STARTED")
        logger.info("=" * 60)

        capture_thread = threading.Thread(target=self.capture_packets, daemon=True)
        capture_thread.start()

        analysis_thread = threading.Thread(target=self.periodic_analysis, daemon=True)
        analysis_thread.start()

        status_thread = threading.Thread(target=self.status_reporter, daemon=True)
        status_thread.start()

        logger.info("All threads started. System is ACTIVE.")
        logger.info("Press Ctrl+C to stop.")


        try:
            while self.is_running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()

    def status_reporter(self):
        while self.is_running:
            time.sleep(30)
            if self.is_running:
                self.print_status()

    def stop(self):
        logger.info("Shutting down defense system...")
        self.is_running = False

        self.print_status()
        self.save_final_report()

        logger.info("System shutdown complete.")

    def save_final_report(self):
        report = {
            "system_name": "Wireless Network Defense System with ML",
            "timestamp": datetime.now().isoformat(),
            "statistics": self.get_statistics(),
            "configuration": self.config,
            "detection_history": list(self.detection_log),
            "defense_history": list(self.defense_log),
            "ml_status": self.get_ml_status(),
            "blacklist_entries": [
                {
                    "ip": entry.ip,
                    "reason": entry.reason,
                    "severity": entry.severity,
                    "hit_count": entry.hit_count
                }
                for entry in self.blacklist.values()
            ]
        }

        try:
            with open("final_report.json", "w") as f:
                json.dump(report, f, indent=2)
            logger.info("Final report saved: final_report.json")
        except Exception as e:
            logger.error(f"Failed to save final report: {e}")


# ============================================================
# MAIN ENTRY POINT
# ============================================================
if __name__ == "__main__":
    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║     WIRELESS NETWORK DEFENSE SYSTEM                         ║
    ║     With ML: Random Forest, XGBoost, SVM, Isolation Forest  ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)

    defense_system = WirelessDDoSDefenseSystem(CONFIG)
    defense_system.start()
