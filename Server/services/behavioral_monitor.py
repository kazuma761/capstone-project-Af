"""
APSA (Adaptive Pattern Signature Analysis) Behavioral Monitor
Real-time process monitoring for ransomware/cryptojacking detection
"""

import asyncio
import psutil
import numpy as np
from scipy.spatial.distance import mahalanobis
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ThreatTier(str, Enum):
    CLEAN = "CLEAN"
    MONITOR = "MONITOR"
    SUSPICIOUS = "SUSPICIOUS"
    ALERT = "ALERT"


@dataclass
class ProcessFeatures:
    """Feature vector for a process: [fe, fa, fn, fc]"""
    fe: float = 0.0  # Encryption frequency
    fa: float = 0.0  # File access anomaly
    fn: float = 0.0  # Network anomaly
    fc: float = 0.0  # CPU/resource abuse
    
    def to_array(self) -> np.ndarray:
        return np.array([self.fe, self.fa, self.fn, self.fc])
    
    def to_dict(self) -> Dict[str, float]:
        return {"fe": self.fe, "fa": self.fa, "fn": self.fn, "fc": self.fc}


@dataclass
class ProcessBaseline:
    """Adaptive baseline for a process using EMA"""
    mean: np.ndarray = field(default_factory=lambda: np.zeros(4))
    covariance: np.ndarray = field(default_factory=lambda: np.eye(4) * 0.1)
    sample_count: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "mean": self.mean.tolist(),
            "covariance": self.covariance.tolist(),
            "sample_count": self.sample_count
        }


@dataclass
class ProcessInfo:
    """Complete process analysis info"""
    pid: int
    name: str
    features: ProcessFeatures
    risk_score: float
    tier: ThreatTier
    baseline: ProcessBaseline
    last_updated: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "pid": self.pid,
            "name": self.name,
            "features": self.features.to_dict(),
            "risk_score": round(self.risk_score, 4),
            "tier": self.tier.value,
            "last_updated": self.last_updated.isoformat()
        }


class APSAEngine:
    """
    Adaptive Pattern Signature Analysis Engine
    Implements probabilistic risk scoring with learned weights
    """
    
    # APSA weights from the paper
    WEIGHTS = {
        "we": 0.4,  # Encryption frequency weight
        "wa": 0.3,  # File access anomaly weight
        "wn": 0.2,  # Network anomaly weight
        "wc": 0.1   # CPU abuse weight
    }
    
    # Threat tier thresholds
    THRESHOLDS = {
        "clean": 0.40,
        "monitor": 0.65,
        "suspicious": 0.85
    }
    
    # EMA alpha for adaptive learning
    EMA_ALPHA = 0.1
    
    # Suspicious process patterns (ransomware indicators)
    SUSPICIOUS_PATTERNS = [
        "encrypt", "ransom", "crypt", "locker", "wanna", "petya", "locky",
        "cerber", "dharma", "ryuk", "conti", "lockbit", "blackcat"
    ]
    
    # Known safe processes to whitelist
    SAFE_PROCESSES = [
        "system", "svchost", "explorer", "csrss", "wininit", "services",
        "lsass", "smss", "conhost", "dwm", "taskhostw", "sihost",
        "chrome", "firefox", "msedge", "code", "python", "node"
    ]
    
    def __init__(self):
        self.process_baselines: Dict[str, ProcessBaseline] = {}
        self.process_history: Dict[int, List[ProcessFeatures]] = {}
        self.alerts: List[Dict[str, Any]] = []
        
    def sigmoid(self, x: float) -> float:
        """Sigmoid activation for probabilistic scoring"""
        return 1 / (1 + np.exp(-x))
    
    def calculate_weighted_score(self, features: ProcessFeatures) -> float:
        """Calculate S(x) = w·x weighted sum"""
        score = (
            self.WEIGHTS["we"] * features.fe +
            self.WEIGHTS["wa"] * features.fa +
            self.WEIGHTS["wn"] * features.fn +
            self.WEIGHTS["wc"] * features.fc
        )
        return score
    
    def calculate_risk_probability(self, features: ProcessFeatures) -> float:
        """Calculate P(R|X) = sigmoid(S(x))"""
        weighted_score = self.calculate_weighted_score(features)
        # Scale to make sigmoid more sensitive (multiply by factor)
        return self.sigmoid(weighted_score * 2 - 5)
    
    def calculate_mahalanobis_distance(
        self, features: ProcessFeatures, baseline: ProcessBaseline
    ) -> float:
        """Calculate Mahalanobis distance for coordinated anomaly detection"""
        try:
            x = features.to_array()
            # Add small regularization to prevent singular matrix
            cov = baseline.covariance + np.eye(4) * 1e-6
            cov_inv = np.linalg.inv(cov)
            diff = x - baseline.mean
            distance = np.sqrt(np.dot(np.dot(diff, cov_inv), diff))
            return float(distance)
        except Exception as e:
            logger.warning(f"Mahalanobis calculation failed: {e}")
            return 0.0
    
    def update_baseline_ema(
        self, baseline: ProcessBaseline, features: ProcessFeatures
    ) -> ProcessBaseline:
        """Update baseline using Exponential Moving Average"""
        x = features.to_array()
        
        if baseline.sample_count == 0:
            baseline.mean = x
            baseline.covariance = np.eye(4) * 0.1
        else:
            # EMA update for mean
            baseline.mean = (
                self.EMA_ALPHA * x + (1 - self.EMA_ALPHA) * baseline.mean
            )
            # EMA update for covariance
            diff = x - baseline.mean
            new_cov = np.outer(diff, diff)
            baseline.covariance = (
                self.EMA_ALPHA * new_cov + 
                (1 - self.EMA_ALPHA) * baseline.covariance
            )
        
        baseline.sample_count += 1
        return baseline
    
    def classify_tier(self, risk_probability: float) -> ThreatTier:
        """Classify threat tier based on probability thresholds"""
        if risk_probability < self.THRESHOLDS["clean"]:
            return ThreatTier.CLEAN
        elif risk_probability < self.THRESHOLDS["monitor"]:
            return ThreatTier.MONITOR
        elif risk_probability < self.THRESHOLDS["suspicious"]:
            return ThreatTier.SUSPICIOUS
        else:
            return ThreatTier.ALERT
    
    def is_suspicious_name(self, process_name: str) -> bool:
        """Check if process name matches suspicious patterns"""
        name_lower = process_name.lower()
        return any(pattern in name_lower for pattern in self.SUSPICIOUS_PATTERNS)
    
    def is_safe_process(self, process_name: str) -> bool:
        """Check if process is in safe whitelist"""
        name_lower = process_name.lower().replace(".exe", "")
        return name_lower in self.SAFE_PROCESSES


class BehavioralMonitor:
    """
    Real-time process behavioral monitor using APSA framework
    """
    
    def __init__(self):
        self.engine = APSAEngine()
        self.is_running = False
        self.monitored_processes: Dict[int, ProcessInfo] = {}
        self.websocket_callback = None
        self.monitoring_task: Optional[asyncio.Task] = None
        self.scan_interval = 2.0  # seconds
        
    def set_websocket_callback(self, callback):
        """Set callback for real-time WebSocket updates"""
        self.websocket_callback = callback
        
    async def extract_features(self, proc: psutil.Process) -> ProcessFeatures:
        """Extract behavioral features from a process"""
        features = ProcessFeatures()
        
        try:
            # CPU usage (fc - resource abuse)
            try:
                cpu_percent = proc.cpu_percent(interval=0.05)
                features.fc = min(cpu_percent / 100.0 * 10, 10)  # Scale 0-10
            except:
                features.fc = 0
            
            # Memory usage as proxy for activity
            try:
                memory_percent = proc.memory_percent()
                # Use memory as a factor in file access estimate
                features.fa = min(memory_percent / 10.0, 10)
            except:
                features.fa = 0
            
            # File access patterns (fa) - try to get open files
            try:
                open_files = proc.open_files()
                num_files = len(open_files)
                features.fa = max(features.fa, min(num_files / 50.0 * 10, 10))
                
                # Check for encryption-like patterns
                encrypt_indicators = sum(
                    1 for f in open_files 
                    if any(ext in f.path.lower() for ext in ['.encrypted', '.locked', '.crypt', '.enc'])
                )
                features.fe = min(encrypt_indicators * 2, 10)
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            
            # Network connections (fn)
            try:
                connections = proc.connections()
                num_connections = len(connections)
                external_conns = sum(
                    1 for c in connections 
                    if c.status == 'ESTABLISHED' and c.raddr
                )
                features.fn = min(external_conns / 10.0 * 10, 10)
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            
            # Boost scores for suspicious process names
            try:
                if self.engine.is_suspicious_name(proc.name()):
                    features.fe = min(features.fe + 5, 10)
                    features.fa = min(features.fa + 3, 10)
            except:
                pass
                
        except Exception as e:
            logger.debug(f"Feature extraction partial failure: {e}")
            
        return features
    
    async def analyze_process(self, proc: psutil.Process) -> Optional[ProcessInfo]:
        """Analyze a single process and return ProcessInfo"""
        try:
            pid = proc.pid
            name = proc.name()
            
            # Skip system-critical processes
            if pid < 10:
                return None
            
            # Skip idle/system
            if name.lower() in ['system idle process', 'system', '']:
                return None
                
            # Extract features
            features = await self.extract_features(proc)
            
            # Get or create baseline
            baseline_key = name.lower()
            if baseline_key not in self.engine.process_baselines:
                self.engine.process_baselines[baseline_key] = ProcessBaseline()
            baseline = self.engine.process_baselines[baseline_key]
            
            # Calculate risk
            risk_score = self.engine.calculate_risk_probability(features)
            
            # Boost risk for non-safe processes with high features
            if not self.engine.is_safe_process(name):
                mahal_dist = self.engine.calculate_mahalanobis_distance(features, baseline)
                if mahal_dist > 3:  # Significant deviation
                    risk_score = min(risk_score + 0.2, 1.0)
            
            # Classify tier
            tier = self.engine.classify_tier(risk_score)
            
            # Update baseline for clean processes (adaptive learning)
            if tier == ThreatTier.CLEAN:
                self.engine.update_baseline_ema(baseline, features)
            
            return ProcessInfo(
                pid=pid,
                name=name,
                features=features,
                risk_score=risk_score,
                tier=tier,
                baseline=baseline,
                last_updated=datetime.now()
            )
            
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
            logger.debug(f"Process {proc.pid} access error: {e}")
            return None
        except Exception as e:
            logger.debug(f"Process analysis error: {e}")
            return None
    
    async def scan_all_processes(self) -> List[ProcessInfo]:
        """Scan all running processes with real-time streaming"""
        results = []
        scanned = 0
        errors = 0
        
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                scanned += 1
                info = await self.analyze_process(proc)
                if info:
                    self.monitored_processes[info.pid] = info
                    results.append(info)
                    
                    # Stream each process to UI in real-time
                    if self.websocket_callback:
                        await self.websocket_callback({
                            "type": "process_scanned",
                            "process": info.to_dict(),
                            "progress": {
                                "scanned": scanned,
                                "found": len(results)
                            }
                        })
                    
                    # Generate alert for high-risk processes
                    if info.tier in [ThreatTier.SUSPICIOUS, ThreatTier.ALERT]:
                        alert = {
                            "type": "behavioral_alert",
                            "process": info.to_dict(),
                            "timestamp": datetime.now().isoformat()
                        }
                        self.engine.alerts.append(alert)
                        
                        # Send WebSocket notification immediately for alerts
                        if self.websocket_callback:
                            await self.websocket_callback(alert)
                            
            except Exception as e:
                errors += 1
                logger.debug(f"Error scanning process: {e}")
        
        logger.info(f"Scan complete: {len(results)} processes monitored out of {scanned} scanned ({errors} errors)")
        return results
    
    async def monitoring_loop(self):
        """Main monitoring loop"""
        logger.info("APSA Behavioral Monitor started")
        
        while self.is_running:
            try:
                await self.scan_all_processes()
                
                # Send periodic update
                if self.websocket_callback:
                    update = {
                        "type": "behavioral_update",
                        "process_count": len(self.monitored_processes),
                        "alert_count": len([
                            p for p in self.monitored_processes.values()
                            if p.tier in [ThreatTier.SUSPICIOUS, ThreatTier.ALERT]
                        ]),
                        "timestamp": datetime.now().isoformat()
                    }
                    await self.websocket_callback(update)
                    
            except Exception as e:
                logger.error(f"Monitoring loop error: {e}")
                
            await asyncio.sleep(self.scan_interval)
            
        logger.info("APSA Behavioral Monitor stopped")
    
    async def start(self):
        """Start the behavioral monitor"""
        if self.is_running:
            return {"status": "already_running"}
            
        self.is_running = True
        self.monitoring_task = asyncio.create_task(self.monitoring_loop())
        return {"status": "started"}
    
    async def stop(self):
        """Stop the behavioral monitor"""
        self.is_running = False
        if self.monitoring_task:
            self.monitoring_task.cancel()
            try:
                await self.monitoring_task
            except asyncio.CancelledError:
                pass
        return {"status": "stopped"}
    
    def get_status(self) -> Dict[str, Any]:
        """Get current monitor status"""
        return {
            "is_running": self.is_running,
            "process_count": len(self.monitored_processes),
            "alert_count": len(self.engine.alerts),
            "scan_interval": self.scan_interval
        }
    
    def get_processes(self, tier_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get monitored processes, optionally filtered by tier"""
        processes = list(self.monitored_processes.values())
        
        if tier_filter:
            processes = [p for p in processes if p.tier.value == tier_filter.upper()]
            
        # Sort by risk score descending
        processes.sort(key=lambda x: x.risk_score, reverse=True)
        
        return [p.to_dict() for p in processes]
    
    def get_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent alerts"""
        return self.engine.alerts[-limit:]
    
    def get_baseline(self, process_name: str) -> Optional[Dict[str, Any]]:
        """Get baseline for a specific process"""
        key = process_name.lower()
        if key in self.engine.process_baselines:
            return self.engine.process_baselines[key].to_dict()
        return None
    
    async def kill_process(self, pid: int) -> Dict[str, Any]:
        """Kill a suspicious process"""
        try:
            proc = psutil.Process(pid)
            name = proc.name()
            proc.terminate()
            
            # Remove from monitored
            if pid in self.monitored_processes:
                del self.monitored_processes[pid]
                
            return {"status": "killed", "pid": pid, "name": name}
        except psutil.NoSuchProcess:
            return {"status": "error", "message": "Process not found"}
        except psutil.AccessDenied:
            return {"status": "error", "message": "Access denied"}


# Global instance
behavioral_monitor = BehavioralMonitor()
