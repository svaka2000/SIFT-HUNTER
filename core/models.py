"""
Core Pydantic models for SIFT-HUNTER.
All structured data flows through these types — no raw strings passed between agents.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class ConfidenceLevel(str, Enum):
    CONFIRMED = "CONFIRMED"    # 2+ independent evidence sources
    PROBABLE = "PROBABLE"      # 1 strong evidence source
    POSSIBLE = "POSSIBLE"      # Circumstantial evidence
    UNVERIFIED = "UNVERIFIED"  # Single weak source or tool failure


class EvidenceType(str, Enum):
    DISK_IMAGE = "DISK_IMAGE"
    MEMORY_CAPTURE = "MEMORY_CAPTURE"
    LOG_FILE = "LOG_FILE"
    REGISTRY_HIVE = "REGISTRY_HIVE"
    PREFETCH = "PREFETCH"
    MFT = "MFT"
    AMCACHE = "AMCACHE"
    USN_JOURNAL = "USN_JOURNAL"
    SHELLBAGS = "SHELLBAGS"
    UNKNOWN = "UNKNOWN"


class FindingType(str, Enum):
    PERSISTENCE = "PERSISTENCE"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    CREDENTIAL_ACCESS = "CREDENTIAL_ACCESS"
    DEFENSE_EVASION = "DEFENSE_EVASION"
    EXECUTION = "EXECUTION"
    EXFILTRATION = "EXFILTRATION"
    COMMAND_AND_CONTROL = "COMMAND_AND_CONTROL"
    INITIAL_ACCESS = "INITIAL_ACCESS"
    DISCOVERY = "DISCOVERY"
    COLLECTION = "COLLECTION"
    IMPACT = "IMPACT"
    ANOMALY = "ANOMALY"


class MITREMapping(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    sub_technique_id: Optional[str] = None
    confidence: ConfidenceLevel = ConfidenceLevel.POSSIBLE
    evidence_ref: Optional[str] = None


class Evidence(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    path: str
    hash_sha256: Optional[str] = None
    hash_verified: bool = False
    evidence_type: EvidenceType = EvidenceType.UNKNOWN
    size_bytes: Optional[int] = None
    acquired_at: datetime = Field(default_factory=datetime.utcnow)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ToolExecution(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tool_name: str
    command: str
    args: dict[str, Any] = Field(default_factory=dict)
    raw_output: str = ""
    output_hash: Optional[str] = None
    exit_code: int = 0
    error_message: Optional[str] = None
    started_at: datetime = Field(default_factory=datetime.utcnow)
    duration_ms: float = 0.0
    evidence_paths: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    finding_type: FindingType
    title: str
    description: str
    confidence: ConfidenceLevel
    evidence_refs: list[str] = Field(default_factory=list)     # Evidence IDs
    tool_execution_refs: list[str] = Field(default_factory=list)  # ToolExecution IDs
    mitre_ttps: list[MITREMapping] = Field(default_factory=list)
    artifact_path: Optional[str] = None
    artifact_hash: Optional[str] = None
    timestamps: list[datetime] = Field(default_factory=list)
    raw_evidence_excerpt: str = ""  # Direct quote from tool output supporting this finding
    agent_source: str = ""          # Which agent produced this finding
    verified: bool = False
    verification_notes: str = ""
    created_at: datetime = Field(default_factory=datetime.utcnow)
    tags: list[str] = Field(default_factory=list)


class Correction(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    finding_id: str
    issue_description: str
    action: str  # RE_EXAMINE, DOWNGRADE_CONFIDENCE, REMOVE, FLAG_HALLUCINATION
    original_confidence: ConfidenceLevel
    corrected_confidence: Optional[ConfidenceLevel] = None
    corrected_by: str = "verifier"
    correction_reasoning: str = ""
    created_at: datetime = Field(default_factory=datetime.utcnow)


class AgentAction(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_name: str
    action: str
    reasoning: str
    tool_executions: list[str] = Field(default_factory=list)  # ToolExecution IDs
    findings_produced: list[str] = Field(default_factory=list)  # Finding IDs
    corrections_applied: list[str] = Field(default_factory=list)  # Correction IDs
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    iteration: int = 0


class AuditEntry(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    agent: str
    action: str
    tool_execution_id: Optional[str] = None
    tool_name: Optional[str] = None
    command: Optional[str] = None
    output_hash: Optional[str] = None
    finding_id: Optional[str] = None
    correction_id: Optional[str] = None
    reasoning: str = ""
    phase: str = ""
    iteration: int = 0
    metadata: dict[str, Any] = Field(default_factory=dict)


class AttackTimelineEvent(BaseModel):
    timestamp: datetime
    description: str
    finding_refs: list[str] = Field(default_factory=list)
    mitre_tactic: Optional[str] = None
    confidence: ConfidenceLevel = ConfidenceLevel.POSSIBLE


class ConfidenceSummary(BaseModel):
    confirmed: int = 0
    probable: int = 0
    possible: int = 0
    unverified: int = 0
    total: int = 0
    hallucinations_caught: int = 0
    corrections_made: int = 0


class IncidentReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    executive_summary: str
    findings: list[Finding] = Field(default_factory=list)
    attack_timeline: list[AttackTimelineEvent] = Field(default_factory=list)
    mitre_mapping: list[MITREMapping] = Field(default_factory=list)
    confidence_summary: ConfidenceSummary = Field(default_factory=ConfidenceSummary)
    evidence_items: list[Evidence] = Field(default_factory=list)
    tool_executions: list[ToolExecution] = Field(default_factory=list)
    corrections_applied: list[Correction] = Field(default_factory=list)
    self_assessment: str = ""
    recommendations: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    analyst_notes: str = ""
