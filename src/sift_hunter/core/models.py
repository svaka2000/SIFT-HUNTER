"""All Pydantic v2 models for findings, evidence, tool executions, audit entries, and reports."""
from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class ConfidenceLevel(str, Enum):
    """How confident we are in a finding."""
    CONFIRMED = "CONFIRMED"     # 2+ independent evidence sources agree
    PROBABLE = "PROBABLE"       # 1 strong evidence source
    POSSIBLE = "POSSIBLE"       # Circumstantial evidence only
    UNVERIFIED = "UNVERIFIED"   # Single weak source or tool failure


class FindingType(str, Enum):
    """MITRE ATT&CK-aligned categories of forensic findings."""
    PERSISTENCE = "PERSISTENCE"
    EXECUTION = "EXECUTION"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    CREDENTIAL_ACCESS = "CREDENTIAL_ACCESS"
    EXFILTRATION = "EXFILTRATION"
    COMMAND_AND_CONTROL = "COMMAND_AND_CONTROL"
    DEFENSE_EVASION = "DEFENSE_EVASION"
    INITIAL_ACCESS = "INITIAL_ACCESS"
    COLLECTION = "COLLECTION"
    IMPACT = "IMPACT"
    DISCOVERY = "DISCOVERY"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    ANTI_FORENSICS = "ANTI_FORENSICS"
    ANOMALY = "ANOMALY"


class EvidenceType(str, Enum):
    """Types of forensic evidence."""
    DISK_IMAGE = "DISK_IMAGE"
    MEMORY_CAPTURE = "MEMORY_CAPTURE"
    REGISTRY_HIVE = "REGISTRY_HIVE"
    MFT = "MFT"
    PREFETCH = "PREFETCH"
    AMCACHE = "AMCACHE"
    USN_JOURNAL = "USN_JOURNAL"
    EVENT_LOG = "EVENT_LOG"
    SHELLBAGS = "SHELLBAGS"
    TIMELINE = "TIMELINE"
    ARTIFACT_EXPORT = "ARTIFACT_EXPORT"
    UNKNOWN = "UNKNOWN"


class AgentName(str, Enum):
    """Names of agents in the multi-agent system."""
    TRIAGE = "triage"
    DISK_ANALYST = "disk_analyst"
    MEMORY_ANALYST = "memory_analyst"
    CORRELATOR = "correlator"
    VERIFIER = "verifier"
    REPORTER = "reporter"


class AnalysisPhase(str, Enum):
    """Phases of the analysis pipeline."""
    INITIALIZING = "initializing"
    TRIAGE = "triage"
    DISK_ANALYSIS = "disk_analysis"
    MEMORY_ANALYSIS = "memory_analysis"
    CORRELATION = "correlation"
    VERIFICATION = "verification"
    REPORTING = "reporting"
    COMPLETE = "complete"


class MITREMapping(BaseModel):
    """Maps a finding to a MITRE ATT&CK technique."""
    technique_id: str = Field(description="e.g., T1547.001")
    technique_name: str = Field(description="e.g., Registry Run Keys / Startup Folder")
    tactic: str = Field(description="e.g., Persistence")
    evidence_summary: str = Field(default="", description="Why this technique was identified")


class EvidenceItem(BaseModel):
    """A piece of forensic evidence with chain-of-custody tracking."""
    id: str = Field(default_factory=lambda: f"E-{uuid.uuid4().hex[:8]}")
    path: str
    evidence_type: EvidenceType = EvidenceType.UNKNOWN
    hash_sha256: str = Field(default="", description="SHA256 hash computed on first access")
    hash_verified: bool = False
    size_bytes: int = 0
    description: str = ""
    accessed_at: datetime = Field(default_factory=datetime.utcnow)


class ToolExecution(BaseModel):
    """Record of a single forensic tool invocation."""
    id: str = Field(default_factory=lambda: f"T-{uuid.uuid4().hex[:8]}")
    tool_name: str = Field(description="e.g., MFTECmd, vol3.windows.pslist")
    binary: str = Field(default="", description="Actual binary called")
    command_args: list[str] = Field(default_factory=list, description="Arguments passed")
    evidence_id: str = Field(default="", description="Which evidence item was analyzed")
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: datetime = Field(default_factory=datetime.utcnow)
    duration_seconds: float = 0.0
    exit_code: int = 0
    output_hash: str = Field(default="", description="SHA256 of raw stdout")
    output_size_bytes: int = 0
    raw_output: str = Field(default="", description="Raw tool output (truncated to 8KB)")
    output_summary: str = Field(default="", description="First 500 chars of output")
    error_output: str = Field(default="", description="stderr content if any")
    evidence_paths: list[str] = Field(default_factory=list)
    success: bool = True


class Finding(BaseModel):
    """A forensic finding produced by an agent."""
    id: str = Field(default_factory=lambda: f"F-{uuid.uuid4().hex[:8]}")
    finding_type: FindingType = FindingType.ANOMALY
    title: str = Field(description="Brief title")
    description: str = Field(default="", description="Detailed explanation")
    confidence: ConfidenceLevel = ConfidenceLevel.UNVERIFIED
    evidence_refs: list[str] = Field(default_factory=list, description="EvidenceItem IDs")
    tool_refs: list[str] = Field(default_factory=list, description="ToolExecution IDs")
    mitre_mappings: list[MITREMapping] = Field(default_factory=list)
    agent_source: str = Field(default="", description="Which agent produced this")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    raw_evidence_excerpts: list[str] = Field(
        default_factory=list,
        description="Verbatim excerpts from tool output supporting this finding",
    )
    artifact_path: Optional[str] = None
    verified: bool = False
    verification_notes: str = ""
    pid: Optional[int] = None
    process_name: Optional[str] = None


class VerificationCheck(BaseModel):
    """A single verification check performed by the verifier agent."""
    id: str = Field(default_factory=lambda: f"V-{uuid.uuid4().hex[:8]}")
    check_type: str = Field(
        description="cross_reference|hallucination|confidence|consistency|completeness"
    )
    finding_id: str
    description: str = Field(description="What was checked")
    passed: bool
    details: str = Field(default="", description="Explanation of check result")
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class Correction(BaseModel):
    """Instruction to re-examine a finding (self-correction record)."""
    id: str = Field(default_factory=lambda: f"C-{uuid.uuid4().hex[:8]}")
    finding_id: str
    issue_type: str = Field(
        description="contradiction|hallucination|insufficient_evidence|tool_error"
    )
    issue_description: str
    correction_instruction: str = Field(
        description="What the analyst should do differently"
    )
    target_agent: str = Field(description="Which agent should re-examine")
    attempt_number: int = Field(default=1, ge=1, le=3)
    original_confidence: ConfidenceLevel = ConfidenceLevel.UNVERIFIED
    corrected_confidence: Optional[ConfidenceLevel] = None
    resolved: bool = False
    resolution_notes: str = ""
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class AuditEntry(BaseModel):
    """Single entry in the structured audit trail."""
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    agent: str
    action: str = Field(
        description="tool_call|finding_created|verification_check|correction_issued|phase_change|error"
    )
    tool_execution_id: Optional[str] = None
    finding_id: Optional[str] = None
    correction_id: Optional[str] = None
    verification_id: Optional[str] = None
    phase: Optional[str] = None
    iteration: Optional[int] = None
    details: str = Field(default="", description="Human-readable description")
    metadata: dict[str, Any] = Field(default_factory=dict)


class AttackTimelineEvent(BaseModel):
    """A single event in the reconstructed attack timeline."""
    timestamp: datetime
    description: str
    finding_refs: list[str] = Field(default_factory=list)
    mitre_tactic: Optional[str] = None
    confidence: ConfidenceLevel = ConfidenceLevel.POSSIBLE


class ConfidenceSummary(BaseModel):
    """Counts of findings per confidence level."""
    confirmed: int = 0
    probable: int = 0
    possible: int = 0
    unverified: int = 0
    total: int = 0
    hallucinations_caught: int = 0
    corrections_made: int = 0


class IncidentReport(BaseModel):
    """Final structured incident report."""
    id: str = Field(default_factory=lambda: f"RPT-{uuid.uuid4().hex[:8]}")
    title: str
    executive_summary: str
    evidence_items: list[EvidenceItem] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    attack_timeline: list[AttackTimelineEvent] = Field(default_factory=list)
    mitre_mapping: list[MITREMapping] = Field(default_factory=list)
    confidence_summary: ConfidenceSummary = Field(default_factory=ConfidenceSummary)
    corrections: list[Correction] = Field(default_factory=list)
    self_assessment: str = ""
    limitations: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    analyst_notes: str = ""
    analysis_duration_seconds: float = 0.0
    total_tool_calls: int = 0
    generated_at: datetime = Field(default_factory=datetime.utcnow)
