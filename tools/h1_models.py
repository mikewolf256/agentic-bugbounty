#!/usr/bin/env python3
"""
HackerOne Program Models

Data structures for representing HackerOne bug bounty program information,
scope definitions, and rules.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum
import json


class AssetType(str, Enum):
    """HackerOne asset types"""
    URL = "URL"
    CIDR = "CIDR"
    WILDCARD = "WILDCARD"
    API = "API"
    MOBILE_APPLICATION = "MOBILE_APPLICATION"
    SOURCE_CODE = "SOURCE_CODE"
    HARDWARE = "HARDWARE"
    OTHER = "OTHER"
    EXECUTABLE = "EXECUTABLE"
    DOWNLOADABLE_EXECUTABLES = "DOWNLOADABLE_EXECUTABLES"
    IOS = "IOS"
    ANDROID = "ANDROID"
    SMART_CONTRACT = "SMART_CONTRACT"
    TESTNET_SMART_CONTRACT = "TESTNET_SMART_CONTRACT"


class SeverityRating(str, Enum):
    """CVSS severity ratings"""
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class BountyRange:
    """Represents a bounty payout range for a severity level"""
    severity: SeverityRating
    min_amount: float
    max_amount: float
    currency: str = "USD"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "severity": self.severity.value,
            "min": self.min_amount,
            "max": self.max_amount,
            "currency": self.currency,
        }


@dataclass
class ScopeAsset:
    """Represents an in-scope or out-of-scope asset"""
    identifier: str  # The actual target (URL, IP range, app name, etc.)
    asset_type: AssetType
    eligible_for_bounty: bool = True
    eligible_for_submission: bool = True
    instruction: Optional[str] = None  # Special instructions for this asset
    max_severity: Optional[SeverityRating] = None
    confidentiality_requirement: Optional[str] = None
    integrity_requirement: Optional[str] = None
    availability_requirement: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        result = {
            "identifier": self.identifier,
            "asset_type": self.asset_type.value,
            "eligible_for_bounty": self.eligible_for_bounty,
            "eligible_for_submission": self.eligible_for_submission,
        }
        if self.instruction:
            result["instruction"] = self.instruction
        if self.max_severity:
            result["max_severity"] = self.max_severity.value
        if self.confidentiality_requirement:
            result["confidentiality_requirement"] = self.confidentiality_requirement
        if self.integrity_requirement:
            result["integrity_requirement"] = self.integrity_requirement
        if self.availability_requirement:
            result["availability_requirement"] = self.availability_requirement
        return result
    
    def to_target_url(self) -> Optional[str]:
        """Convert asset to a target URL if applicable"""
        if self.asset_type in (AssetType.URL, AssetType.API, AssetType.WILDCARD):
            identifier = self.identifier
            # Ensure URL has scheme
            if not identifier.startswith(("http://", "https://")):
                # Wildcard domains
                if identifier.startswith("*."):
                    return f"https://{identifier[2:]}"  # Remove wildcard for base
                return f"https://{identifier}"
            return identifier
        return None


@dataclass
class ProgramPolicy:
    """Program rules and policies"""
    # Disclosure policies
    disclosure_type: str = "coordinated"  # coordinated, full, none
    disclosure_timeline_days: int = 90
    
    # Testing rules
    safe_harbor: bool = True
    allow_automated_testing: bool = True
    testing_rate_limit: Optional[str] = None  # e.g., "100 requests per second"
    
    # Report requirements
    requires_poc: bool = True
    requires_impact_statement: bool = True
    
    # Exclusions
    excluded_vuln_types: List[str] = field(default_factory=list)
    
    # Custom rules from the program
    custom_rules: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "disclosure_type": self.disclosure_type,
            "disclosure_timeline_days": self.disclosure_timeline_days,
            "safe_harbor": self.safe_harbor,
            "allow_automated_testing": self.allow_automated_testing,
            "testing_rate_limit": self.testing_rate_limit,
            "requires_poc": self.requires_poc,
            "requires_impact_statement": self.requires_impact_statement,
            "excluded_vuln_types": self.excluded_vuln_types,
            "custom_rules": self.custom_rules,
        }


@dataclass
class H1Program:
    """Complete HackerOne bug bounty program representation"""
    # Basic info
    handle: str  # The program handle/slug (e.g., "23andme_bbp")
    name: str
    url: str  # HackerOne program URL
    
    # Program status
    offers_bounties: bool = True
    offers_swag: bool = False
    managed: bool = False  # Is it a managed program (H1 triage)?
    state: str = "open"  # open, paused, soft_launched
    
    # Scope
    in_scope_assets: List[ScopeAsset] = field(default_factory=list)
    out_of_scope_assets: List[ScopeAsset] = field(default_factory=list)
    
    # Bounty info
    bounty_ranges: List[BountyRange] = field(default_factory=list)
    average_bounty: Optional[float] = None
    top_bounty: Optional[float] = None
    
    # Policy
    policy: ProgramPolicy = field(default_factory=ProgramPolicy)
    
    # Response times
    avg_first_response_time: Optional[int] = None  # in seconds
    avg_bounty_time: Optional[int] = None  # in seconds
    avg_resolution_time: Optional[int] = None  # in seconds
    
    # Metadata
    launched_at: Optional[str] = None
    last_updated: Optional[str] = None
    
    # Raw data for debugging
    raw_data: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "handle": self.handle,
            "name": self.name,
            "url": self.url,
            "offers_bounties": self.offers_bounties,
            "offers_swag": self.offers_swag,
            "managed": self.managed,
            "state": self.state,
            "in_scope_assets": [a.to_dict() for a in self.in_scope_assets],
            "out_of_scope_assets": [a.to_dict() for a in self.out_of_scope_assets],
            "bounty_ranges": [b.to_dict() for b in self.bounty_ranges],
            "average_bounty": self.average_bounty,
            "top_bounty": self.top_bounty,
            "policy": self.policy.to_dict(),
            "avg_first_response_time": self.avg_first_response_time,
            "avg_bounty_time": self.avg_bounty_time,
            "avg_resolution_time": self.avg_resolution_time,
            "launched_at": self.launched_at,
            "last_updated": self.last_updated,
        }
    
    def to_scope_json(self, include_out_of_scope: bool = False) -> Dict[str, Any]:
        """
        Convert to scope.json format compatible with the agentic runner.
        
        This generates the structure expected by scope_runner.py and agentic_runner.py.
        """
        # Extract primary targets (in-scope web assets)
        primary_targets = []
        secondary_targets = []
        
        for asset in self.in_scope_assets:
            target_url = asset.to_target_url()
            if target_url:
                if asset.eligible_for_bounty:
                    primary_targets.append(target_url)
                else:
                    secondary_targets.append(target_url)
        
        # Build rules from policy
        rules: Dict[str, Any] = {
            "rate_limit": self.policy.testing_rate_limit,
            "safe_harbor": self.policy.safe_harbor,
            "allow_automated": self.policy.allow_automated_testing,
            "excluded_vuln_types": self.policy.excluded_vuln_types,
            "requires_poc": self.policy.requires_poc,
        }
        
        # Build the scope structure
        scope = {
            "program_name": self.name,
            "program_handle": self.handle,
            "program_url": self.url,
            "primary_targets": primary_targets,
            "secondary_targets": secondary_targets,
            "rules": rules,
        }
        
        # Add detailed scope info
        scope["in_scope"] = [
            {
                "url": a.to_target_url() or a.identifier,
                "target": a.identifier,
                "type": a.asset_type.value,
                "bounty_eligible": a.eligible_for_bounty,
                "instruction": a.instruction,
            }
            for a in self.in_scope_assets
        ]
        
        if include_out_of_scope:
            scope["out_of_scope"] = [
                {
                    "target": a.identifier,
                    "type": a.asset_type.value,
                    "instruction": a.instruction,
                }
                for a in self.out_of_scope_assets
            ]
        
        # Add bounty information
        if self.bounty_ranges:
            scope["bounties"] = {
                b.severity.value: {"min": b.min_amount, "max": b.max_amount}
                for b in self.bounty_ranges
            }
        
        return scope
    
    def to_json(self, indent: int = 2) -> str:
        """Serialize to JSON string"""
        return json.dumps(self.to_dict(), indent=indent)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "H1Program":
        """Create from dictionary"""
        # Parse assets
        in_scope = [
            ScopeAsset(
                identifier=a["identifier"],
                asset_type=AssetType(a.get("asset_type", "OTHER")),
                eligible_for_bounty=a.get("eligible_for_bounty", True),
                eligible_for_submission=a.get("eligible_for_submission", True),
                instruction=a.get("instruction"),
                max_severity=SeverityRating(a["max_severity"]) if a.get("max_severity") else None,
            )
            for a in data.get("in_scope_assets", [])
        ]
        
        out_of_scope = [
            ScopeAsset(
                identifier=a["identifier"],
                asset_type=AssetType(a.get("asset_type", "OTHER")),
                eligible_for_bounty=False,
                eligible_for_submission=False,
                instruction=a.get("instruction"),
            )
            for a in data.get("out_of_scope_assets", [])
        ]
        
        # Parse bounty ranges
        bounties = [
            BountyRange(
                severity=SeverityRating(b["severity"]),
                min_amount=b.get("min", 0),
                max_amount=b.get("max", 0),
                currency=b.get("currency", "USD"),
            )
            for b in data.get("bounty_ranges", [])
        ]
        
        # Parse policy
        policy_data = data.get("policy", {})
        policy = ProgramPolicy(
            disclosure_type=policy_data.get("disclosure_type", "coordinated"),
            disclosure_timeline_days=policy_data.get("disclosure_timeline_days", 90),
            safe_harbor=policy_data.get("safe_harbor", True),
            allow_automated_testing=policy_data.get("allow_automated_testing", True),
            testing_rate_limit=policy_data.get("testing_rate_limit"),
            requires_poc=policy_data.get("requires_poc", True),
            requires_impact_statement=policy_data.get("requires_impact_statement", True),
            excluded_vuln_types=policy_data.get("excluded_vuln_types", []),
            custom_rules=policy_data.get("custom_rules", []),
        )
        
        return cls(
            handle=data["handle"],
            name=data["name"],
            url=data.get("url", f"https://hackerone.com/{data['handle']}"),
            offers_bounties=data.get("offers_bounties", True),
            offers_swag=data.get("offers_swag", False),
            managed=data.get("managed", False),
            state=data.get("state", "open"),
            in_scope_assets=in_scope,
            out_of_scope_assets=out_of_scope,
            bounty_ranges=bounties,
            average_bounty=data.get("average_bounty"),
            top_bounty=data.get("top_bounty"),
            policy=policy,
            avg_first_response_time=data.get("avg_first_response_time"),
            avg_bounty_time=data.get("avg_bounty_time"),
            avg_resolution_time=data.get("avg_resolution_time"),
            launched_at=data.get("launched_at"),
            last_updated=data.get("last_updated"),
            raw_data=data.get("raw_data"),
        )

