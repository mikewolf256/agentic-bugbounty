#!/usr/bin/env python3
"""
Income Calculator for Agentic Bug Bounty System

Calculates potential income based on:
- 10 containers scanning 2x per day
- Full scan profile with all modules
- Delta checking (only new findings)
- LLM triage with validation

Assumptions based on industry standards and system capabilities.
"""

import json
from typing import Dict, Any
from dataclasses import dataclass
from datetime import datetime, timedelta


@dataclass
class ScanConfig:
    """Configuration for scan operations"""
    containers: int = 10
    scans_per_day: int = 2
    days_per_month: int = 30
    full_scan_profile: bool = True
    delta_checking: bool = True
    llm_triage: bool = True


@dataclass
class FindingMetrics:
    """Metrics for findings and acceptance rates"""
    # Findings per scan (varies by target size and scan depth)
    findings_per_scan_min: float = 5.0
    findings_per_scan_avg: float = 15.0
    findings_per_scan_max: float = 50.0
    
    # Pre-filtering (before LLM triage)
    # System filters noise, deduplicates, and pre-filters by CVSS
    pre_filter_retention_rate: float = 0.15  # 15% pass pre-filter (85% noise removed)
    
    # LLM triage confidence filtering
    # Only medium/high confidence findings proceed
    llm_high_confidence_rate: float = 0.40  # 40% of pre-filtered are high confidence
    
    # Validation success rate (Dalfox, SQLmap, BAC, SSRF validators)
    validation_success_rate: float = 0.60  # 60% of high-confidence findings validate
    
    # Bug bounty acceptance rate (industry standard: 20-40% for well-tested findings)
    acceptance_rate: float = 0.30  # 30% of validated findings accepted
    
    # False positive rate (after all filtering)
    false_positive_rate: float = 0.10  # 10% false positives in final submissions


@dataclass
class BountyMetrics:
    """Bounty ranges and averages"""
    # Based on HackerOne data and scope files
    low_severity_avg: float = 200.0
    medium_severity_avg: float = 500.0
    high_severity_avg: float = 2000.0
    critical_severity_avg: float = 5000.0
    
    # Distribution of accepted findings by severity
    low_pct: float = 0.20   # 20% low
    medium_pct: float = 0.40  # 40% medium
    high_pct: float = 0.30   # 30% high
    critical_pct: float = 0.10  # 10% critical


@dataclass
class CostMetrics:
    """Costs for running the system"""
    # LLM costs (OpenAI GPT-4o-mini)
    llm_cost_per_finding: float = 0.002  # $0.002 per finding triage (~500 tokens)
    
    # Infrastructure costs (per container per day)
    container_cost_per_day: float = 0.50  # $0.50/day per container (cloud compute)
    
    # Storage and other overhead
    storage_cost_per_month: float = 10.0  # $10/month for artifact storage


class IncomeCalculator:
    """Calculate potential income from bug bounty scanning"""
    
    def __init__(
        self,
        scan_config: ScanConfig,
        finding_metrics: FindingMetrics,
        bounty_metrics: BountyMetrics,
        cost_metrics: CostMetrics
    ):
        self.scan_config = scan_config
        self.finding_metrics = finding_metrics
        self.bounty_metrics = bounty_metrics
        self.cost_metrics = cost_metrics
    
    def calculate_daily_operations(self) -> Dict[str, Any]:
        """Calculate daily scan operations"""
        total_scans_per_day = self.scan_config.containers * self.scan_config.scans_per_day
        
        # Average findings per scan
        avg_findings_per_scan = self.finding_metrics.findings_per_scan_avg
        
        # Total raw findings per day
        raw_findings_per_day = total_scans_per_day * avg_findings_per_scan
        
        # Pre-filtering (noise removal, deduplication, CVSS gating)
        pre_filtered_per_day = raw_findings_per_day * self.finding_metrics.pre_filter_retention_rate
        
        # LLM triage (only medium/high confidence)
        high_confidence_per_day = pre_filtered_per_day * self.finding_metrics.llm_high_confidence_rate
        
        # Validation (Dalfox, SQLmap, BAC, SSRF)
        validated_per_day = high_confidence_per_day * self.finding_metrics.validation_success_rate
        
        # Accepted by bug bounty programs
        accepted_per_day = validated_per_day * self.finding_metrics.acceptance_rate
        
        return {
            "total_scans_per_day": total_scans_per_day,
            "raw_findings_per_day": raw_findings_per_day,
            "pre_filtered_per_day": pre_filtered_per_day,
            "high_confidence_per_day": high_confidence_per_day,
            "validated_per_day": validated_per_day,
            "accepted_per_day": accepted_per_day,
        }
    
    def calculate_bounty_income(self, accepted_count: float) -> Dict[str, Any]:
        """Calculate bounty income based on accepted findings"""
        # Distribute by severity
        low_count = accepted_count * self.bounty_metrics.low_pct
        medium_count = accepted_count * self.bounty_metrics.medium_pct
        high_count = accepted_count * self.bounty_metrics.high_pct
        critical_count = accepted_count * self.bounty_metrics.critical_pct
        
        # Calculate income by severity
        low_income = low_count * self.bounty_metrics.low_severity_avg
        medium_income = medium_count * self.bounty_metrics.medium_severity_avg
        high_income = high_count * self.bounty_metrics.high_severity_avg
        critical_income = critical_count * self.bounty_metrics.critical_severity_avg
        
        total_income = low_income + medium_income + high_income + critical_income
        
        return {
            "low_severity": {
                "count": low_count,
                "income": low_income,
            },
            "medium_severity": {
                "count": medium_count,
                "income": medium_income,
            },
            "high_severity": {
                "count": high_count,
                "income": high_income,
            },
            "critical_severity": {
                "count": critical_count,
                "income": critical_income,
            },
            "total_income": total_income,
        }
    
    def calculate_costs(self, pre_filtered_count: float) -> Dict[str, Any]:
        """Calculate operational costs"""
        # LLM costs (only for pre-filtered findings that pass to LLM)
        llm_cost = pre_filtered_count * self.cost_metrics.llm_cost_per_finding
        
        # Infrastructure costs
        container_cost = (
            self.scan_config.containers *
            self.cost_metrics.container_cost_per_day
        )
        
        # Storage costs (monthly, prorated daily)
        storage_cost_daily = self.cost_metrics.storage_cost_per_month / self.scan_config.days_per_month
        
        total_cost = llm_cost + container_cost + storage_cost_daily
        
        return {
            "llm_cost": llm_cost,
            "container_cost": container_cost,
            "storage_cost": storage_cost_daily,
            "total_cost": total_cost,
        }
    
    def calculate_delta_efficiency(self) -> Dict[str, Any]:
        """Calculate efficiency gains from delta checking"""
        # Delta checking reduces redundant findings by focusing on new endpoints/changes
        # Assumes 30% of findings are new/changed vs baseline
        delta_efficiency = 0.30  # Only 30% of findings are new
        
        # This means we can scan more targets or reduce costs
        # For income calculation, this means higher quality findings
        # (new endpoints are more likely to have vulnerabilities)
        
        return {
            "delta_efficiency": delta_efficiency,
            "new_findings_rate": delta_efficiency,
            "note": "Delta checking focuses on new endpoints/changes, improving signal-to-noise ratio",
        }
    
    def calculate_monthly_summary(self) -> Dict[str, Any]:
        """Calculate monthly income and costs"""
        daily_ops = self.calculate_daily_operations()
        delta_info = self.calculate_delta_efficiency()
        
        # Apply delta efficiency (focus on new findings)
        # Delta checking improves quality, not necessarily quantity
        # We'll assume it improves acceptance rate by 10% (better targeting)
        delta_acceptance_boost = 1.10
        
        # Daily accepted with delta boost
        daily_accepted = daily_ops["accepted_per_day"] * delta_acceptance_boost
        
        # Monthly totals
        monthly_accepted = daily_accepted * self.scan_config.days_per_month
        monthly_pre_filtered = daily_ops["pre_filtered_per_day"] * self.scan_config.days_per_month
        
        # Income
        monthly_income = self.calculate_bounty_income(monthly_accepted)
        
        # Costs
        daily_costs = self.calculate_costs(daily_ops["pre_filtered_per_day"])
        monthly_costs = {
            "llm_cost": daily_costs["llm_cost"] * self.scan_config.days_per_month,
            "container_cost": daily_costs["container_cost"] * self.scan_config.days_per_month,
            "storage_cost": self.cost_metrics.storage_cost_per_month,
            "total_cost": (
                daily_costs["llm_cost"] * self.scan_config.days_per_month +
                daily_costs["container_cost"] * self.scan_config.days_per_month +
                self.cost_metrics.storage_cost_per_month
            ),
        }
        
        # Net income
        net_income = monthly_income["total_income"] - monthly_costs["total_cost"]
        
        return {
            "monthly_operations": {
                "total_scans": daily_ops["total_scans_per_day"] * self.scan_config.days_per_month,
                "raw_findings": daily_ops["raw_findings_per_day"] * self.scan_config.days_per_month,
                "pre_filtered_findings": monthly_pre_filtered,
                "high_confidence_findings": daily_ops["high_confidence_per_day"] * self.scan_config.days_per_month,
                "validated_findings": daily_ops["validated_per_day"] * self.scan_config.days_per_month,
                "accepted_findings": monthly_accepted,
            },
            "delta_efficiency": delta_info,
            "monthly_income": monthly_income,
            "monthly_costs": monthly_costs,
            "net_income": net_income,
            "roi_percentage": (net_income / monthly_costs["total_cost"] * 100) if monthly_costs["total_cost"] > 0 else 0,
        }
    
    def generate_report(self) -> str:
        """Generate a formatted report"""
        monthly = self.calculate_monthly_summary()
        
        report = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║         AGENTIC BUG BOUNTY INCOME CALCULATOR - MONTHLY PROJECTION           ║
╚══════════════════════════════════════════════════════════════════════════════╝

📊 SCAN CONFIGURATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Containers:              {self.scan_config.containers}
  Scans per day:           {self.scan_config.scans_per_day}
  Total scans/day:         {monthly['monthly_operations']['total_scans'] / self.scan_config.days_per_month:.1f}
  Full scan profile:       {'Yes' if self.scan_config.full_scan_profile else 'No'}
  Delta checking:          {'Yes' if self.scan_config.delta_checking else 'No'}
  LLM triage:              {'Yes' if self.scan_config.llm_triage else 'No'}

📈 MONTHLY OPERATIONS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Total scans:             {monthly['monthly_operations']['total_scans']:,.0f}
  Raw findings:            {monthly['monthly_operations']['raw_findings']:,.0f}
  After pre-filtering:    {monthly['monthly_operations']['pre_filtered_findings']:,.0f}
  High confidence:        {monthly['monthly_operations']['high_confidence_findings']:,.0f}
  Validated findings:     {monthly['monthly_operations']['validated_findings']:,.0f}
  Accepted findings:      {monthly['monthly_operations']['accepted_findings']:,.1f}

💰 BOUNTY INCOME BREAKDOWN
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Low severity:           {monthly['monthly_income']['low_severity']['count']:.1f} findings × ${self.bounty_metrics.low_severity_avg:,.0f} = ${monthly['monthly_income']['low_severity']['income']:,.2f}
  Medium severity:        {monthly['monthly_income']['medium_severity']['count']:.1f} findings × ${self.bounty_metrics.medium_severity_avg:,.0f} = ${monthly['monthly_income']['medium_severity']['income']:,.2f}
  High severity:          {monthly['monthly_income']['high_severity']['count']:.1f} findings × ${self.bounty_metrics.high_severity_avg:,.0f} = ${monthly['monthly_income']['high_severity']['income']:,.2f}
  Critical severity:      {monthly['monthly_income']['critical_severity']['count']:.1f} findings × ${self.bounty_metrics.critical_severity_avg:,.0f} = ${monthly['monthly_income']['critical_severity']['income']:,.2f}
  ─────────────────────────────────────────────────────────────────────────────
  TOTAL GROSS INCOME:     ${monthly['monthly_income']['total_income']:,.2f}

💸 OPERATIONAL COSTS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  LLM triage costs:       ${monthly['monthly_costs']['llm_cost']:,.2f}
  Container infrastructure: ${monthly['monthly_costs']['container_cost']:,.2f}
  Storage & overhead:     ${monthly['monthly_costs']['storage_cost']:,.2f}
  ─────────────────────────────────────────────────────────────────────────────
  TOTAL COSTS:            ${monthly['monthly_costs']['total_cost']:,.2f}

💵 NET INCOME & ROI
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  NET MONTHLY INCOME:     ${monthly['net_income']:,.2f}
  ROI:                    {monthly['roi_percentage']:.1f}%

📊 KEY METRICS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Acceptance rate:       {self.finding_metrics.acceptance_rate * 100:.1f}%
  Avg bounty per finding: ${monthly['monthly_income']['total_income'] / monthly['monthly_operations']['accepted_findings']:,.2f}
  Cost per finding:      ${monthly['monthly_costs']['total_cost'] / monthly['monthly_operations']['accepted_findings']:,.2f}
  Profit margin:         {(monthly['net_income'] / monthly['monthly_income']['total_income'] * 100) if monthly['monthly_income']['total_income'] > 0 else 0:.1f}%

📝 ASSUMPTIONS & NOTES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  • Pre-filtering removes 85% of noise before LLM triage
  • Delta checking improves acceptance rate by 10% (better targeting)
  • Full scan profile includes: ZAP, Nuclei, Katana, Dalfox, SQLmap, BAC, SSRF
  • LLM triage uses GPT-4o-mini for cost efficiency
  • Validation engines (Dalfox, SQLmap, etc.) confirm 60% of high-confidence findings
  • Industry-standard acceptance rate: 30% of validated findings
  • Bounty ranges based on HackerOne program data

⚠️  VARIABLES THAT AFFECT INCOME
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  • Target quality (more targets = more findings)
  • Scan depth (full profile vs. recon-only)
  • Program bounty ranges (varies by program)
  • Acceptance rate (depends on report quality)
  • Time to payout (typically 30-90 days after acceptance)
"""
        return report


def main():
    """Main entry point"""
    import sys
    
    scenario = sys.argv[1] if len(sys.argv) > 1 else "optimistic"
    
    # Default configuration
    scan_config = ScanConfig(
        containers=10,
        scans_per_day=2,
        days_per_month=30,
        full_scan_profile=True,
        delta_checking=True,
        llm_triage=True,
    )
    
    if scenario == "conservative":
        # Conservative scenario - lower acceptance rates, fewer findings
        finding_metrics = FindingMetrics(
            findings_per_scan_avg=10.0,  # Fewer findings per scan
            pre_filter_retention_rate=0.10,  # 10% pass pre-filter (more aggressive)
            llm_high_confidence_rate=0.30,   # 30% are high confidence
            validation_success_rate=0.50,     # 50% validate successfully
            acceptance_rate=0.20,             # 20% accepted (more conservative)
        )
        
        # Lower bounty averages
        bounty_metrics = BountyMetrics(
            low_severity_avg=150.0,
            medium_severity_avg=400.0,
            high_severity_avg=1500.0,
            critical_severity_avg=4000.0,
        )
    elif scenario == "realistic":
        # Realistic scenario - balanced assumptions
        finding_metrics = FindingMetrics(
            findings_per_scan_avg=12.0,
            pre_filter_retention_rate=0.12,  # 12% pass pre-filter
            llm_high_confidence_rate=0.35,   # 35% are high confidence
            validation_success_rate=0.55,     # 55% validate successfully
            acceptance_rate=0.25,             # 25% accepted
        )
        
        bounty_metrics = BountyMetrics(
            low_severity_avg=175.0,
            medium_severity_avg=450.0,
            high_severity_avg=1750.0,
            critical_severity_avg=4500.0,
        )
    else:  # optimistic
        # Finding metrics (based on system capabilities)
        finding_metrics = FindingMetrics(
            findings_per_scan_avg=15.0,
            pre_filter_retention_rate=0.15,  # 15% pass pre-filter
            llm_high_confidence_rate=0.40,   # 40% are high confidence
            validation_success_rate=0.60,     # 60% validate successfully
            acceptance_rate=0.30,             # 30% accepted
        )
        
        # Bounty metrics (based on HackerOne data)
        bounty_metrics = BountyMetrics(
            low_severity_avg=200.0,
            medium_severity_avg=500.0,
            high_severity_avg=2000.0,
            critical_severity_avg=5000.0,
        )
    
    # Cost metrics
    cost_metrics = CostMetrics(
        llm_cost_per_finding=0.002,
        container_cost_per_day=0.50,
        storage_cost_per_month=10.0,
    )
    
    # Create calculator
    calculator = IncomeCalculator(
        scan_config=scan_config,
        finding_metrics=finding_metrics,
        bounty_metrics=bounty_metrics,
        cost_metrics=cost_metrics,
    )
    
    # Generate and print report
    report = calculator.generate_report()
    print(report)
    
    # Also save to JSON for programmatic access
    monthly_summary = calculator.calculate_monthly_summary()
    output_file = f"income_projection_{scenario}.json"
    with open(output_file, "w") as f:
        json.dump(monthly_summary, f, indent=2)
    print(f"\n📄 Detailed data saved to: {output_file}")


if __name__ == "__main__":
    main()

