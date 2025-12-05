#!/usr/bin/env python3
"""Token Usage Tracker and Cost Estimation

Tracks LLM token usage per scan and estimates costs.
Supports OpenAI and Anthropic models with per-model pricing.
"""

import os
import json
import time
from typing import Dict, Any, Optional, List
from datetime import datetime
from pathlib import Path


# Model pricing (per 1M tokens) - updated as of 2024
MODEL_PRICING = {
    # OpenAI models
    "gpt-4o": {"input": 2.50, "output": 10.00},  # $2.50/$10 per 1M tokens
    "gpt-4o-mini": {"input": 0.15, "output": 0.60},  # $0.15/$0.60 per 1M tokens
    "gpt-4": {"input": 30.00, "output": 60.00},
    "gpt-3.5-turbo": {"input": 0.50, "output": 1.50},
    
    # Anthropic models
    "claude-3-5-sonnet-20241022": {"input": 3.00, "output": 15.00},
    "claude-3-opus-20240229": {"input": 15.00, "output": 75.00},
    "claude-3-sonnet-20240229": {"input": 3.00, "output": 15.00},
    "claude-3-haiku-20240307": {"input": 0.25, "output": 1.25},
}


class TokenTracker:
    """Tracks token usage and estimates costs."""
    
    def __init__(self, output_dir: str = "output_zap"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.current_scan: Dict[str, Any] = {
            "scan_id": None,
            "start_time": None,
            "calls": [],
            "total_tokens_in": 0,
            "total_tokens_out": 0,
            "total_cost": 0.0,
            "model_breakdown": {},
        }
    
    def start_scan(self, scan_id: Optional[str] = None):
        """Start tracking a new scan.
        
        Args:
            scan_id: Optional scan identifier
        """
        if scan_id is None:
            scan_id = f"scan_{int(time.time())}"
        
        self.current_scan = {
            "scan_id": scan_id,
            "start_time": datetime.now().isoformat(),
            "calls": [],
            "total_tokens_in": 0,
            "total_tokens_out": 0,
            "total_cost": 0.0,
            "model_breakdown": {},
        }
    
    def track_call(
        self,
        model: str,
        tokens_in: int,
        tokens_out: int,
        context: Optional[str] = None,
    ):
        """Track a single LLM API call.
        
        Args:
            model: Model name
            tokens_in: Input tokens
            tokens_out: Output tokens
            context: Optional context (e.g., "triage", "rag_search")
        """
        # Get pricing
        pricing = MODEL_PRICING.get(model, {"input": 0.0, "output": 0.0})
        
        # Calculate cost
        cost = (tokens_in / 1_000_000) * pricing["input"] + (tokens_out / 1_000_000) * pricing["output"]
        
        # Record call
        call_record = {
            "timestamp": datetime.now().isoformat(),
            "model": model,
            "tokens_in": tokens_in,
            "tokens_out": tokens_out,
            "cost": cost,
            "context": context,
        }
        
        self.current_scan["calls"].append(call_record)
        self.current_scan["total_tokens_in"] += tokens_in
        self.current_scan["total_tokens_out"] += tokens_out
        self.current_scan["total_cost"] += cost
        
        # Update model breakdown
        if model not in self.current_scan["model_breakdown"]:
            self.current_scan["model_breakdown"][model] = {
                "calls": 0,
                "tokens_in": 0,
                "tokens_out": 0,
                "cost": 0.0,
            }
        
        breakdown = self.current_scan["model_breakdown"][model]
        breakdown["calls"] += 1
        breakdown["tokens_in"] += tokens_in
        breakdown["tokens_out"] += tokens_out
        breakdown["cost"] += cost
    
    def end_scan(self) -> Dict[str, Any]:
        """End tracking and return summary.
        
        Returns:
            Scan summary dict
        """
        self.current_scan["end_time"] = datetime.now().isoformat()
        
        # Calculate duration
        if self.current_scan.get("start_time"):
            start = datetime.fromisoformat(self.current_scan["start_time"])
            end = datetime.fromisoformat(self.current_scan["end_time"])
            duration = (end - start).total_seconds()
            self.current_scan["duration_seconds"] = duration
        
        # Save to file
        self.save_scan()
        
        return self.current_scan.copy()
    
    def save_scan(self):
        """Save current scan data to file."""
        if not self.current_scan.get("scan_id"):
            return
        
        timestamp = int(time.time())
        filename = f"token_usage_{timestamp}.json"
        filepath = self.output_dir / filename
        
        with open(filepath, "w") as f:
            json.dump(self.current_scan, f, indent=2)
        
        print(f"[TOKEN-TRACKER] Saved token usage to {filepath}")
        print(f"[TOKEN-TRACKER] Total cost: ${self.current_scan['total_cost']:.4f}")
        print(f"[TOKEN-TRACKER] Tokens: {self.current_scan['total_tokens_in']:,} in, {self.current_scan['total_tokens_out']:,} out")
    
    def get_summary(self) -> Dict[str, Any]:
        """Get current scan summary without ending it.
        
        Returns:
            Summary dict
        """
        return {
            "scan_id": self.current_scan.get("scan_id"),
            "total_tokens_in": self.current_scan.get("total_tokens_in", 0),
            "total_tokens_out": self.current_scan.get("total_tokens_out", 0),
            "total_cost": self.current_scan.get("total_cost", 0.0),
            "call_count": len(self.current_scan.get("calls", [])),
            "model_breakdown": self.current_scan.get("model_breakdown", {}),
        }
    
    def estimate_cost(self, model: str, tokens_in: int, tokens_out: int) -> float:
        """Estimate cost for a call without tracking it.
        
        Args:
            model: Model name
            tokens_in: Input tokens
            tokens_out: Output tokens
            
        Returns:
            Estimated cost in USD
        """
        pricing = MODEL_PRICING.get(model, {"input": 0.0, "output": 0.0})
        cost = (tokens_in / 1_000_000) * pricing["input"] + (tokens_out / 1_000_000) * pricing["output"]
        return cost


# Global tracker instance
_global_tracker: Optional[TokenTracker] = None


def get_tracker() -> TokenTracker:
    """Get or create global token tracker instance."""
    global _global_tracker
    if _global_tracker is None:
        output_dir = os.environ.get("OUTPUT_DIR", "output_zap")
        _global_tracker = TokenTracker(output_dir=output_dir)
    return _global_tracker


def track_llm_call(model: str, tokens_in: int, tokens_out: int, context: Optional[str] = None):
    """Convenience function to track an LLM call.
    
    Args:
        model: Model name
        tokens_in: Input tokens
        tokens_out: Output tokens
        context: Optional context
    """
    tracker = get_tracker()
    tracker.track_call(model, tokens_in, tokens_out, context)


def load_token_usage_history(days: int = 30) -> List[Dict[str, Any]]:
    """Load token usage history from files.
    
    Args:
        days: Number of days to look back
        
    Returns:
        List of scan summaries
    """
    output_dir = Path(os.environ.get("OUTPUT_DIR", "output_zap"))
    if not output_dir.exists():
        return []
    
    cutoff_time = time.time() - (days * 24 * 60 * 60)
    scans = []
    
    for filepath in output_dir.glob("token_usage_*.json"):
        try:
            mtime = filepath.stat().st_mtime
            if mtime < cutoff_time:
                continue
            
            with open(filepath, "r") as f:
                scan_data = json.load(f)
                scans.append(scan_data)
        except Exception:
            continue
    
    # Sort by start time
    scans.sort(key=lambda x: x.get("start_time", ""), reverse=True)
    return scans


def calculate_cost_summary(scans: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Calculate cost summary from multiple scans.
    
    Args:
        scans: List of scan summaries
        
    Returns:
        Summary with totals and averages
    """
    total_cost = sum(s.get("total_cost", 0.0) for s in scans)
    total_tokens_in = sum(s.get("total_tokens_in", 0) for s in scans)
    total_tokens_out = sum(s.get("total_tokens_out", 0) for s in scans)
    total_calls = sum(len(s.get("calls", [])) for s in scans)
    
    avg_cost = total_cost / len(scans) if scans else 0.0
    
    # Model breakdown
    model_breakdown = {}
    for scan in scans:
        for model, stats in scan.get("model_breakdown", {}).items():
            if model not in model_breakdown:
                model_breakdown[model] = {
                    "calls": 0,
                    "tokens_in": 0,
                    "tokens_out": 0,
                    "cost": 0.0,
                }
            model_breakdown[model]["calls"] += stats.get("calls", 0)
            model_breakdown[model]["tokens_in"] += stats.get("tokens_in", 0)
            model_breakdown[model]["tokens_out"] += stats.get("tokens_out", 0)
            model_breakdown[model]["cost"] += stats.get("cost", 0.0)
    
    return {
        "scan_count": len(scans),
        "total_cost": total_cost,
        "avg_cost_per_scan": avg_cost,
        "total_tokens_in": total_tokens_in,
        "total_tokens_out": total_tokens_out,
        "total_calls": total_calls,
        "model_breakdown": model_breakdown,
    }


if __name__ == "__main__":
    # CLI for viewing token usage
    import argparse
    
    parser = argparse.ArgumentParser(description="Token Usage Tracker")
    parser.add_argument("--summary", action="store_true", help="Show cost summary")
    parser.add_argument("--days", type=int, default=30, help="Number of days to analyze")
    
    args = parser.parse_args()
    
    if args.summary:
        scans = load_token_usage_history(days=args.days)
        summary = calculate_cost_summary(scans)
        
        print(f"\nToken Usage Summary (last {args.days} days):")
        print(f"  Scans: {summary['scan_count']}")
        print(f"  Total Cost: ${summary['total_cost']:.2f}")
        print(f"  Avg Cost/Scan: ${summary['avg_cost_per_scan']:.4f}")
        print(f"  Total Tokens: {summary['total_tokens_in']:,} in, {summary['total_tokens_out']:,} out")
        print(f"  Total Calls: {summary['total_calls']}")
        print("\nModel Breakdown:")
        for model, stats in summary["model_breakdown"].items():
            print(f"  {model}:")
            print(f"    Calls: {stats['calls']}")
            print(f"    Cost: ${stats['cost']:.2f}")
            print(f"    Tokens: {stats['tokens_in']:,} in, {stats['tokens_out']:,} out")

