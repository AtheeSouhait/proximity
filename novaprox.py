#!/usr/bin/env python3
"""
Nova Proximity - MCP and Skills Security Scanner
A security scanner for MCP (Model Context Protocol) servers and Agent Skills with NOVA-powered analysis.

Author: Thomas Roccia (@fr0gger_)
Version: 1.2.0
License: MIT
Repository: https://github.com/fr0gger/nova-proximity

Nova Proximity is a security-focused scanner that provides:
- MCP server discovery and analysis
- Agent Skills (agentskills.io) security scanning
- Tools, prompts, and resources enumeration
- Function signature analysis and documentation
- NOVA-based security evaluation
- Multiple output formats (console, JSON, markdown)
- Support for stdio, SSE, and HTTP transports

Usage:
    python novaprox.py <target> [options]
    python novaprox.py --skill <path> [options]

Examples:
    # Basic MCP scan
    python novaprox.py http://localhost:8000

    # Security scan with Nova rules
    python novaprox.py http://localhost:8000 --nova-scan -r my_rule.nov

    # Scan Agent Skills directory
    python novaprox.py --skill /path/to/skill -n -r skill_rules.nov

    # Recursively scan skills repository
    python novaprox.py --skill /path/to/skills-repo --skill-recursive -n

    # Export detailed reports
    python novaprox.py "python server.py" --json-report --md-report
"""

import argparse
import asyncio
import copy
import json
import sys
import os
from datetime import datetime
from typing import Optional

from lib.mcp_scanner_lib import scan_mcp_server
from lib.skill_scanner_lib import scan_skills, YAML_AVAILABLE
from lib.nova_evaluator_lib import NovaEvaluator, MCPNovaAnalyzer, SkillNovaAnalyzer, NOVA_AVAILABLE
from yaspin import yaspin

TOOL_NAME = "Nova Proximity"
TOOL_VERSION = "1.2.0"
TOOL_AUTHOR = "Thomas Roccia (@fr0gger_)"
TOOL_DESCRIPTION = "MCP and Skills Security Scanner"

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
ORANGE = "\033[38;5;208m"
BLUE = "\033[94m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


class ProximityReporter:
    """Reporter for generating output reports."""

    def __init__(self, results: dict, nova_analysis: Optional[dict] = None,
                 scan_mode: str = "mcp", full_output: bool = False):
        self.results = results
        self.nova_analysis = nova_analysis
        self.scan_mode = scan_mode  # "mcp" or "skill"
        self.full_output = full_output

    def _format_hook_matcher(self, matcher):
        """Format matcher value for display while preserving explicit empty strings."""
        if matcher is None:
            return "—"
        if matcher == "":
            return '""'
        return str(matcher)

    def _hook_event_timing(self, event_name: str) -> str:
        """Human-readable event timing summary based on Claude Code hook docs."""
        timings = {
            "SessionStart": "when a session begins or resumes",
            "UserPromptSubmit": "before Claude processes a submitted prompt",
            "PreToolUse": "before a tool call executes",
            "PermissionRequest": "when a permission dialog appears",
            "PostToolUse": "after a tool call succeeds",
            "PostToolUseFailure": "after a tool call fails",
            "Notification": "when Claude Code sends a notification",
            "SubagentStart": "when a subagent is spawned",
            "SubagentStop": "when a subagent finishes",
            "Stop": "when Claude finishes responding",
            "StopFailure": "when a turn ends due to an API error",
            "TeammateIdle": "when a teammate is about to go idle",
            "TaskCompleted": "when a task is being marked completed",
            "InstructionsLoaded": "when instruction files are loaded into context",
            "ConfigChange": "when configuration changes during a session",
            "WorktreeCreate": "when a worktree is being created",
            "WorktreeRemove": "when a worktree is being removed",
            "PreCompact": "before context compaction",
            "PostCompact": "after context compaction completes",
            "Elicitation": "when an MCP server requests user input",
            "ElicitationResult": "after a user responds to an MCP elicitation",
            "SessionEnd": "when a session terminates",
        }
        return timings.get(str(event_name), f"when event '{event_name}' fires")

    def _hook_matcher_scope(self, event_name: str, matcher) -> str:
        """Explain matcher semantics for an event."""
        no_matcher_events = {
            "UserPromptSubmit", "Stop", "TeammateIdle", "TaskCompleted",
            "WorktreeCreate", "WorktreeRemove"
        }
        matcher_fields = {
            "PreToolUse": "tool name",
            "PostToolUse": "tool name",
            "PostToolUseFailure": "tool name",
            "PermissionRequest": "tool name",
            "SessionStart": "session start source",
            "SessionEnd": "session end reason",
            "Notification": "notification type",
            "SubagentStart": "agent type",
            "SubagentStop": "agent type",
            "PreCompact": "compaction trigger",
            "PostCompact": "compaction trigger",
            "ConfigChange": "configuration source",
            "StopFailure": "error type",
            "InstructionsLoaded": "load reason",
            "Elicitation": "MCP server name",
            "ElicitationResult": "MCP server name",
        }

        event = str(event_name)
        matcher_value = matcher if matcher is not None else None

        if event in no_matcher_events:
            if matcher_value is not None:
                return "matcher is ignored for this event (it always runs)"
            return "runs on every occurrence (no matcher support)"

        field = matcher_fields.get(event)
        if matcher_value in (None, "", "*"):
            if field:
                return f"matches all {field} values"
            return "matches all occurrences"

        formatted = self._format_hook_matcher(matcher_value)
        if field:
            return f"matcher filters {field} with regex {formatted}"
        return f"matcher regex is {formatted}"

    def _hook_action_summary(self, hook_type: str) -> str:
        """Explain what a hook handler type does."""
        action_by_type = {
            "command": "executes a shell command",
            "http": "sends hook JSON as an HTTP POST request",
            "prompt": "runs a single-turn LLM prompt evaluation",
            "agent": "runs an agent-based verifier with tool access",
        }
        return action_by_type.get(str(hook_type), f"uses handler type '{hook_type}'")

    def _hook_behavior_summary(self, hook: dict) -> str:
        """Build a single sentence that explains event timing, matcher, and action."""
        event_name = str(hook.get("event", "unknown"))
        matcher = hook.get("matcher")
        hook_type = str(hook.get("type", "unknown"))
        timing = self._hook_event_timing(event_name)
        matcher_scope = self._hook_matcher_scope(event_name, matcher)
        action = self._hook_action_summary(hook_type)
        return f"Runs {timing}; {matcher_scope}; {action}."

    def _format_hook_options(self, hook: dict) -> str:
        """Format optional hook handler fields for display."""
        options = []
        for field in ("timeout", "statusMessage", "once", "async", "model"):
            if field in hook:
                options.append(f"{field}={hook[field]}")
        if hook.get("allowedEnvVars"):
            options.append(f"allowedEnvVars={hook['allowedEnvVars']}")
        return ", ".join(str(option) for option in options)

    def _hook_compliance_items(self, hooks_analysis: dict):
        """Return hook schema compliance counters for reporting."""
        checks = [
            ("Unknown events", "unknown_events"),
            ("Unknown hook types", "unknown_hook_types"),
            ("Type not supported by event", "wrong_type_hooks"),
            ("Ignored matchers", "ignored_matchers"),
            ("Invalid matcher regex/type", "invalid_matchers"),
            ("Malformed event entries", "malformed_event_entries"),
            ("Malformed matcher groups", "malformed_matcher_groups"),
            ("Malformed hooks lists", "malformed_hooks_lists"),
            ("Malformed hook items", "malformed_hook_items"),
            ("Missing required fields", "missing_required_fields"),
            ("Async on non-command hooks", "async_not_command"),
        ]
        return [
            (label, len(hooks_analysis.get(key, [])))
            for label, key in checks
            if len(hooks_analysis.get(key, [])) > 0
        ]

    def _sorted_hook_details(self, hooks: list):
        """Sort hooks for deterministic output."""
        return sorted(
            hooks,
            key=lambda hook: (
                str(hook.get("event", "")),
                "" if hook.get("matcher") is None else str(hook.get("matcher")),
                str(hook.get("type", "")),
                str(hook.get("command") or hook.get("url") or hook.get("prompt") or "")
            )
        )

    def _hook_behavioral_flag_types(self) -> set:
        """Hook finding types that represent behavioral execution risk."""
        return {
            "dangerous_hook_command",
            "hook_http_endpoint",
        }

    def _hook_config_flag_types(self) -> set:
        """Hook finding types that represent config/logic quality issues."""
        return {
            "hook_malformed_config",
            "hook_malformed_event_entries",
            "hook_malformed_matcher_group",
            "hook_malformed_hooks_list",
            "hook_malformed_hook_item",
            "hook_invalid_matcher",
            "hook_missing_required_field",
            "hook_async_not_command",
            "hook_unknown_event",
            "hook_unknown_type",
            "hook_wrong_type",
            "hook_ignored_matcher",
        }

    def _format_hook_config_quality(self, config_quality: str):
        """Return icon/colorized label for hook config quality."""
        if config_quality == "error":
            return f"🔴 {RED}ERROR{RESET}"
        if config_quality == "warning":
            return f"🟡 {YELLOW}WARNING{RESET}"
        return f"🟢 {GREEN}CLEAN{RESET}"

    def _hooks_guidance_text(self) -> str:
        """Canonical guidance text for detected hook usage."""
        return (
            "Review all hook definitions carefully. Hooks execute automatically during Claude Code "
            "lifecycle events. Remove hooks unless they are essential and from a trusted source."
        )

    def _severity_style(self, severity: str):
        """Return (icon, color) pair for a severity label."""
        sev = str(severity or "").lower()
        if sev == "critical":
            return "🔴", RED
        if sev == "high":
            return "🟠", ORANGE
        if sev == "medium":
            return "🟡", YELLOW
        if sev == "low":
            return "🟢", GREEN
        return "⚪", CYAN

    def _risk_style(self, risk_level: str):
        """Return (icon, color) pair for risk level labels."""
        return self._severity_style(risk_level)

    def _severity_rank(self, severity: str) -> int:
        """Sort key rank for severity ordering."""
        ranks = {
            "critical": 0,
            "high": 1,
            "medium": 2,
            "low": 3,
        }
        return ranks.get(str(severity or "").lower(), 4)

    def _sort_flags_by_severity(self, flags: list) -> list:
        """Return flags ordered by severity while preserving relative order within each level."""
        return sorted(
            enumerate(flags),
            key=lambda item: (self._severity_rank(item[1].get("severity")), item[0])
        )

    def _format_security_flag_lines(self, flag: dict) -> list:
        """Format a security flag into printable lines."""
        lines = []
        severity = flag.get("severity", "unknown")
        sev_icon, sev_color = self._severity_style(severity)

        lines.append(f"      {sev_icon} {sev_color}[{severity.upper()}]{RESET} {flag['type']}")

        if flag.get("source"):
            source_info = flag["source"]
            if flag.get("line_number"):
                source_info += f":{flag['line_number']}"
            lines.append(f"         📍 Source: {source_info}")

        if flag.get("line_content"):
            line_content = flag.get("line_content", "")
            if len(line_content) > 120 and not self.full_output:
                line_content = line_content[:120] + f"... [+{len(flag['line_content'])-120}]"
            lines.append(f"         📝 Code: {CYAN}{line_content}{RESET}")

        if flag.get("package"):
            lines.append(f"         📦 Package: {flag['package']}")

        if flag.get("required_tool"):
            lines.append(f"         🔧 Required Tool: {flag['required_tool']}")

        if flag.get("details"):
            details = flag.get("details", "")
            if len(details) > 150 and not self.full_output:
                details = details[:150] + f"... [+{len(flag['details'])-150}]"
            lines.append(f"         ℹ️  Details: {details}")

        if flag.get("remediation"):
            lines.append(f"         {GREEN}✅ Remediation:{RESET} {flag['remediation']}")

        return lines

    def _build_security_sections(self, security_flags: list, include_details: bool = True) -> dict:
        """Build grouped, severity-ordered security sections for JSON output."""
        flags = list(security_flags or [])
        critical = [f for f in flags if str(f.get("severity", "")).lower() == "critical"]
        high = [f for f in flags if str(f.get("severity", "")).lower() == "high"]
        medium = [f for f in flags if str(f.get("severity", "")).lower() == "medium"]
        low = [f for f in flags if str(f.get("severity", "")).lower() == "low"]

        hook_behavioral_flags = [
            f for f in flags if f.get("type") in self._hook_behavioral_flag_types()
        ]
        hook_config_flags = [
            f for f in flags if f.get("type") in self._hook_config_flag_types()
        ]
        other_flags = [
            f for f in flags
            if f.get("type") not in self._hook_behavioral_flag_types()
            and f.get("type") not in self._hook_config_flag_types()
        ]

        security_findings = [f for _, f in self._sort_flags_by_severity(hook_behavioral_flags + other_flags)]
        hook_config_logic_findings = [f for _, f in self._sort_flags_by_severity(hook_config_flags)]

        sections = {
            "total_flags": len(flags),
            "counts_by_severity": {
                "critical": len(critical),
                "high": len(high),
                "medium": len(medium),
                "low": len(low),
            }
        }
        if include_details:
            sections["security_findings"] = security_findings
            sections["hook_config_logic_findings"] = hook_config_logic_findings
        return sections

    def _build_hooks_behavior_details(self, hooks_analysis: dict) -> list:
        """Build deterministic hook details with behavior summary for JSON output."""
        hooks = hooks_analysis.get("hooks", []) if isinstance(hooks_analysis, dict) else []
        details = []
        for hook in self._sorted_hook_details(hooks):
            entry = dict(hook)
            entry["behavior"] = self._hook_behavior_summary(hook)
            details.append(entry)
        return details

    def _apply_json_style_sections(self, raw_results: dict) -> dict:
        """Attach presentation-style grouped sections to JSON scan results."""
        styled = copy.deepcopy(raw_results)
        has_skills = isinstance(styled.get("skills"), list) and len(styled.get("skills", [])) > 0

        # Top-level grouping for aggregated security flags
        top_level_flags = styled.get("security_flags", [])
        styled["security_sections"] = self._build_security_sections(
            top_level_flags,
            include_details=not has_skills
        )
        # Avoid duplicate representations in exported JSON.
        styled.pop("security_flags", None)

        # Per-skill grouping and hook behavior enrichment
        skills = styled.get("skills", [])
        if isinstance(skills, list):
            for skill in skills:
                if not isinstance(skill, dict):
                    continue
                skill_flags = skill.get("security_flags", [])
                skill["security_sections"] = self._build_security_sections(skill_flags)
                # Avoid duplicate representations in exported JSON.
                skill.pop("security_flags", None)
                hooks_analysis = skill.get("hooks_analysis", {})
                if isinstance(hooks_analysis, dict):
                    hooks_analysis["hooks_with_behavior"] = self._build_hooks_behavior_details(hooks_analysis)

        return styled
    
    def display_console_report(self):
        """Display a nice terminal report."""
        print(f"\n{BOLD}{CYAN}{'='*60}{RESET}")
        print(f"{BOLD}{GREEN} {TOOL_NAME} v{TOOL_VERSION} - {TOOL_DESCRIPTION}{RESET}")
        print(f"{BOLD}{CYAN}{'='*60}{RESET}")

        print(f"{CYAN}Target:{RESET} {self.results['target']}")
        scan_time = self.results['timestamp'][:19].replace('T', ' ')
        print(f"{CYAN}Scan Time:{RESET} {scan_time}")
        # MCP Protocol Version (MCP Spec 2025-11-25)
        if self.results.get('protocol_version'):
            print(f"{CYAN}Protocol Version:{RESET} {self.results['protocol_version']}")
        print(f"{CYAN}Endpoints:{RESET} {len(self.results['endpoints'])}")
        transport_types = ', '.join(self.results['transport_types'])
        print(f"{CYAN}Transport Types:{RESET} {transport_types}")
        # Session ID (MCP Spec 2025-11-25)
        if self.results.get('session_id'):
            session_display = self.results['session_id'][:24] + "..." if len(self.results['session_id']) > 24 else self.results['session_id']
            print(f"{CYAN}Session ID:{RESET} {session_display}")

        caps = self.results["capabilities"]
        print(f"\n{BOLD}{YELLOW}[CONFIG] Server Capabilities:{RESET}")
        tools_status = f"{GREEN}[+] YES{RESET}" if caps.get('tools') else f"{RED}[-] NO{RESET}"
        prompts_status = f"{GREEN}[+] YES{RESET}" if caps.get('prompts') else f"{RED}[-] NO{RESET}"
        resources_status = f"{GREEN}[+] YES{RESET}" if caps.get('resources') else f"{RED}[-] NO{RESET}"

        print(f"  {CYAN}Tools:{RESET} {tools_status}")
        print(f"  {CYAN}Prompts:{RESET} {prompts_status}")
        print(f"  {CYAN}Resources:{RESET} {resources_status}")

        if self.results["tools"]:
            tool_count = len(self.results['tools'])
            print(f"\n{BOLD}{BLUE}[TOOLS] Tools Discovered ({tool_count}){RESET}")
            print(f"{BLUE}{'-' * 50}{RESET}")
            for i, tool in enumerate(self.results["tools"], 1):
                param_count = len(tool["parameters"])
                required_count = len([p for p in tool["parameters"]
                                     if p["required"]])

                print(f"\n{YELLOW}[{i}]{RESET} {BOLD}{tool['name']}{RESET}")
                if tool.get("title"):  # MCP Spec 2025-11-25
                    print(f"   {CYAN}Title:{RESET} {tool['title']}")
                print(f"   {CYAN}Description:{RESET} {tool['description']}")
                print(f"   {CYAN}Parameters:{RESET} {param_count} total "
                      f"({required_count} required)")
                complexity = tool['complexity'].title()
                if complexity == "Simple":
                    complexity_color = GREEN
                elif complexity == "Moderate":
                    complexity_color = YELLOW
                else:
                    complexity_color = RED
                print(f"   {CYAN}Complexity:{RESET} {complexity_color}{complexity}{RESET}")

                if tool["parameters"]:
                    print(f"   {CYAN}Function Parameters:{RESET}")
                    for param in tool["parameters"]:
                        marker = f"{RED}*{RESET}" if param["required"] else " "
                        print(f"     {marker} {BOLD}{param['name']}{RESET}: "
                              f"{param['type']}")
                        if param['description'] != "No description":
                            print(f"       {CYAN}Description:{RESET} "
                                  f"{param['description']}")

                    print(f"   {CYAN}Function Signature:{RESET} "
                          f"{BOLD}{tool['function_signature']}{RESET}")

                # Display security annotations if present (MCP Spec 2025-11-25)
                if tool.get("annotations"):
                    annotations = tool["annotations"]
                    hints = []
                    if annotations.get("readOnlyHint"):
                        hints.append(f"{GREEN}read-only{RESET}")
                    if annotations.get("destructiveHint"):
                        hints.append(f"{RED}destructive{RESET}")
                    if not annotations.get("idempotentHint"):
                        hints.append(f"{YELLOW}non-idempotent{RESET}")
                    if annotations.get("openWorldHint"):
                        hints.append(f"{CYAN}external-access{RESET}")
                    if hints:
                        print(f"   {CYAN}Security Hints:{RESET} {', '.join(hints)}")

                    if tool["example_usage"]:
                        print(f"   {CYAN}Example Usage:{RESET}")
                        for param, value in tool["example_usage"].items():
                            print(f"     {param}: \"{value}\"")

        if self.results["prompts"]:
            prompt_count = len(self.results['prompts'])
            print(f"\n{BOLD}{BLUE}[PROMPTS] Prompts Discovered ({prompt_count}){RESET}")
            print(f"{BLUE}{'-' * 50}{RESET}")
            for i, prompt in enumerate(self.results["prompts"], 1):
                arg_count = len(prompt["arguments"])
                required_count = len([a for a in prompt["arguments"]
                                     if a["required"]])

                print(f"\n{YELLOW}[{i}]{RESET} {BOLD}{prompt['name']}{RESET}")
                if prompt.get("title"):  # MCP Spec 2025-11-25
                    print(f"   {CYAN}Title:{RESET} {prompt['title']}")
                print(f"   {CYAN}Description:{RESET} {prompt['description']}")
                print(f"   {CYAN}Arguments:{RESET} {arg_count} total "
                      f"({required_count} required)")

                if prompt["arguments"]:
                    print(f"   {CYAN}Parameters:{RESET}")
                    for arg in prompt["arguments"]:
                        marker = f"{RED}*{RESET}" if arg["required"] else " "
                        print(f"     {marker} {BOLD}{arg['name']}{RESET}: "
                              f"{arg['description']}")

                #full prompt content
                if (prompt["full_content"] and
                        prompt["full_content"]["messages"]):
                    print(f"   {CYAN}Full Prompt Content:{RESET}")
                    for msg_idx, msg in enumerate(
                            prompt["full_content"]["messages"], 1):
                        role = msg.get("role", "unknown")
                        print(f"     {YELLOW}Message {msg_idx} ({role}):{RESET}")

                        for content_item in msg.get("content", []):
                            if content_item["type"] == "text":
                                text = content_item["text"]
                                # Show first 3 lines for console
                                lines = text.split('\n')[:3]
                                for line in lines:
                                    print(f"       {line}")
                                if len(text.split('\n')) > 3:
                                    remaining_lines = (len(text.split('\n'))
                                                      - 3)
                                    print(f"       {YELLOW}... ({remaining_lines} "
                                          f"more lines){RESET}")

        if self.results["resources"]:
            resource_count = len(self.results['resources'])
            print(f"\n{BOLD}{BLUE}[RESOURCES] Resources Discovered ({resource_count}){RESET}")
            print(f"{BLUE}{'-' * 50}{RESET}")
            for i, resource in enumerate(self.results["resources"], 1):
                print(f"\n{YELLOW}[{i}]{RESET} {BOLD}{resource['uri']}{RESET}")
                if resource.get("name"):
                    print(f"   {CYAN}Name:{RESET} {resource['name']}")
                if resource.get("title"):  # MCP Spec 2025-11-25
                    print(f"   {CYAN}Title:{RESET} {resource['title']}")
                if resource.get("description") and resource["description"] != "No description":
                    print(f"   {CYAN}Description:{RESET} {resource['description']}")
                if resource.get("mime_type"):
                    print(f"   {CYAN}MIME Type:{RESET} {resource['mime_type']}")
                if resource.get("size"):  # MCP Spec 2025-11-25
                    print(f"   {CYAN}Size:{RESET} {resource['size']} bytes")
                # Display resource annotations if present (MCP Spec 2025-11-25)
                if resource.get("annotations"):
                    annotations = resource["annotations"]
                    if annotations.get("audience"):
                        print(f"   {CYAN}Audience:{RESET} {', '.join(annotations['audience'])}")
                    if annotations.get("priority") is not None:
                        print(f"   {CYAN}Priority:{RESET} {annotations['priority']}")

        if self.nova_analysis:
            self._display_nova_analysis()

        if self.results["errors"]:
            error_count = len(self.results['errors'])
            print(f"\n{BOLD}{RED}[ERROR] Errors Encountered ({error_count}){RESET}")
            print(f"{RED}{'-' * 50}{RESET}")
            for i, error in enumerate(self.results["errors"], 1):
                print(f"   {YELLOW}[{i}]{RESET} {RED}{error}{RESET}")

        print(f"\n{BOLD}{CYAN}{'='*60}{RESET}")
        summary_parts = []
        if self.results["tools"]:
            summary_parts.append(f"{len(self.results['tools'])} tools")
        if self.results["prompts"]:
            summary_parts.append(f"{len(self.results['prompts'])} prompts")
        if self.results["resources"]:
            summary_parts.append(f"{len(self.results['resources'])} "
                                "resources")

        summary = (", ".join(summary_parts) if summary_parts
                   else "No capabilities")
        print(f"{BOLD}{GREEN}[SUMMARY]{RESET} Discovery: {GREEN}{summary}{RESET}")

        if self.nova_analysis:
            flagged = self.nova_analysis["flagged_count"]
            total = self.nova_analysis["total_texts_analyzed"]
            rule_count = self.nova_analysis["rule_info"]["rule_count"]
            
            # Unique rules that matched
            matched_rules_set = set()
            for result in self.nova_analysis["analysis_results"]:
                if result["nova_evaluation"].get("matched", False):
                    matched_rules = result["nova_evaluation"].get("matched_rules", [])
                    primary_rule = result["nova_evaluation"].get("rule_name", "Unknown")
                    if matched_rules:
                        matched_rules_set.update(matched_rules)
                    else:
                        matched_rules_set.add(primary_rule)
            
            matched_rule_count = len(matched_rules_set)
            
            print(f"{BOLD}{GREEN}[SECURITY]{RESET} Analysis: {flagged}/{total} items flagged")
            if matched_rule_count > 0:
                print(f"{BOLD}{GREEN}[NOVA]{RESET} {matched_rule_count} rule{'s' if matched_rule_count > 1 else ''} matched")

        print(f"{BOLD}{CYAN}{'='*60}{RESET}")

    def display_skill_report(self):
        """Display a nice terminal report for skill scan results."""
        print(f"\n{BOLD}{CYAN}{'='*60}{RESET}")
        print(f"{BOLD}{GREEN} {TOOL_NAME} v{TOOL_VERSION} - Skills Scanner{RESET}")
        print(f"{BOLD}{CYAN}{'='*60}{RESET}")

        print(f"{CYAN}Target:{RESET} {self.results['target']}")
        scan_time = self.results['timestamp'][:19].replace('T', ' ')
        print(f"{CYAN}Scan Time:{RESET} {scan_time}")
        print(f"{CYAN}Skills Found:{RESET} {self.results['total_skills']}")

        # Display each skill
        for i, skill in enumerate(self.results.get("skills", []), 1):
            print(f"\n{BOLD}{BLUE}{'='*60}{RESET}")
            print(f"{BOLD}{BLUE}[SKILL {i}] {skill['name']}{RESET}")
            print(f"{BOLD}{BLUE}{'='*60}{RESET}")

            # ═══════════════════════════════════════════════════════════
            # SECTION 1: SKILL OVERVIEW
            # ═══════════════════════════════════════════════════════════
            print(f"\n{BOLD}{CYAN}[OVERVIEW] Skill Information{RESET}")
            print(f"{CYAN}{'-' * 50}{RESET}")

            # Description (full, formatted)
            if skill.get("description"):
                desc = skill.get('description', '')
                if len(desc) > 500 and not self.full_output:
                    desc = desc[:500] + f"... [+{len(skill['description'])-500}]"
                print(f"   {CYAN}Description:{RESET}")
                # Word wrap description for readability
                import textwrap
                wrapped = textwrap.fill(desc, width=55, initial_indent="      ", subsequent_indent="      ")
                print(wrapped)

            # Metadata section
            print(f"\n   {CYAN}Metadata:{RESET}")
            if skill.get("author"):
                print(f"      Author: {skill['author']}")
            else:
                print(f"      Author: {YELLOW}Not specified{RESET}")

            if skill.get("version"):
                print(f"      Version: {skill['version']}")
            else:
                print(f"      Version: {YELLOW}Not specified{RESET}")

            if skill.get("license"):
                print(f"      License: {skill['license']}")
            else:
                print(f"      License: {YELLOW}Not specified{RESET}")

            if skill.get("compatibility"):
                print(f"      Compatibility: {skill['compatibility']}")

            # ═══════════════════════════════════════════════════════════
            # SECTION 2: SKILL STRUCTURE
            # ═══════════════════════════════════════════════════════════
            print(f"\n{BOLD}{CYAN}[STRUCTURE] Skill Contents{RESET}")
            print(f"{CYAN}{'-' * 50}{RESET}")

            # Scripts
            scripts = skill.get("scripts", [])
            if scripts:
                suspicious_count = sum(1 for s in scripts if s.get("suspicious_patterns"))
                print(f"   {CYAN}📜 Scripts:{RESET} {len(scripts)} file(s)")
                for script in scripts:
                    status_icon = f"{RED}⚠{RESET}" if script.get("suspicious_patterns") else f"{GREEN}✓{RESET}"
                    size_kb = script.get("size", 0) / 1024
                    print(f"      {status_icon} {script['name']} ({size_kb:.1f} KB, {script.get('line_count', 0)} lines)")
            else:
                print(f"   {CYAN}📜 Scripts:{RESET} None")

            # References
            refs = skill.get("references", [])
            if refs:
                print(f"   {CYAN}📚 References:{RESET} {len(refs)} file(s)")
                for ref in refs[:5]:  # Show first 5
                    size_kb = ref.get("size", 0) / 1024
                    print(f"      • {ref.get('relative_path', ref['name'])} ({size_kb:.1f} KB)")
                if len(refs) > 5:
                    print(f"      ... and {len(refs) - 5} more")
            else:
                print(f"   {CYAN}📚 References:{RESET} None")

            # Assets
            assets = skill.get("assets", [])
            if assets:
                print(f"   {CYAN}📦 Assets:{RESET} {len(assets)} file(s)")
                for asset in assets[:5]:  # Show first 5
                    size_kb = asset.get("size", 0) / 1024
                    print(f"      • {asset.get('relative_path', asset['name'])} ({size_kb:.1f} KB)")
                if len(assets) > 5:
                    print(f"      ... and {len(assets) - 5} more")
            else:
                print(f"   {CYAN}📦 Assets:{RESET} None")

            # ═══════════════════════════════════════════════════════════
            # SECTION 3: PERMISSIONS
            # ═══════════════════════════════════════════════════════════
            tools_analysis = skill.get("allowed_tools_analysis", {})
            raw_tools = tools_analysis.get("raw_value", [])

            print(f"\n{BOLD}{CYAN}[PERMISSIONS] Allowed Tools{RESET}")
            print(f"{CYAN}{'-' * 50}{RESET}")

            if tools_analysis and tools_analysis.get("tool_count", 0) > 0:
                risk_level = tools_analysis.get("risk_level", "low")
                risk_icon, risk_color = self._risk_style(risk_level)

                print(f"   {CYAN}Tool Count:{RESET} {tools_analysis['tool_count']}")
                print(f"   {CYAN}Risk Level:{RESET} {risk_icon} {risk_color}{risk_level.upper()}{RESET}")

                # Show actual tools
                if isinstance(raw_tools, list):
                    print(f"   {CYAN}Declared Tools:{RESET}")
                    for tool in raw_tools:
                        # Check if this is a dangerous pattern
                        dangerous = any(p in str(tool) for p in ['*', 'Bash(*)', 'Write(*)', 'Edit(*)'])
                        icon = f"{RED}⚠{RESET}" if dangerous else f"{GREEN}✓{RESET}"
                        print(f"      {icon} {tool}")
                elif raw_tools:
                    print(f"   {CYAN}Declared Tools:{RESET} {raw_tools}")

                if tools_analysis.get("dangerous_patterns"):
                    print(f"   {RED}Dangerous Patterns:{RESET} {', '.join(tools_analysis['dangerous_patterns'])}")
            else:
                print(f"   {CYAN}Allowed Tools:{RESET} {YELLOW}None declared{RESET}")
                print(f"   {YELLOW}Note: Skills without declared tools may request permissions at runtime{RESET}")

            # ═══════════════════════════════════════════════════════════
            # SECTION 4: HOOKS
            # ═══════════════════════════════════════════════════════════
            hooks_analysis = skill.get("hooks_analysis", {})
            compliance_items = self._hook_compliance_items(hooks_analysis)
            has_hook_details = bool(hooks_analysis.get("hooks"))
            has_hook_data = (
                bool(hooks_analysis)
                and (
                    hooks_analysis.get("total_hooks", 0) > 0
                    or hooks_analysis.get("valid_hook_handlers", 0) > 0
                    or len(compliance_items) > 0
                )
            )
            if has_hook_data:
                risk_level = hooks_analysis.get("risk_level", "low")
                risk_icon, risk_color = self._risk_style(risk_level)

                print(f"\n{BOLD}{CYAN}[HOOKS] Claude Code Hooks{RESET}")
                print(f"{CYAN}{'-' * 50}{RESET}")
                hook_events = sorted(str(event) for event in hooks_analysis.get("hook_events", []))
                print(f"   {CYAN}Hook Events:{RESET} {len(hook_events)}")
                print(f"   {CYAN}Total Handlers:{RESET} {hooks_analysis.get('total_hooks', 0)}")
                print(f"   {CYAN}Valid Handlers:{RESET} {hooks_analysis.get('valid_hook_handlers', 0)}")
                print(f"   {CYAN}Invalid Handlers:{RESET} {hooks_analysis.get('invalid_hook_handlers', 0)}")
                print(f"   {CYAN}Behavioral Risk:{RESET} {risk_icon} {risk_color}{risk_level.upper()}{RESET}")
                print(
                    f"   {CYAN}Config Quality:{RESET} "
                    f"{self._format_hook_config_quality(hooks_analysis.get('config_quality', 'clean'))}"
                )
                if hooks_analysis.get("valid_hook_handlers", 0) > 0:
                    print(f"   {CYAN}Guidance:{RESET} {self._hooks_guidance_text()}")

                hook_types = hooks_analysis.get("hooks_by_type", {})
                if hook_types:
                    print(f"   {CYAN}Types:{RESET}")
                    for hook_type in sorted(hook_types):
                        count = hook_types[hook_type]
                        if hook_type == "command":
                            icon = "🔴"
                        elif hook_type == "http":
                            icon = "🟠"
                        elif hook_type in {"prompt", "agent"}:
                            icon = "🟡"
                        else:
                            icon = "⚪"
                        print(f"      {icon} {hook_type}: {count}")

                if compliance_items:
                    print(f"   {CYAN}Schema Compliance:{RESET}")
                    for label, count in compliance_items:
                        print(f"      ⚠️ {label}: {count}")

                if has_hook_details:
                    print(f"\n   {CYAN}Hook Details:{RESET}")
                    for hook in self._sorted_hook_details(hooks_analysis.get("hooks", [])):
                        matcher = hook.get("matcher")
                        matcher_str = f" [matcher: {self._format_hook_matcher(matcher)}]" if matcher is not None else ""
                        print(f"      {hook['event']}{matcher_str}")
                        if hook["type"] == "command":
                            print(f"         ⚡ command: {hook.get('command', '')[:80]}")
                        elif hook["type"] == "http":
                            print(f"         🌐 url: {hook.get('url', '')}")
                        elif hook["type"] in {"prompt", "agent"}:
                            print(f"         🤖 {hook['type']}: {hook.get('prompt', '')[:80]}")
                        else:
                            print(f"         ⚪ {hook['type']}")
                        print(f"         {CYAN}behavior:{RESET} {self._hook_behavior_summary(hook)}")
                        options = self._format_hook_options(hook)
                        if options:
                            print(f"         {CYAN}options:{RESET} {options}")

            # ═══════════════════════════════════════════════════════════
            # SECTION 5: SECURITY ANALYSIS
            # ═══════════════════════════════════════════════════════════
            security_flags = skill.get("security_flags", [])
            print(f"\n{BOLD}{RED if security_flags else GREEN}[SECURITY] Security Analysis{RESET}")
            print(f"{RED if security_flags else GREEN}{'-' * 50}{RESET}")

            if security_flags:
                # Group by severity
                critical = [f for f in security_flags if f.get("severity") == "critical"]
                high = [f for f in security_flags if f.get("severity") == "high"]
                medium = [f for f in security_flags if f.get("severity") == "medium"]
                low = [f for f in security_flags if f.get("severity") == "low"]

                print(f"   {CYAN}Total Flags:{RESET} {len(security_flags)}")
                print(f"      {RED}Critical:{RESET} {len(critical)}")
                print(f"      {ORANGE}High:{RESET} {len(high)}")
                print(f"      {YELLOW}Medium:{RESET} {len(medium)}")
                print(f"      {GREEN}Low:{RESET} {len(low)}")

                hook_behavioral_flags = [
                    f for f in security_flags if f.get("type") in self._hook_behavioral_flag_types()
                ]
                hook_config_flags = [
                    f for f in security_flags if f.get("type") in self._hook_config_flag_types()
                ]
                other_flags = [
                    f for f in security_flags
                    if f.get("type") not in self._hook_behavioral_flag_types()
                    and f.get("type") not in self._hook_config_flag_types()
                ]
                security_findings = [f for _, f in self._sort_flags_by_severity(hook_behavioral_flags + other_flags)]
                hook_config_flags = [f for _, f in self._sort_flags_by_severity(hook_config_flags)]

                if security_findings:
                    print(f"\n   {BOLD}{CYAN}Security Findings:{RESET}")
                    for idx, flag in enumerate(security_findings):
                        for line in self._format_security_flag_lines(flag):
                            print(line)
                        if idx < len(security_findings) - 1:
                            print()

                if hook_config_flags:
                    print(f"\n   {BOLD}{YELLOW}Hook Config/Logic Findings:{RESET}")
                    for idx, flag in enumerate(hook_config_flags):
                        for line in self._format_security_flag_lines(flag):
                            print(line)
                        if idx < len(hook_config_flags) - 1:
                            print()
            else:
                print(f"   {GREEN}✅ No security issues detected{RESET}")

            # Parse errors
            parse_errors = skill.get("parse_errors", [])
            if parse_errors:
                print(f"\n   {BOLD}{YELLOW}[!] Parse Errors:{RESET}")
                for error in parse_errors:
                    print(f"      ⚠️  {YELLOW}{error}{RESET}")

        # Display Nova analysis if available
        if self.nova_analysis:
            self._display_nova_analysis()

        # Display errors
        if self.results.get("errors"):
            error_count = len(self.results['errors'])
            print(f"\n{BOLD}{RED}[ERROR] Errors Encountered ({error_count}){RESET}")
            print(f"{RED}{'-' * 50}{RESET}")
            for i, error in enumerate(self.results["errors"], 1):
                print(f"   {YELLOW}[{i}]{RESET} {RED}{error}{RESET}")

        # Summary
        print(f"\n{BOLD}{CYAN}{'='*60}{RESET}")
        total_skills = self.results["total_skills"]
        total_flags = len(self.results.get("security_flags", []))

        print(f"{BOLD}{GREEN}[SUMMARY]{RESET} Skills: {GREEN}{total_skills}{RESET}, "
              f"Security Flags: {RED if total_flags > 0 else GREEN}{total_flags}{RESET}")

        if self.nova_analysis:
            flagged = self.nova_analysis["flagged_count"]
            total = self.nova_analysis["total_texts_analyzed"]

            matched_rules_set = set()
            for result in self.nova_analysis["analysis_results"]:
                if result["nova_evaluation"].get("matched", False):
                    matched_rules = result["nova_evaluation"].get("matched_rules", [])
                    primary_rule = result["nova_evaluation"].get("rule_name", "Unknown")
                    if matched_rules:
                        matched_rules_set.update(matched_rules)
                    else:
                        matched_rules_set.add(primary_rule)

            matched_rule_count = len(matched_rules_set)

            print(f"{BOLD}{GREEN}[NOVA]{RESET} Analysis: {flagged}/{total} items flagged")
            if matched_rule_count > 0:
                print(f"{BOLD}{GREEN}[NOVA]{RESET} {matched_rule_count} rule{'s' if matched_rule_count > 1 else ''} matched")

        print(f"{BOLD}{CYAN}{'='*60}{RESET}")

    def _display_nova_analysis(self):
        """Display Nova security analysis results."""
        print(f"\n{BOLD}{GREEN}[NOVA] NOVA Analysis Results{RESET}")
        print(f"{GREEN}{'-' * 50}{RESET}")

        rule_info = self.nova_analysis["rule_info"]
        
        if rule_info['rule_count'] > 1:
            rules_str = ', '.join(rule_info['rule_names'])
            print(f"{CYAN}Rules:{RESET} {rules_str} ({rule_info['rule_count']} total)")
        else:
            print(f"{CYAN}Rule:{RESET} {rule_info['name']}")
        
        print(f"{CYAN}Evaluator:{RESET} {rule_info['evaluator_type']}")
        total_analyzed = self.nova_analysis['total_texts_analyzed']
        print(f"{CYAN}Total Items Analyzed:{RESET} {total_analyzed}")
        print(f"{CYAN}Flagged Items:{RESET} {self.nova_analysis['flagged_count']}")

        if self.nova_analysis["flagged_count"] > 0:
            print(f"\n{BOLD}{RED}[!] Security Alerts:{RESET}")
            
            alerts_by_rule = {}
            for result in self.nova_analysis["analysis_results"]:
                if result["nova_evaluation"].get("matched", False):

                    matched_rules = result["nova_evaluation"].get("matched_rules", [])
                    primary_rule = result["nova_evaluation"].get("rule_name", "Unknown")
                    
                    if not matched_rules:
                        matched_rules = [primary_rule]
                    
                    # Add this result to each rule it matches
                    for rule_name in matched_rules:
                        if rule_name not in alerts_by_rule:
                            alerts_by_rule[rule_name] = []
                        alerts_by_rule[rule_name].append(result)
            
            # alerts grouped by rule
            for rule_name, alerts in alerts_by_rule.items():
                print(f"\n{BOLD}{RED}▌ Rule: {rule_name} ({len(alerts)} alert{'s' if len(alerts) > 1 else ''}){RESET}")
                print(f"{RED}{'─' * 50}{RESET}")
                
                for i, result in enumerate(alerts, 1):
                    nova_result = result["nova_evaluation"]
                    
                    print(f"\n{YELLOW}[{i}]{RESET} {BOLD}{result['source']}{RESET}")
                    print(f"    {CYAN}Type:{RESET} {result['type']}")
                    print(f"    {CYAN}Content:{RESET} {result['text_preview']}")
                    
                    # matched keywords specific to this rule
                    per_rule_keywords = nova_result.get("per_rule_keywords", {})
                    
                    # keywords for the current rule displaying
                    if per_rule_keywords and rule_name in per_rule_keywords:
                        keywords_to_show = per_rule_keywords[rule_name]
                    else:
                        keywords_to_show = nova_result.get("matching_keywords", {})
                    
                    if keywords_to_show:
                        if isinstance(keywords_to_show, dict):
                            keyword_list = [f"'{k}'" for k, v in keywords_to_show.items() if v]
                        else:
                            keyword_list = [str(keywords_to_show)]
                        
                        if keyword_list:
                            keywords_str = ", ".join(keyword_list)
                            print(f"    {CYAN}Triggered Keywords:{RESET} {keywords_str}")
                    
                    matched_rules = nova_result.get("matched_rules", [])
                    if matched_rules and len(matched_rules) > 1:
                        other_rules = [r for r in matched_rules if r != rule_name]
                        if other_rules:
                            print(f"    {CYAN}Also Matches:{RESET} {', '.join(other_rules)}")
        else:
            print(f"\n{GREEN}[+] No security issues detected!{RESET}")
    
    def export_json_report(self, filename: str):
        """Export detailed JSON report."""
        report = {
            "scan_results": self._apply_json_style_sections(self.results),
            "nova_analysis": self.nova_analysis,
            "export_timestamp": datetime.now().isoformat()
        }
        
        with open(filename, "w") as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"{GREEN}[+] JSON report exported to: {filename}{RESET}")

    def export_markdown_report(self, filename: str):
        """Export markdown report."""
        md_content = []

        # Header
        header = f"# {TOOL_NAME} v{TOOL_VERSION} - MCP Scan Report\n\n"
        md_content.append(header)
        md_content.append(f"**Target:** {self.results['target']}\n")
        md_content.append(f"**Scan Date:** {self.results['timestamp']}\n")
        if self.results.get('protocol_version'):
            md_content.append(f"**Protocol Version:** {self.results['protocol_version']}\n")
        md_content.append(f"**Endpoints:** {len(self.results['endpoints'])}\n")
        transport_types = ', '.join(self.results['transport_types'])
        md_content.append(f"**Transport Types:** {transport_types}\n")
        if self.results.get('session_id'):
            md_content.append(f"**Session ID:** {self.results['session_id']}\n")
        md_content.append("\n")

        # Capabilities
        caps = self.results["capabilities"]
        md_content.append("## Server Capabilities\n\n")
        tools_status = '✅ Available' if caps.get('tools') else '❌ Not Available'
        prompts_status = ('✅ Available' if caps.get('prompts')
                         else '❌ Not Available')
        resources_status = ('✅ Available' if caps.get('resources')
                           else '❌ Not Available')
        md_content.append(f"- **Tools:** {tools_status}\n")
        md_content.append(f"- **Prompts:** {prompts_status}\n")
        md_content.append(f"- **Resources:** {resources_status}\n\n")
        
        # Tools
        if self.results["tools"]:
            tool_count = len(self.results['tools'])
            md_content.append(f"## Tools Analysis ({tool_count} found)\n\n")
            for tool in self.results["tools"]:
                md_content.append(f"### {tool['name']}\n\n")
                md_content.append(f"**Description:** {tool['description']}\n\n")
                complexity = tool['complexity'].title()
                md_content.append(f"**Complexity:** {complexity}\n")
                param_count = len(tool['parameters'])
                md_content.append(f"**Parameters:** {param_count} total\n\n")

                if tool["parameters"]:
                    md_content.append("**Function Parameters:**\n")
                    for param in tool["parameters"]:
                        status = "Required" if param["required"] else "Optional"
                        param_desc = param['description']
                        md_content.append(f"- `{param['name']}` "
                                        f"({param['type']}, {status}): "
                                        f"{param_desc}\n")
                    md_content.append("\n")
                    signature = tool['function_signature']
                    md_content.append(f"**Function Signature:**\n"
                                    f"```\n{signature}\n```\n\n")

        # Prompts
        if self.results["prompts"]:
            prompt_count = len(self.results['prompts'])
            md_content.append(f"## Prompts Analysis ({prompt_count} found)\n\n")
            for prompt in self.results["prompts"]:
                md_content.append(f"### {prompt['name']}\n\n")
                md_content.append(f"**Description:** {prompt['description']}\n\n")

                if prompt["arguments"]:
                    md_content.append("**Arguments:**\n")
                    for arg in prompt["arguments"]:
                        status = "Required" if arg["required"] else "Optional"
                        md_content.append(f"- `{arg['name']}` ({status}): "
                                        f"{arg['description']}\n")
                    md_content.append("\n")

                if (prompt["full_content"] and
                        prompt["full_content"]["messages"]):
                    md_content.append("**Full Prompt Content:**\n")
                    for msg_idx, msg in enumerate(
                            prompt["full_content"]["messages"], 1):
                        role = msg.get("role", "unknown")
                        md_content.append(f"**Message {msg_idx} ({role}):**\n")
                        for content_item in msg.get("content", []):
                            if content_item["type"] == "text":
                                text = content_item['text']
                                md_content.append(f"```\n{text}\n```\n\n")

        # Resources
        if self.results["resources"]:
            resource_count = len(self.results['resources'])
            md_content.append(f"## Resources Analysis "
                            f"({resource_count} found)\n\n")
            for resource in self.results["resources"]:
                md_content.append(f"### {resource['uri']}\n\n")
                if resource["name"]:
                    md_content.append(f"**Name:** {resource['name']}\n")
                md_content.append(f"**Description:** "
                                f"{resource['description']}\n")
                if resource["mime_type"]:
                    md_content.append(f"**MIME Type:** "
                                    f"{resource['mime_type']}\n")
                md_content.append("\n")

        # Nova analysis
        if self.nova_analysis:
            md_content.append("## Security Analysis\n\n")
            rule_info = self.nova_analysis["rule_info"]
            
            # Show all rules if multiple rules are loaded
            if rule_info['rule_count'] > 1:
                rules_str = ', '.join(rule_info['rule_names'])
                md_content.append(f"**Rules:** {rules_str} ({rule_info['rule_count']} total)\n")
            else:
                md_content.append(f"**Rule:** {rule_info['name']}\n")
            
            md_content.append(f"**Evaluator:** "
                            f"{rule_info['evaluator_type']}\n")
            total_analyzed = self.nova_analysis['total_texts_analyzed']
            md_content.append(f"**Items Analyzed:** {total_analyzed}\n")
            flagged_count = self.nova_analysis['flagged_count']
            md_content.append(f"**Flagged Items:** {flagged_count}\n\n")

            if self.nova_analysis["flagged_count"] > 0:
                md_content.append("### Security Alerts\n\n")
                
                alerts_by_rule = {}
                for result in self.nova_analysis["analysis_results"]:
                    if result["nova_evaluation"].get("matched", False):
                        matched_rules = result["nova_evaluation"].get("matched_rules", [])
                        primary_rule = result["nova_evaluation"].get("rule_name", "Unknown")
                        
                        if not matched_rules:
                            matched_rules = [primary_rule]
                        
                        for rule_name in matched_rules:
                            if rule_name not in alerts_by_rule:
                                alerts_by_rule[rule_name] = []
                            alerts_by_rule[rule_name].append(result)
                
                for rule_name, alerts in alerts_by_rule.items():
                    alert_count = len(alerts)
                    md_content.append(f"#### Rule: {rule_name} ({alert_count} alert{'s' if alert_count > 1 else ''})\n\n")
                    
                    for i, result in enumerate(alerts, 1):
                        nova_result = result["nova_evaluation"]
                        
                        md_content.append(f"**[{i}] {result['source']}**\n\n")
                        md_content.append(f"- **Type:** {result['type']}\n")
                        md_content.append(f"- **Content:** {result['text_preview']}\n")
                        
                        per_rule_keywords = nova_result.get("per_rule_keywords", {})
                        
                        if per_rule_keywords and rule_name in per_rule_keywords:
                            keywords_to_show = per_rule_keywords[rule_name]
                        else:
                            keywords_to_show = nova_result.get("matching_keywords", {})
                        
                        if keywords_to_show:
                            if isinstance(keywords_to_show, dict):
                                keyword_list = [f"'{k}'" for k, v in keywords_to_show.items() if v]
                            else:
                                keyword_list = [str(keywords_to_show)]
                            
                            if keyword_list:
                                keywords_str = ", ".join(keyword_list)
                                md_content.append(f"- **Triggered Keywords:** {keywords_str}\n")
                        
                        # Show additional matched rules if multiple rules matched
                        matched_rules = nova_result.get("matched_rules", [])
                        if matched_rules and len(matched_rules) > 1:
                            other_rules = [r for r in matched_rules if r != rule_name]
                            if other_rules:
                                md_content.append(f"- **Also Matches:** {', '.join(other_rules)}\n")
                        
                        md_content.append("\n")

        # Errors
        if self.results["errors"]:
            md_content.append("## Errors\n\n")
            for error in self.results["errors"]:
                md_content.append(f"- {error}\n")
            md_content.append("\n")

        # Write to file
        with open(filename, "w") as f:
            f.write("".join(md_content))

        print(f"{GREEN}[+] Markdown report exported to: {filename}{RESET}")

    def export_skill_json_report(self, filename: str):
        """Export detailed JSON report for skill scan."""
        report = {
            "scan_type": "skill",
            "scan_results": self._apply_json_style_sections(self.results),
            "nova_analysis": self.nova_analysis,
            "export_timestamp": datetime.now().isoformat()
        }

        with open(filename, "w") as f:
            json.dump(report, f, indent=2, default=str)

        print(f"{GREEN}[+] JSON report exported to: {filename}{RESET}")

    def export_skill_markdown_report(self, filename: str):
        """Export markdown report for skill scan."""
        md_content = []

        # Header
        header = f"# {TOOL_NAME} v{TOOL_VERSION} - Skills Scan Report\n\n"
        md_content.append(header)
        md_content.append(f"**Target:** {self.results['target']}\n")
        md_content.append(f"**Scan Date:** {self.results['timestamp']}\n")
        md_content.append(f"**Skills Found:** {self.results['total_skills']}\n")
        total_flags = len(self.results.get("security_flags", []))
        md_content.append(f"**Security Flags:** {total_flags}\n\n")

        # Skills
        for i, skill in enumerate(self.results.get("skills", []), 1):
            md_content.append(f"## Skill {i}: {skill['name']}\n\n")

            if skill.get("description"):
                md_content.append(f"**Description:** {skill['description']}\n\n")

            if skill.get("author"):
                md_content.append(f"**Author:** {skill['author']}\n")

            if skill.get("version"):
                md_content.append(f"**Version:** {skill['version']}\n")

            if skill.get("license"):
                md_content.append(f"**License:** {skill['license']}\n")

            md_content.append("\n")

            # Scripts
            scripts = skill.get("scripts", [])
            if scripts:
                md_content.append(f"### Scripts ({len(scripts)} files)\n\n")
                for script in scripts:
                    suspicious = script.get("suspicious_patterns", [])
                    status = " (SUSPICIOUS)" if suspicious else ""
                    md_content.append(f"- `{script['name']}`{status}\n")
                    if suspicious:
                        for pattern in suspicious:
                            md_content.append(f"  - {pattern}\n")
                md_content.append("\n")

            # References
            refs = skill.get("references", [])
            if refs:
                md_content.append(f"### References ({len(refs)} files)\n\n")
                for ref in refs:
                    md_content.append(f"- `{ref.get('relative_path', ref['name'])}`\n")
                md_content.append("\n")

            # Allowed Tools Analysis
            tools_analysis = skill.get("allowed_tools_analysis", {})
            if tools_analysis and tools_analysis.get("tool_count", 0) > 0:
                md_content.append("### Tool Permissions Analysis\n\n")
                md_content.append(f"**Tool Count:** {tools_analysis['tool_count']}\n")
                md_content.append(f"**Risk Level:** {tools_analysis['risk_level'].upper()}\n")
                if tools_analysis.get("dangerous_patterns"):
                    md_content.append(f"**Dangerous Patterns:** {', '.join(tools_analysis['dangerous_patterns'])}\n")
                md_content.append("\n")

            hooks_analysis = skill.get("hooks_analysis", {})
            compliance_items = self._hook_compliance_items(hooks_analysis)
            has_hook_details = bool(hooks_analysis.get("hooks"))
            has_hook_data = (
                bool(hooks_analysis)
                and (
                    hooks_analysis.get("total_hooks", 0) > 0
                    or hooks_analysis.get("valid_hook_handlers", 0) > 0
                    or len(compliance_items) > 0
                )
            )
            if has_hook_data:
                md_content.append("### Hooks Analysis\n\n")
                hook_events = sorted(str(event) for event in hooks_analysis.get("hook_events", []))
                md_content.append(f"**Hook Events:** {', '.join(hook_events)}\n")
                md_content.append(f"**Total Handlers:** {hooks_analysis.get('total_hooks', 0)}\n")
                md_content.append(f"**Valid Handlers:** {hooks_analysis.get('valid_hook_handlers', 0)}\n")
                md_content.append(f"**Invalid Handlers:** {hooks_analysis.get('invalid_hook_handlers', 0)}\n")
                md_content.append(f"**Behavioral Risk:** {hooks_analysis.get('risk_level', 'low').upper()}\n")
                md_content.append(f"**Config Quality:** {hooks_analysis.get('config_quality', 'clean').upper()}\n")
                if hooks_analysis.get("valid_hook_handlers", 0) > 0:
                    md_content.append(f"**Guidance:** {self._hooks_guidance_text()}\n")

                hook_types = hooks_analysis.get("hooks_by_type", {})
                if hook_types:
                    types_text = ", ".join(f"{hook_type}: {hook_types[hook_type]}" for hook_type in sorted(hook_types))
                    md_content.append(f"**Types:** {types_text}\n")

                if compliance_items:
                    summary_text = ", ".join(f"{label}: {count}" for label, count in compliance_items)
                    md_content.append(f"**Schema Compliance:** {summary_text}\n")

                if has_hook_details:
                    md_content.append("\n| Event | Matcher | Type | Command/URL/Prompt | Behavior |\n")
                    md_content.append("|-------|---------|------|--------------------|----------|\n")
                    for hook in self._sorted_hook_details(hooks_analysis.get("hooks", [])):
                        matcher = self._format_hook_matcher(hook.get("matcher"))
                        value = hook.get("command") or hook.get("url") or hook.get("prompt") or ""
                        options = self._format_hook_options(hook)
                        if options:
                            value = f"{value} [{options}]"
                        behavior = self._hook_behavior_summary(hook)
                        matcher = str(matcher).replace("|", "\\|").replace("\n", " ")
                        value = str(value).replace("|", "\\|").replace("\n", " ")[:120]
                        behavior = str(behavior).replace("|", "\\|").replace("\n", " ")
                        md_content.append(f"| {hook['event']} | {matcher} | {hook['type']} | {value} | {behavior} |\n")
                md_content.append("\n")

            # Security Flags
            security_flags = skill.get("security_flags", [])
            if security_flags:
                md_content.append("### Security Flags\n\n")
                hook_behavioral_flags = [
                    f for f in security_flags if f.get("type") in self._hook_behavioral_flag_types()
                ]
                hook_config_flags = [
                    f for f in security_flags if f.get("type") in self._hook_config_flag_types()
                ]
                other_flags = [
                    f for f in security_flags
                    if f.get("type") not in self._hook_behavioral_flag_types()
                    and f.get("type") not in self._hook_config_flag_types()
                ]
                security_findings = [f for _, f in self._sort_flags_by_severity(hook_behavioral_flags + other_flags)]
                hook_config_flags = [f for _, f in self._sort_flags_by_severity(hook_config_flags)]

                def append_flag_block(title: str, flags: list):
                    if not flags:
                        return
                    md_content.append(f"#### {title}\n\n")
                    for flag in flags:
                        severity = flag.get("severity", "unknown").upper()
                        md_content.append(f"- **[{severity}]** {flag['type']}\n")
                        if flag.get("source"):
                            source_info = flag["source"]
                            if flag.get("line_number"):
                                source_info += f":{flag['line_number']}"
                            md_content.append(f"  - Source: `{source_info}`\n")
                        if flag.get("line_content"):
                            md_content.append(f"  - Line: `{flag['line_content']}`\n")
                        if flag.get("package"):
                            md_content.append(f"  - Package: `{flag['package']}`\n")
                        if flag.get("required_tool"):
                            md_content.append(f"  - Required Tool: `{flag['required_tool']}`\n")
                        if flag.get("details"):
                            md_content.append(f"  - Details: {flag['details']}\n")
                        if flag.get("remediation"):
                            md_content.append(f"  - **Remediation:** {flag['remediation']}\n")
                    md_content.append("\n")

                append_flag_block("Security Findings", security_findings)
                append_flag_block("Hook Config/Logic Findings", hook_config_flags)

        # Nova analysis
        if self.nova_analysis:
            md_content.append("## NOVA Security Analysis\n\n")
            rule_info = self.nova_analysis["rule_info"]

            if rule_info['rule_count'] > 1:
                rules_str = ', '.join(rule_info['rule_names'])
                md_content.append(f"**Rules:** {rules_str} ({rule_info['rule_count']} total)\n")
            else:
                md_content.append(f"**Rule:** {rule_info['name']}\n")

            md_content.append(f"**Evaluator:** {rule_info['evaluator_type']}\n")
            total_analyzed = self.nova_analysis['total_texts_analyzed']
            md_content.append(f"**Items Analyzed:** {total_analyzed}\n")
            flagged_count = self.nova_analysis['flagged_count']
            md_content.append(f"**Flagged Items:** {flagged_count}\n\n")

            if self.nova_analysis["flagged_count"] > 0:
                md_content.append("### Security Alerts\n\n")

                alerts_by_rule = {}
                for result in self.nova_analysis["analysis_results"]:
                    if result["nova_evaluation"].get("matched", False):
                        matched_rules = result["nova_evaluation"].get("matched_rules", [])
                        primary_rule = result["nova_evaluation"].get("rule_name", "Unknown")

                        if not matched_rules:
                            matched_rules = [primary_rule]

                        for rule_name in matched_rules:
                            if rule_name not in alerts_by_rule:
                                alerts_by_rule[rule_name] = []
                            alerts_by_rule[rule_name].append(result)

                for rule_name, alerts in alerts_by_rule.items():
                    alert_count = len(alerts)
                    md_content.append(f"#### Rule: {rule_name} ({alert_count} alert{'s' if alert_count > 1 else ''})\n\n")

                    for i, result in enumerate(alerts, 1):
                        nova_result = result["nova_evaluation"]

                        md_content.append(f"**[{i}] {result['source']}**\n\n")
                        md_content.append(f"- **Type:** {result['type']}\n")
                        md_content.append(f"- **Content:** {result['text_preview']}\n")

                        per_rule_keywords = nova_result.get("per_rule_keywords", {})

                        if per_rule_keywords and rule_name in per_rule_keywords:
                            keywords_to_show = per_rule_keywords[rule_name]
                        else:
                            keywords_to_show = nova_result.get("matching_keywords", {})

                        if keywords_to_show:
                            if isinstance(keywords_to_show, dict):
                                keyword_list = [f"'{k}'" for k, v in keywords_to_show.items() if v]
                            else:
                                keyword_list = [str(keywords_to_show)]

                            if keyword_list:
                                keywords_str = ", ".join(keyword_list)
                                md_content.append(f"- **Triggered Keywords:** {keywords_str}\n")

                        matched_rules_list = nova_result.get("matched_rules", [])
                        if matched_rules_list and len(matched_rules_list) > 1:
                            other_rules = [r for r in matched_rules_list if r != rule_name]
                            if other_rules:
                                md_content.append(f"- **Also Matches:** {', '.join(other_rules)}\n")

                        md_content.append("\n")

        # Errors
        if self.results.get("errors"):
            md_content.append("## Errors\n\n")
            for error in self.results["errors"]:
                md_content.append(f"- {error}\n")
            md_content.append("\n")

        # Write to file
        with open(filename, "w") as f:
            f.write("".join(md_content))

        print(f"{GREEN}[+] Markdown report exported to: {filename}{RESET}")


def print_ascii_art():
    """Print fun ASCII art for help display."""
    art = """
    ███╗   ██╗ ██████╗ ██╗   ██╗ █████╗     ██████╗ ██████╗  ██████╗ ██╗  ██╗
    ████╗  ██║██╔═══██╗██║   ██║██╔══██╗    ██╔══██╗██╔══██╗██╔═══██╗╚██╗██╔╝
    ██╔██╗ ██║██║   ██║██║   ██║███████║    ██████╔╝██████╔╝██║   ██║ ╚███╔╝
    ██║╚██╗██║██║   ██║╚██╗ ██╔╝██╔══██║    ██╔═══╝ ██╔══██╗██║   ██║ ██╔██╗
    ██║ ╚████║╚██████╔╝ ╚████╔╝ ██║  ██║    ██║     ██║  ██║╚██████╔╝██╔╝ ██╗
    ╚═╝  ╚═══╝ ╚═════╝   ╚═══╝  ╚═╝  ╚═╝    ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝

    🛡️  {} v{} - {}
    🔍 Discover • 🔧 Analyze • 🛡️  Secure
    by {}
    """.format(TOOL_NAME, TOOL_VERSION, TOOL_DESCRIPTION, TOOL_AUTHOR)
    print(art)


class CustomHelpAction(argparse._HelpAction):
    """Custom help action that shows ASCII art."""
    def __init__(self, option_strings, dest=argparse.SUPPRESS,
                 default=argparse.SUPPRESS, help=None):
        super().__init__(option_strings, dest, default, help)

    def __call__(self, parser, namespace, values, option_string=None):
        _ = namespace, values, option_string
        print_ascii_art()
        parser.print_help()
        parser.exit()


async def main():
    """Main function for Nova Proximity scanner."""
    parser = argparse.ArgumentParser(
        description="Nova Proximity - MCP and Skills Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False,
        epilog="""
Examples:
  # Basic MCP scan
  python novaprox.py http://localhost:8000

  # Scan with authentication
  python novaprox.py http://localhost:8000 -t your_token

  # Scan stdio server
  python novaprox.py "python server.py"

  # Security scan with Nova rules
  python novaprox.py http://localhost:8000 -n -r my_rule.nov

  # Scan Agent Skills directory
  python novaprox.py --skill /path/to/skill -n -r skill_rules.nov

  # Recursively scan skills repository
  python novaprox.py --skill /path/to/skills-repo --skill-recursive -n

  # Export reports
  python novaprox.py http://localhost:8000 --json-report --md-report
        """
    )

    parser.add_argument('-h', '--help', action=CustomHelpAction,
                        help='show this help message and exit')

    # MCP target (optional when using --skill)
    parser.add_argument("target", nargs="?", default=None,
                        help="MCP server target (HTTP URL or stdio command)")

    # Skill scanning options
    skill_group = parser.add_argument_group("Skill Scanning")
    skill_group.add_argument("-s", "--skill", metavar="PATH",
                             help="Scan Agent Skills directory for security issues")
    skill_group.add_argument("--skill-recursive", action="store_true",
                             help="Recursively scan for skills in subdirectories")

    # MCP options
    mcp_group = parser.add_argument_group("MCP Options")
    mcp_group.add_argument("-t", "--token",
                           help="Authentication token for HTTP endpoints")
    mcp_group.add_argument("--timeout", type=float, default=10.0,
                           help="Connection timeout in seconds (default: 10)")

    # Common options
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable verbose output during scanning")

    # Nova security scanning
    nova_group = parser.add_argument_group("Nova Security Scanning")
    nova_group.add_argument("-n", "--nova-scan", action="store_true",
                            help="Enable Nova security analysis")
    nova_group.add_argument("-r", "--rule", default=None,
                            help="Nova rule file path (default: my_rule.nov for MCP, skill_rules.nov for skills)")
    nova_group.add_argument("--evaluator", choices=["openai", "groq", "anthropic", "azure", "ollama"],
                            default="openai",
                            help="LLM evaluator type (default: openai)")
    nova_group.add_argument("--model",
                            help="LLM model to use (optional)")
    nova_group.add_argument("--api-key",
                            help="API key for LLM evaluator (optional)")

    # Output options
    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument("--json-report", action="store_true",
                              help="Export detailed JSON report")
    output_group.add_argument("--md-report", action="store_true",
                              help="Export markdown report")
    output_group.add_argument("--output-prefix", default=None,
                              help="Prefix for output files (default: novaprox_scan or skill_scan)")
    output_group.add_argument("--full-output", action="store_true",
                              help="Show full text without truncation (remediation, details, etc.)")

    args = parser.parse_args()

    # Determine scan mode
    scan_mode = "skill" if args.skill else "mcp"

    # Validate arguments
    if scan_mode == "mcp" and not args.target:
        parser.error("target is required for MCP scanning (or use --skill for skill scanning)")

    if scan_mode == "skill" and not YAML_AVAILABLE:
        print(f"{RED}[-] Error: PyYAML not available for skill scanning.{RESET}")
        print("Install with: pip install pyyaml")
        sys.exit(1)

    # Set default rule file based on mode
    if args.rule is None:
        args.rule = "skill_rules.nov" if scan_mode == "skill" else "my_rule.nov"

    # Set default output prefix based on mode
    if args.output_prefix is None:
        args.output_prefix = "skill_scan" if scan_mode == "skill" else "novaprox_scan"
    
    # Validate Nova requirements
    if args.nova_scan and not NOVA_AVAILABLE:
        print(f"{RED}[-] Error: Nova library not available for security scanning.{RESET}")
        print("Install with: pip install nova-hunting")
        sys.exit(1)

    if args.nova_scan and not os.path.exists(args.rule):
        print(f"{RED}[-] Error: Nova rule file not found: {args.rule}{RESET}")
        sys.exit(1)

    # Display header based on mode
    if scan_mode == "skill":
        print(f"\n--==[{BOLD}{GREEN} {TOOL_NAME} v{TOOL_VERSION} - Skills Scanner{RESET} - {CYAN}by {TOOL_AUTHOR}{RESET}]==--")
        print(f"\n🎯 {CYAN}Target: {args.skill}{RESET}")
        if args.skill_recursive:
            print(f"📁 {CYAN}Recursive: Enabled{RESET}")
    else:
        print(f"\n--==[{BOLD}{GREEN} {TOOL_NAME} v{TOOL_VERSION} - MCP Scanner{RESET} - {CYAN}by {TOOL_AUTHOR}{RESET}]==--")
        print(f"\n🎯 {CYAN}Target: {args.target}{RESET}")

    if args.nova_scan:
        print(f"🛡️ {YELLOW} NOVA Analysis: Enabled ({args.rule}){RESET}")
    print()

    try:
        if scan_mode == "skill":
            # Skill scanning mode
            with yaspin(text=" Scanning Agent Skills...", color="cyan") as spinner:
                await asyncio.sleep(0.1)
                verbose_mode = args.verbose or args.nova_scan

                def update_spinner(message):
                    spinner.text = message

                scan_results = await scan_skills(
                    target_path=args.skill,
                    verbose=verbose_mode,
                    spinner_callback=update_spinner,
                    recursive=args.skill_recursive
                )

                await asyncio.sleep(0.1)
                spinner.ok("[+]")

            if args.verbose:
                print(f"{CYAN}[DEBUG] Scan results summary:{RESET}")
                print(f"  Skills: {scan_results.get('total_skills', 0)}")
                print(f"  Security Flags: {len(scan_results.get('security_flags', []))}")

            nova_analysis = None

            if args.nova_scan:
                with yaspin(text=" Running NOVA analysis...",
                           color="yellow") as spinner:
                    try:
                        nova_evaluator = NovaEvaluator(
                            rule_file_path=args.rule,
                            evaluator_type=args.evaluator,
                            model=args.model,
                            api_key=args.api_key
                        )

                        analyzer = SkillNovaAnalyzer(nova_evaluator)

                        def progress_callback(current, total, item):
                            spinner.text = (f" Analyzing {current}/{total}: "
                                           f"{item[:30]}...")

                        nova_analysis = analyzer.analyze_skill_results(
                            scan_results,
                            progress_callback=progress_callback
                        )

                        flagged = nova_analysis['flagged_count']
                        total = nova_analysis['total_texts_analyzed']
                        spinner.ok(f"[+] NOVA analysis complete: "
                                  f"{flagged}/{total} items flagged")

                    except Exception as e:
                        spinner.fail(f"[-] NOVA analysis failed: {e}")
                        nova_analysis = None

            reporter = ProximityReporter(scan_results, nova_analysis, scan_mode="skill",
                                         full_output=args.full_output)
            reporter.display_skill_report()

            if args.json_report or args.md_report:
                with yaspin(text=" Generating reports...",
                           color="green") as spinner:

                    if args.json_report:
                        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                        json_filename = f"{args.output_prefix}_{timestamp}.json"
                        reporter.export_skill_json_report(json_filename)

                    if args.md_report:
                        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                        md_filename = f"{args.output_prefix}_{timestamp}.md"
                        reporter.export_skill_markdown_report(md_filename)

                    spinner.ok("[+]")

        else:
            # MCP scanning mode (original behavior)
            with yaspin(text=" Scanning MCP server...", color="cyan") as spinner:
                await asyncio.sleep(0.1)
                verbose_mode = args.verbose or args.nova_scan

                def update_spinner(message):
                    spinner.text = message

                scan_results = await scan_mcp_server(
                    target=args.target,
                    token=args.token,
                    timeout=args.timeout,
                    verbose=verbose_mode,
                    spinner_callback=update_spinner
                )

                await asyncio.sleep(0.1)
                spinner.ok("[+]")

            if args.verbose:
                print(f"{CYAN}[DEBUG] Scan results summary:{RESET}")
                print(f"  Tools: {len(scan_results.get('tools', []))}")
                print(f"  Prompts: {len(scan_results.get('prompts', []))}")
                print(f"  Resources: {len(scan_results.get('resources', []))}")
                print(f"  Capabilities: {scan_results.get('capabilities', {})}")

            nova_analysis = None

            if args.nova_scan:
                with yaspin(text=" Running NOVA analysis...",
                           color="yellow") as spinner:
                    try:
                        nova_evaluator = NovaEvaluator(
                            rule_file_path=args.rule,
                            evaluator_type=args.evaluator,
                            model=args.model,
                            api_key=args.api_key
                        )

                        analyzer = MCPNovaAnalyzer(nova_evaluator)

                        def progress_callback(current, total, item):
                            spinner.text = (f" Analyzing {current}/{total}: "
                                           f"{item[:30]}...")

                        nova_analysis = analyzer.analyze_mcp_results(
                            scan_results,
                            progress_callback=progress_callback
                        )

                        flagged = nova_analysis['flagged_count']
                        total = nova_analysis['total_texts_analyzed']
                        spinner.ok(f"[+] NOVA analysis complete: "
                                  f"{flagged}/{total} items flagged")

                    except Exception as e:
                        spinner.fail(f"[-] NOVA analysis failed: {e}")
                        nova_analysis = None

            reporter = ProximityReporter(scan_results, nova_analysis, scan_mode="mcp",
                                         full_output=args.full_output)
            reporter.display_console_report()

            if args.json_report or args.md_report:
                with yaspin(text=" Generating reports...",
                           color="green") as spinner:

                    if args.json_report:
                        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                        json_filename = f"{args.output_prefix}_{timestamp}.json"
                        reporter.export_json_report(json_filename)

                    if args.md_report:
                        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                        md_filename = f"{args.output_prefix}_{timestamp}.md"
                        reporter.export_markdown_report(md_filename)

                    spinner.ok("[+]")

        print(f"\n{GREEN}[+] {TOOL_NAME} scan completed successfully!{RESET}")

    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Scan interrupted by user{RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{RED}[-] Scan failed: {e}{RESET}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
