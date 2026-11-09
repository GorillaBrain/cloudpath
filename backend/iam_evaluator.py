"""
AWS IAM Policy Semantics Evaluator for CloudPath.
Evaluates Allow vs. explicit Deny precedence, wildcard actions/resources,
privilege escalation combinations (iam:PassRole + compute execution, policy modification),
role assumption permissions, and conditional constraints.
"""

from __future__ import annotations
import fnmatch
from dataclasses import dataclass, field
from typing import Any


EXECUTION_ACTIONS = {
    "ec2:RunInstances",
    "lambda:CreateFunction",
    "lambda:UpdateFunctionConfiguration",
    "ecs:RunTask",
    "ecs:RegisterTaskDefinition",
    "glue:CreateDevEndpoint",
    "cloudformation:CreateStack",
    "sagemaker:CreateNotebookInstance",
}

POLICY_MODIFICATION_ACTIONS = {
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    "iam:AttachUserPolicy",
    "iam:AttachRolePolicy",
    "iam:AttachGroupPolicy",
    "iam:PutUserPolicy",
    "iam:PutRolePolicy",
    "iam:PutGroupPolicy",
    "iam:AddUserToGroup",
    "iam:UpdateAssumeRolePolicy",
    "iam:CreateAccessKey",
    "iam:CreateLoginProfile",
    "iam:UpdateLoginProfile",
}

ADMIN_WILDCARD_ACTIONS = {"*", "*:*", "iam:*"}


def _ensure_list(val: Any) -> list[str]:
    if val is None:
        return []
    if isinstance(val, str):
        return [val]
    if isinstance(val, list):
        return [str(v) for v in val]
    return [str(val)]


def _action_matches(pattern: str, target_action: str) -> bool:
    p = pattern.lower().strip()
    t = target_action.lower().strip()
    if p in ("*", "*:*"):
        return True
    return fnmatch.fnmatchcase(t, p)


def _resource_matches(pattern: str, target_resource: str) -> bool:
    p = pattern.strip()
    t = target_resource.strip()
    if p == "*" or t == "*":
        return True
    return fnmatch.fnmatchcase(t, p)


@dataclass
class EffectivePermissions:
    allowed_actions: list[str] = field(default_factory=list)
    explicitly_denied_actions: list[str] = field(default_factory=list)
    allowed_resources: dict[str, list[str]] = field(default_factory=dict)
    denied_resources: dict[str, list[str]] = field(default_factory=dict)
    has_wildcard_allow: bool = False
    has_wildcard_resource: bool = False
    is_admin_equivalent: bool = False
    can_pass_role: bool = False
    can_assume_role: bool = False
    can_escalate_via_passrole: bool = False
    can_modify_policies: bool = False
    escalation_primitives: list[str] = field(default_factory=list)
    excessive_permissions: list[str] = field(default_factory=list)
    conditions_present: bool = False
    statements_evaluated: list[dict[str, Any]] = field(default_factory=list)

    def is_action_allowed(self, action: str, resource: str = "*") -> bool:
        """
        Evaluate whether `action` on `resource` is allowed under AWS IAM evaluation logic:
        1. Explicit Deny in any applicable statement overrides all Allows.
        2. At least one Allow must match both the action and resource.
        """
        for denied_act, res_list in self.denied_resources.items():
            if _action_matches(denied_act, action):
                if any(_resource_matches(r, resource) for r in res_list):
                    return False

        for allowed_act, res_list in self.allowed_resources.items():
            if _action_matches(allowed_act, action):
                if any(_resource_matches(r, resource) for r in res_list):
                    return True

        return False


def evaluate_effective_permissions(statements: list[dict[str, Any]]) -> EffectivePermissions:
    """
    Evaluate a list of IAM policy statements (from attached and inline policies)
    and return an `EffectivePermissions` summary honoring explicit Deny precedence.
    """
    eff = EffectivePermissions(statements_evaluated=statements)

    for stmt in statements:
        if not isinstance(stmt, dict):
            continue
        effect = str(stmt.get("Effect", "Allow")).strip().capitalize()
        actions = _ensure_list(stmt.get("Action"))
        resources = _ensure_list(stmt.get("Resource", "*")) or ["*"]
        condition = stmt.get("Condition")
        if condition:
            eff.conditions_present = True

        if effect == "Deny":
            for act in actions:
                if act not in eff.explicitly_denied_actions:
                    eff.explicitly_denied_actions.append(act)
                eff.denied_resources.setdefault(act, []).extend(resources)
        elif effect == "Allow":
            for act in actions:
                if act not in eff.allowed_actions:
                    eff.allowed_actions.append(act)
                eff.allowed_resources.setdefault(act, []).extend(resources)
                if act in ("*", "*:*") or act.endswith(":*"):
                    eff.has_wildcard_allow = True
                    if act not in eff.excessive_permissions:
                        eff.excessive_permissions.append(act)
                if "*" in resources:
                    eff.has_wildcard_resource = True

    # Evaluate high-impact capabilities after applying explicit Deny precedence
    if eff.is_action_allowed("iam:CreateUser") and eff.is_action_allowed("s3:GetObject") and eff.is_action_allowed("ec2:RunInstances"):
        eff.is_admin_equivalent = True
    elif any(a in ADMIN_WILDCARD_ACTIONS for a in eff.allowed_actions) and not eff.explicitly_denied_actions:
        eff.is_admin_equivalent = True

    eff.can_pass_role = eff.is_action_allowed("iam:PassRole")
    eff.can_assume_role = eff.is_action_allowed("sts:AssumeRole")

    # Check iam:PassRole + Execution service escalation
    if eff.can_pass_role:
        for exec_act in sorted(EXECUTION_ACTIONS):
            if eff.is_action_allowed(exec_act):
                eff.can_escalate_via_passrole = True
                primitive = f"iam:PassRole + {exec_act}"
                if primitive not in eff.escalation_primitives:
                    eff.escalation_primitives.append(primitive)

    # Check Policy Modification / Self-Escalation primitives
    for mod_act in sorted(POLICY_MODIFICATION_ACTIONS):
        if eff.is_action_allowed(mod_act):
            eff.can_modify_policies = True
            if mod_act not in eff.escalation_primitives:
                eff.escalation_primitives.append(mod_act)
            if mod_act not in eff.excessive_permissions:
                eff.excessive_permissions.append(mod_act)

    return eff
