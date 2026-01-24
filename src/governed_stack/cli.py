#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""
Governed Stack CLI

HYPER-EXPERIMENTAL: API may change without notice.

Commands:
    governed-stack define <name> --controller <aid> [--stack <preset>]
    governed-stack check <said>
    governed-stack install <said> [--uv|--pip]
    governed-stack generate <said> [--pyproject|--requirements]
    governed-stack list
"""

import argparse
import json
import sys
from pathlib import Path

from governed_stack import (
    StackManager,
    get_stack_manager,
    KERI_PRODUCTION_STACK,
    KERI_DEV_STACK,
    KGQL_STACK,
    AI_ORCHESTRATOR_STACK,
    WITNESS_STACK,
    MINIMAL_STACK,
)


PRESET_STACKS = {
    "keri": KERI_PRODUCTION_STACK,
    "keri-dev": KERI_DEV_STACK,
    "kgql": KGQL_STACK,
    "ai-orchestrator": AI_ORCHESTRATOR_STACK,
    "witness": WITNESS_STACK,
    "minimal": MINIMAL_STACK,
}


def cmd_define(args):
    """Define a new governed stack."""
    sm = get_stack_manager()

    # Get constraints from preset or JSON file
    if args.stack:
        if args.stack in PRESET_STACKS:
            constraints = PRESET_STACKS[args.stack]
        else:
            # Try as JSON file
            try:
                constraints = json.loads(Path(args.stack).read_text())
            except Exception as e:
                print(f"Error loading constraints: {e}", file=sys.stderr)
                return 1
    else:
        constraints = MINIMAL_STACK

    stack = sm.define_stack(
        name=args.name,
        controller_aid=args.controller,
        constraints=constraints,
        rationale=args.rationale or "",
    )

    print(f"Defined stack: {stack.name}")
    print(f"  SAID: {stack.said}")
    print(f"  Controller: {stack.controller_aid}")
    print(f"  Constraints: {len(stack.constraints)}")

    for name, c in sorted(stack.constraints.items()):
        print(f"    {name}: {c.version_spec}")

    return 0


def cmd_check(args):
    """Check compliance with a stack."""
    sm = get_stack_manager()

    # Try SAID first, then name
    stack = sm.get_stack(args.said) or sm.get_stack_by_name(args.said)
    if not stack:
        print(f"Stack not found: {args.said}", file=sys.stderr)
        return 1

    result = sm.check_compliance(stack.said)

    print(f"Stack: {stack.name}")
    print(f"SAID: {stack.said}")
    print(f"Compliant: {'Yes' if result.compliant else 'No'}")
    print()

    for name, check in sorted(result.checks.items()):
        status = "✓" if check.compliant else "✗"
        installed = check.installed or "NOT INSTALLED"
        print(f"  [{status}] {name}: {installed} (requires {check.required})")
        if check.error:
            print(f"       Error: {check.error}")

    if result.missing:
        print(f"\nMissing: {', '.join(result.missing)}")
    if result.outdated:
        print(f"Outdated: {', '.join(result.outdated)}")

    return 0 if result.compliant else 1


def cmd_install(args):
    """Install stack dependencies."""
    sm = get_stack_manager()

    # Try SAID first, then name
    stack = sm.get_stack(args.said) or sm.get_stack_by_name(args.said)
    if not stack:
        print(f"Stack not found: {args.said}", file=sys.stderr)
        return 1

    print(f"Installing stack: {stack.name} ({stack.said[:20]}...)")

    if args.pip:
        success, output = sm.install_with_pip(stack.said, upgrade=args.upgrade)
    else:
        success, output = sm.install_with_uv(stack.said, upgrade=args.upgrade)

    if success:
        print("Installation successful!")
    else:
        print(f"Installation failed:\n{output}", file=sys.stderr)

    return 0 if success else 1


def cmd_generate(args):
    """Generate pyproject.toml or requirements.txt."""
    sm = get_stack_manager()

    # Try SAID first, then name
    stack = sm.get_stack(args.said) or sm.get_stack_by_name(args.said)
    if not stack:
        print(f"Stack not found: {args.said}", file=sys.stderr)
        return 1

    if args.requirements:
        output = sm.generate_requirements(stack.said)
    else:
        output = sm.generate_pyproject(stack.said)

    if args.output:
        Path(args.output).write_text(output)
        print(f"Written to {args.output}")
    else:
        print(output)

    return 0


def cmd_list(args):
    """List all defined stacks."""
    sm = get_stack_manager()
    stacks = sm.list_stacks()

    if not stacks:
        print("No stacks defined.")
        print("\nDefine a stack with:")
        print("  governed-stack define my-project --controller <AID> --stack keri")
        return 0

    print(f"Defined stacks ({len(stacks)}):\n")
    for stack in sorted(stacks, key=lambda s: s.name):
        print(f"  {stack.name}")
        print(f"    SAID: {stack.said[:30]}...")
        print(f"    Controller: {stack.controller_aid[:30]}...")
        print(f"    Constraints: {len(stack.constraints)}")
        print()

    return 0


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Governed Stack - KERI-governed dependency management",
        epilog="HYPER-EXPERIMENTAL: API may change without notice.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="governed-stack 0.1.0 (HYPER-EXPERIMENTAL)",
    )

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # define
    p_define = subparsers.add_parser("define", help="Define a governed stack")
    p_define.add_argument("name", help="Stack name")
    p_define.add_argument("--controller", "-c", required=True, help="Controller AID")
    p_define.add_argument(
        "--stack", "-s",
        help=f"Preset stack or JSON file. Presets: {', '.join(PRESET_STACKS.keys())}",
    )
    p_define.add_argument("--rationale", "-r", help="Rationale for these constraints")
    p_define.set_defaults(func=cmd_define)

    # check
    p_check = subparsers.add_parser("check", help="Check compliance")
    p_check.add_argument("said", help="Stack SAID or name")
    p_check.set_defaults(func=cmd_check)

    # install
    p_install = subparsers.add_parser("install", help="Install dependencies")
    p_install.add_argument("said", help="Stack SAID or name")
    p_install.add_argument("--uv", action="store_true", help="Use UV (default)")
    p_install.add_argument("--pip", action="store_true", help="Use pip instead of UV")
    p_install.add_argument("--upgrade", "-U", action="store_true", help="Upgrade packages")
    p_install.set_defaults(func=cmd_install)

    # generate
    p_gen = subparsers.add_parser("generate", help="Generate pyproject.toml or requirements.txt")
    p_gen.add_argument("said", help="Stack SAID or name")
    p_gen.add_argument("--pyproject", action="store_true", help="Generate pyproject.toml (default)")
    p_gen.add_argument("--requirements", action="store_true", help="Generate requirements.txt")
    p_gen.add_argument("--output", "-o", help="Output file (default: stdout)")
    p_gen.set_defaults(func=cmd_generate)

    # list
    p_list = subparsers.add_parser("list", help="List defined stacks")
    p_list.set_defaults(func=cmd_list)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
