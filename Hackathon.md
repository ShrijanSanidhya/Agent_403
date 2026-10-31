# HACKATHON.md

## Team
**Team name:** 403

**Members:**
| Name | Roll No. |
|---|---|
| Shrijan Sanidhya | 2401010449 |
| Gourav Tanwar | 2401010173 |
| Alok Kumar | 2401010058 |

## Problem Statement
**Problem 03: Python Vulnerability Reachability Analyzer**

Security scanners flag every vulnerable dependency, even when the vulnerable
function is never used. We are building a tool that checks whether a known
vulnerable function in a Python dependency can actually be reached from a
project's own code.

Each finding is marked as:
- **Reachable**: with the call path as proof
- **Not affected**: with an OpenVEX statement
- **Uncertain**: for dynamic code (e.g. `getattr`, `importlib`) where we cannot be sure

## AI Models Used (in the product)
**Planned:** an open-weight code model running locally via Ollama,
starting with **Qwen2.5-Coder 7B** (`qwen2.5-coder:7b`).

The model reads security advisories and fix-commit diffs to identify
which functions are vulnerable.

We may switch to another open-weight model (e.g. Gemma or a model from
the organizers' model server) after testing. Any change will be made
through a pull request, and this file will be updated to match.

## Why this model
- **Open-weight and local**: no API keys or cloud services needed.
- **Built for code**: good at reading diffs and naming changed functions.
- **Laptop-friendly size**: 7B runs at usable speed on normal laptops.

The call-graph analysis is deterministic Python (`ast` module), so the
model is used only where it adds real value.

## AI Coding Assistants
Claude Code and Cursor, used to help write code. Each pull request names
the assistant(s) used for that change.
