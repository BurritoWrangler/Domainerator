"""Session variables and command placeholder substitution.

Path-step commands are templates that contain placeholders an operator must
fill in before the command can run - the attacker's IP, a userlist file, a CA
name, etc. This module maps those placeholders to settable session variables
(Metasploit-style ``set LHOST 10.0.0.5``) and substitutes them into a command
string on demand.

Design notes
------------
- Placeholders are matched conservatively: we look for the well-known tokens
  that appear in the check/baseline command templates rather than trying to
  guess arbitrary variables. This avoids mangling real command text (e.g. a
  literal ``users.txt`` should only be replaced when the operator has set
  USERLIST).
- Target-derived values (host, domain, username, dc-ip) are auto-populated
  from the session's Target so an operator rarely needs to set them by hand.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Canonical variable names the console understands, each mapped to the literal
# placeholder token(s) that appear in command templates. When a variable is
# set, every listed token is replaced with the variable's value.
#
# Order matters for substitution: longer/more-specific tokens are replaced
# before shorter ones so that, e.g., "DC-IP" is handled before "DC".
PLACEHOLDER_MAP: dict[str, tuple[str, ...]] = {
    # Attacker-controlled listener (relay/coercion targets).
    "LHOST": ("ATTACKER-IP", "ATTACKER-HOST", "attacker@port"),
    # Files.
    "USERLIST": ("users.txt",),
    "PASSLIST": ("passwords.txt",),
    # Target-derived (auto-filled from Target, but overridable).
    "DC_IP": ("DC-IP",),
    "DC": ("DC",),
    "DOMAIN": ("DOMAIN",),
    "USER": ("USER",),
    "PASS": ("PASS",),
    # AD CS.
    "CA": ("CORP-CA", "CA-NAME", "CA_NAME"),
    "TEMPLATE": ("TEMPLATE-NAME", "TEMPLATE_NAME"),
    # Spray password.
    "SPRAY_PASSWORD": ("Season2025!",),
    # Relay orchestration: victim host to coerce (no placeholder token; used
    # by the 'relay' command directly, listed here so it shows in `options`).
    "RELAY_VICTIM": (),
}

# Reverse index: which variable owns a given placeholder token.
_TOKEN_TO_VAR: dict[str, str] = {}
for _var, _tokens in PLACEHOLDER_MAP.items():
    for _tok in _tokens:
        _TOKEN_TO_VAR[_tok] = _var


@dataclass
class Variables:
    """Operator-settable session variables for command substitution."""

    values: dict[str, str] = field(default_factory=dict)
    # Names whose current value came from auto-seeding a Target (not an
    # explicit ``set``). These are refreshed when the active target changes;
    # operator-set variables are never overwritten by a target switch.
    _auto: set[str] = field(default_factory=set)

    def set(self, name: str, value: str) -> None:
        key = name.upper()
        self.values[key] = value
        # An explicit set makes this variable operator-owned from now on.
        self._auto.discard(key)

    def unset(self, name: str) -> bool:
        """Remove a variable. Returns True if it existed."""
        key = name.upper()
        self._auto.discard(key)
        return self.values.pop(key, None) is not None

    def get(self, name: str) -> str | None:
        return self.values.get(name.upper())

    def seed_from_target(self, target) -> None:
        """Auto-populate variables from a Target where values are available.

        A variable is (re)filled from the target when it is unset or was itself
        previously auto-seeded, so switching the active target updates the
        target-derived values. A variable the operator set explicitly with
        ``set`` is treated as owned and is never overwritten.
        """
        mapping = {
            "DC": target.host,
            "DC_IP": target.dc_ip or target.host,
            "DOMAIN": target.domain,
            "USER": target.username,
            "PASS": target.password,
        }
        for name, value in mapping.items():
            if not value:
                continue
            if name not in self.values or name in self._auto:
                self.values[name] = value
                self._auto.add(name)

    def substitute(self, command: str) -> str:
        """Replace known placeholder tokens in ``command`` with set values.

        Tokens whose variable is unset are left intact so the operator can see
        what still needs filling. Longer tokens are substituted first to avoid
        partial clobbering (e.g. "DC-IP" before "DC").
        """
        result = command
        # Sort tokens by length descending for safe, non-overlapping replace.
        for token in sorted(_TOKEN_TO_VAR, key=len, reverse=True):
            var = _TOKEN_TO_VAR[token]
            value = self.values.get(var)
            if value is None:
                continue
            # Word-ish boundary replace: the placeholder tokens are distinctive
            # enough that a plain replace is safe, but we guard "DC"/"USER"/etc.
            # against matching inside larger words using a boundary regex.
            result = _boundary_replace(result, token, value)
        return result

    def missing_placeholders(self, command: str) -> list[str]:
        """Return the variable names whose placeholders remain unfilled.

        Used to warn the operator before running a command that still has
        template tokens the tool recognises but no value has been set for.
        """
        missing: list[str] = []
        for token, var in _TOKEN_TO_VAR.items():
            if var in missing:
                continue
            if self.values.get(var) is not None:
                continue
            if _token_present(command, token):
                missing.append(var)
        return missing

    def as_rows(self) -> list[tuple[str, str, str]]:
        """Return (name, value, placeholders) rows for display in `options`."""
        rows: list[tuple[str, str, str]] = []
        for name in sorted(PLACEHOLDER_MAP):
            value = self.values.get(name, "")
            tokens = ", ".join(PLACEHOLDER_MAP[name])
            rows.append((name, value, tokens))
        return rows


def _token_pattern(token: str) -> re.Pattern[str]:
    """Build a boundary-guarded regex for a placeholder token.

    The placeholder tokens contain characters like '-'/'@'/'!' that ``\\b``
    treats inconsistently, so we build an explicit guard. A token must not be
    flanked by an alphanumeric/underscore *or a hyphen* on either side. The
    hyphen guard stops the short token "DC" from matching inside "DC-IP"
    (which is owned by the DC_IP variable), while still replacing a standalone
    "DC" and not matching inside "DCSync".
    """
    return re.compile(
        r"(?<![A-Za-z0-9_-])" + re.escape(token) + r"(?![A-Za-z0-9_-])"
    )


def _boundary_replace(text: str, token: str, value: str) -> str:
    return _token_pattern(token).sub(lambda _m: value, text)


def _token_present(text: str, token: str) -> bool:
    return bool(_token_pattern(token).search(text))
