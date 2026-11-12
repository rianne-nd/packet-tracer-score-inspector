#!/usr/bin/env python3
"""PKA Score Inspector - read a Packet Tracer activity's grading key and
generate the IOS commands that satisfy it.

Everything here is deterministic Python: no AI, no network access, no
third-party Python packages. The only native piece is the Twofish library
that ships with the decoder.

Usage:
    python pka_score.py <activity.pka|.pkt> [options]

Options:
    --mode {score,commands,all}   skip the interactive menu
    --outdir DIR                  where to create <name>_report
    --no-pause                    never wait for Enter (scripting)
    --quiet                       write files without console output
"""
from __future__ import annotations

import argparse
import difflib
import os
import re
import shutil
import sys
import textwrap
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

APP_NAME = "PKA Score Inspector"
APP_VERSION = "1.0.0"
WIDTH = 78

HERE = Path(__file__).resolve().parent


# --------------------------------------------------------------------------
# Console helpers
# --------------------------------------------------------------------------
def _ansi_ok() -> bool:
    if "NO_COLOR" in os.environ:
        return False
    if not sys.stdout.isatty():
        return False
    if os.name == "nt":
        try:
            import ctypes

            handle = ctypes.windll.kernel32.GetStdHandle(-11)
            ctypes.windll.kernel32.SetConsoleMode(handle, 7)
        except Exception:
            return False
    return True


_COLOR = _ansi_ok()


class C:
    RESET = "\033[0m" if _COLOR else ""
    BOLD = "\033[1m" if _COLOR else ""
    DIM = "\033[2m" if _COLOR else ""
    CYAN = "\033[36m" if _COLOR else ""
    GREEN = "\033[32m" if _COLOR else ""
    YELLOW = "\033[33m" if _COLOR else ""
    RED = "\033[31m" if _COLOR else ""


def heading(text: str) -> None:
    print()
    print(f"{C.BOLD}{'=' * WIDTH}{C.RESET}")
    print(f" {C.BOLD}{text}{C.RESET}")
    print(f"{C.BOLD}{'=' * WIDTH}{C.RESET}")


def section(text: str) -> None:
    print()
    print(f"{C.CYAN}{'-' * WIDTH}{C.RESET}")
    print(f" {C.BOLD}{text}{C.RESET}")
    print(f"{C.CYAN}{'-' * WIDTH}{C.RESET}")


def wrap(text: str, indent: int = 2, width: int = WIDTH) -> str:
    return textwrap.fill(
        " ".join(text.split()),
        width=width,
        initial_indent=" " * indent,
        subsequent_indent=" " * indent,
    )


def print_two_col(left: str, right: str, left_width: int = 44, indent: str = "    ") -> None:
    if len(left) <= left_width:
        prefix = f"{indent}{left:<{left_width}}  "
        chunks = textwrap.wrap(right, width=max(20, WIDTH - len(prefix))) or [""]
        print(prefix + chunks[0])
        for chunk in chunks[1:]:
            print(" " * len(prefix) + chunk)
    else:
        print(f"{indent}{left}")
        prefix = " " * (len(indent) + left_width + 2)
        for chunk in textwrap.wrap(right, width=max(20, WIDTH - len(prefix))):
            print(prefix + chunk)


def human_size(n: int) -> str:
    size = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            if unit == "B":
                return f"{size:.0f} {unit}"
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GB"


def pause() -> None:
    try:
        input(f"\n  {C.DIM}Press Enter to close...{C.RESET}")
    except (EOFError, KeyboardInterrupt):
        print()


class ToolError(Exception):
    """A problem we can explain to the user without a traceback."""


# --------------------------------------------------------------------------
# Locate and import the decryptor
# --------------------------------------------------------------------------
_DECODER = None


def _load_decoder():
    global _DECODER
    if _DECODER is not None:
        return _DECODER

    candidates = [
        HERE / "vendor",
        HERE / "cisco-pka-to-xml",
        HERE,
        HERE.parent / "vendor",
        HERE.parent / "cisco-pka-to-xml",
        HERE.parent,
    ]
    found = None
    for d in candidates:
        if (d / "pka2xml" / "__init__.py").exists():
            found = d
            sys.path.insert(0, str(d))
            break
    if found is None:
        raise ToolError(
            "Could not find the pka2xml decoder.\n"
            "  Expected it in: vendor/pka2xml/ next to this script.\n"
            "  If you cloned the project, make sure the vendor folder is present."
        )

    try:
        import pka2xml  # type: ignore

        _DECODER = (pka2xml.decrypt_pka, pka2xml.PkaError)
    except Exception as exc:
        raise ToolError(
            "Could not load the pka2xml decoder.\n"
            f"  Location: {found}\n"
            f"  Detail  : {exc}\n"
            "  On Windows the vendored libtwofish.dll must sit next to "
            "pka2xml/__init__.py."
        ) from exc
    return _DECODER


# --------------------------------------------------------------------------
# Decode + sanitise
# --------------------------------------------------------------------------
def decode_file(path: Path) -> str:
    decrypt_pka, pka_error = _load_decoder()
    try:
        raw = decrypt_pka(path.read_bytes())
    except pka_error as exc:
        raise ToolError(f"Could not decrypt {path.name}: {exc}") from exc
    text = raw.decode("utf-8", errors="replace")
    # Packet Tracer stores a few raw binary bytes inside attributes (the
    # activity password blob). Strip characters that are illegal in XML.
    return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", text)


def parse_xml(text: str) -> ET.Element:
    try:
        return ET.fromstring(text)
    except ET.ParseError:
        # Fall back: keep only the two sections we need.
        chunks = []
        for tag in ("COMPARISONS", "PACKETTRACER5_ACTIVITY"):
            m = re.search(rf"<{tag}[ >].*?</{tag}>", text, re.S)
            if m:
                chunks.append(m.group(0))
        for chunk in chunks:
            try:
                return ET.fromstring(chunk)
            except ET.ParseError:
                continue
        raise ToolError("Could not parse the decrypted XML.")


# --------------------------------------------------------------------------
# Grading tree
# --------------------------------------------------------------------------
class Check:
    __slots__ = ("section", "path", "points", "component", "value")

    def __init__(self, section, path, points, component, value):
        self.section = section
        self.path = path
        self.points = points
        self.component = component
        self.value = value

    @property
    def name(self) -> str:
        return self.path[-1] if self.path else ""


def _pts(node) -> int:
    text = (node.findtext("POINTS") or "").strip()
    return int(text) if text.isdigit() else 0


def collect_checks(root: ET.Element):
    comp = root.find(".//COMPARISONS")
    if comp is None:
        return [], []

    sections = []
    checks = []
    top = comp.find("NODE")
    if top is None:
        return [], []

    for sec in [c for c in top if c.tag == "NODE"]:
        sec_name = (sec.findtext("NAME") or "").strip()
        sections.append(sec_name)

        def walk(node, parents):
            kids = [c for c in node if c.tag == "NODE"]
            name = (node.findtext("NAME") or "").strip()
            path = parents + [name]
            if kids:
                for kid in kids:
                    walk(kid, path)
                return
            points = _pts(node)
            if points <= 0:
                return
            name_node = node.find("NAME")
            value = name_node.attrib.get("nodeValue", "") if name_node is not None else ""
            component = (node.findtext("COMPONENTS") or "").strip()
            checks.append(Check(sec_name, path, points, component, value))

        walk(sec, [])

    return sections, checks


class Analysis:
    def __init__(self, root: ET.Element, pka: Path, version: str):
        self.pka = pka
        self.version = version
        self.sections, self.checks = collect_checks(root)
        self.total = sum(c.points for c in self.checks)
        self.by_comp = {}
        self.by_sec = {}
        for check in self.checks:
            self.by_comp[check.component] = (
                self.by_comp.get(check.component, 0) + check.points
            )
            self.by_sec[check.section] = self.by_sec.get(check.section, 0) + check.points


# --------------------------------------------------------------------------
# Running configs / snapshots
# --------------------------------------------------------------------------
class Device:
    __slots__ = ("name", "model", "lines")

    def __init__(self, name, model, lines):
        self.name = name
        self.model = model
        self.lines = lines


def collect_snapshots(root: ET.Element):
    snapshots = []
    for block in root.iter("PACKETTRACER5"):
        devices = {}
        for dev in block.iter("DEVICE"):
            engine = dev.find("ENGINE")
            if engine is None:
                continue
            name = (engine.findtext("NAME") or "").strip()
            type_node = engine.find("TYPE")
            model = type_node.attrib.get("model", "") if type_node is not None else ""
            running = engine.find("RUNNINGCONFIG")
            lines = []
            if running is not None:
                lines = [
                    line.text if line.text is not None else ""
                    for line in running.findall("LINE")
                ]
            devices[name] = Device(name, model, lines)
        if devices:
            snapshots.append(devices)
    return snapshots


def collect_endpoint_settings(root: ET.Element):
    """IP / mask / gateway for PCs, servers, switches (last snapshot wins)."""
    out = {}
    snapshots = list(root.iter("PACKETTRACER5"))
    if not snapshots:
        return out
    for dev in snapshots[-1].iter("DEVICE"):
        engine = dev.find("ENGINE")
        if engine is None:
            continue
        name = (engine.findtext("NAME") or "").strip()
        type_node = engine.find("TYPE")
        model = type_node.attrib.get("model", "") if type_node is not None else ""
        if not model:
            continue
        info = {"model": model, "ports": []}
        gateway = (engine.findtext("GATEWAY") or "").strip()
        index = 0
        for port in engine.iter("PORT"):
            port_ip = (port.findtext("IP") or "").strip()
            if port_ip in ("", "0.0.0.0"):
                index += 1
                continue
            index += 1
            label = {1: "FastEthernet0", 2: "Bluetooth"}.get(index, f"Port {index}")
            info["ports"].append(
                {
                    "name": label,
                    "ip": port_ip,
                    "mask": (port.findtext("SUBNET") or "").strip(),
                    "gw": (port.findtext("PORT_GATEWAY") or "").strip() or gateway,
                }
            )
        if info["ports"]:
            out[name] = info
    return out


def collect_pdus(root: ET.Element):
    ref = {}
    for dev in root.iter("DEVICE"):
        engine = dev.find("ENGINE")
        if engine is None:
            continue
        name = (engine.findtext("NAME") or "").strip()
        for tag in ("SAVE_REF_ID", "ID"):
            value = engine.findtext(tag)
            if value:
                ref[value.strip()] = name
        for key, value in engine.attrib.items():
            if "ref" in key.lower():
                ref[value] = name

    pdus = []
    for scenario in root.iter("SCENARIO"):
        for pdu in scenario.findall("PDU"):
            src = (pdu.findtext("SOURCE") or "").strip()
            dest = pdu.find("DESTINATION")
            dst = dest.attrib.get("device", "") if dest is not None else ""
            ip_node = pdu.find(".//DSTADDR")
            dst_ip = (ip_node.text or "").strip() if ip_node is not None else ""
            points_text = pdu.findtext("POINTS") or "0"
            pdus.append(
                {
                    "src": ref.get(src, src),
                    "dst": ref.get(dst, dst),
                    "dstip": dst_ip,
                    "points": int(points_text) if points_text.strip().isdigit() else 0,
                }
            )
    return pdus


def snapshot_match_score(snapshot, checks) -> int:
    """How many graded expected values are present in this snapshot's configs.

    This is a much better signal than "which snapshot changed the most",
    because Packet Tracer does not guarantee that the starting config is the
    first snapshot. Some activities store the answer first and the blank
    starting config later.
    """
    blobs = {
        name: "\n".join(" ".join(line.split()).lower() for line in dev.lines)
        for name, dev in snapshot.items()
    }
    score = 0
    for check in checks:
        if not check.value:
            continue
        value = " ".join(check.value.split()).lower()
        # Skip tiny values like "0" / "1": they match almost anything.
        if len(value) < 4 or value.isdigit():
            continue
        section = check.section.split(":")[0]
        blob = blobs.get(section)
        if blob and value in blob:
            score += check.points
    return score


def snapshot_size(snapshot) -> int:
    """Number of real config lines in a snapshot (used to break ties)."""
    return sum(
        len(
            [
                line
                for line in dev.lines
                if line.strip() and line.strip() not in ("!", "end")
            ]
        )
        for dev in snapshot.values()
    )


def pick_snapshots(snapshots, checks):
    """Return (start_index, answer_index).

    The answer is the snapshot that matches the most expected values from the
    grading tree. The start is the snapshot that matches the fewest.
    """
    if len(snapshots) < 2:
        return 0, 0

    if not checks:
        # No grading tree: fall back to "the snapshot that differs the most".
        def diff_score(base, other):
            total = 0
            for name, dev in other.items():
                old = base.get(name)
                if old is None:
                    total += 1000
                    continue
                total += len(set(dev.lines) - set(old.lines))
            return total

        answer = max(
            range(1, len(snapshots)),
            key=lambda i: diff_score(snapshots[0], snapshots[i]),
        )
        return 0, answer

    scores = [snapshot_match_score(snapshot, checks) for snapshot in snapshots]
    sizes = [snapshot_size(snapshot) for snapshot in snapshots]
    start_idx = min(
        range(len(snapshots)),
        key=lambda i: (scores[i], i),
    )
    candidates = [i for i in range(len(snapshots)) if i != start_idx]
    answer_idx = max(
        candidates,
        key=lambda i: (scores[i], sizes[i], -i),
    )
    return start_idx, answer_idx


# --------------------------------------------------------------------------
# Config -> commands
# --------------------------------------------------------------------------
NOISE = ("!", "end")
CONFIG_NOISE_PREFIXES = (
    "version ",
    "Building configuration",
    "Current configuration",
)


def parse_config(lines):
    """Return ordered list of ('global', cmd) / ('section', header, subs)."""
    entries = []
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i].rstrip()
        stripped = line.strip()
        if (
            stripped in NOISE
            or stripped == ""
            or stripped.startswith(CONFIG_NOISE_PREFIXES)
        ):
            i += 1
            continue
        if not line[:1].isspace():
            j = i + 1
            subs = []
            while j < n and (lines[j][:1].isspace() or lines[j].strip() in ("!", "")):
                if lines[j].strip() not in ("!", ""):
                    subs.append(lines[j].rstrip())
                j += 1
            if subs:
                entries.append(("section", stripped, subs))
            else:
                entries.append(("global", stripped))
            i = j
        else:
            entries.append(("global", stripped))
            i += 1
    return entries


# Settings that must be actively undone when the answer no longer has them.
RE_ENABLE = {
    "no cdp run": "cdp run",
    "no ip domain-lookup": "ip domain-lookup",
    "no ip routing": "ip routing",
    "no ipv6 unicast-routing": "ipv6 unicast-routing",
    "no service password-encryption": "service password-encryption",
    "shutdown": "no shutdown",
}

SAFE_NEGATE_EXACT = {
    "shutdown": "no shutdown",
    "no shutdown": "shutdown",
}

SAFE_NEGATE_PREFIXES = (
    "ip address ",
    "ipv6 address ",
    "ip route ",
    "ip default-gateway ",
    "ip nat ",
    "access-list ",
    "switchport access vlan ",
    "switchport trunk ",
    "channel-group ",
    "encapsulation ",
    "description ",
    "ip helper-address ",
    "default-router ",
    "dns-server ",
    "network ",
    "passive-interface ",
    "ip access-group ",
)


def negate(line: str):
    """Best-effort 'no' form for a config line, or None if unsafe."""
    if line in SAFE_NEGATE_EXACT:
        return SAFE_NEGATE_EXACT[line]
    if line.startswith("no "):
        # Only re-enable settings that have a meaningful positive form.
        # e.g. "no ip address" must NOT become a bare "ip address".
        return RE_ENABLE.get(line)
    if line.startswith(SAFE_NEGATE_PREFIXES):
        return "no " + line
    return None


def build_commands(start_lines, answer_lines) -> str:
    """Emit only what is missing or changed in the starting config."""
    start = parse_config(start_lines)
    answer = parse_config(answer_lines)

    start_globals = [e[1] for e in start if e[0] == "global"]
    start_sections = {e[1]: e[2] for e in start if e[0] == "section"}

    body = []
    for entry in answer:
        if entry[0] == "global":
            if entry[1] not in start_globals:
                body.append(entry[1])
            continue

        header, subs = entry[1], entry[2]
        old = start_sections.get(header)
        if old is None:
            body.append(header)
            body.extend(subs)
            body.append("exit")
            continue

        old_norm = [s.strip() for s in old]
        new_norm = [s.strip() for s in subs]
        if old_norm == new_norm:
            continue

        body.append(header)
        for old_line in old_norm:
            if old_line and old_line not in new_norm:
                negated = negate(old_line)
                if negated:
                    body.append(" " + negated)
        body.extend(subs)
        body.append("exit")

    # Global settings that the answer removed.
    answer_globals = {e[1] for e in answer if e[0] == "global"}
    for global_line in start_globals:
        if global_line in answer_globals:
            continue
        if global_line in RE_ENABLE:
            body.append(RE_ENABLE[global_line])
        else:
            negated = negate(global_line)
            if negated:
                body.append(negated)

    if not body:
        return ""

    out = ["enable", "configure terminal"]
    out.extend(body)
    out.extend(["end", "write memory"])
    return "\n".join(out)


def config_delta(start_lines, answer_lines):
    """Added / removed config lines (ignoring '!' noise)."""
    added, removed = [], []
    for line in difflib.unified_diff(start_lines, answer_lines, lineterm="", n=0):
        if line.startswith(("+++", "---", "@@")):
            continue
        if line.startswith("+"):
            text = line[1:].strip()
            if text and text != "!":
                added.append(text)
        elif line.startswith("-"):
            text = line[1:].strip()
            if text and text != "!":
                removed.append(text)
    return added, removed


# --------------------------------------------------------------------------
# Plain-English explanations for the generated commands
# --------------------------------------------------------------------------
_EXPLAIN_RULES = [
    (r"^enable$", "enter privileged EXEC mode"),
    (r"^configure terminal$", "enter global configuration mode"),
    (r"^end$", "leave configuration mode"),
    (r"^write memory$", "save the running config to NVRAM"),
    (r"^exit$", "close this config block"),
    (r"^hostname (\S+)$", "set the device name to {0}"),
    (r"^interface range (.+)$", "open a config block for several interfaces ({0})"),
    (r"^interface (.+)$", "open the {0} config block"),
    (r"^ip address (\S+) (\S+)$", "assign {0} {1} to the interface (IP addressing checks)"),
    (r"^ip address dhcp$", "obtain the interface address from DHCP"),
    (r"^ipv6 address (\S+)$", "assign IPv6 address {0}"),
    (r"^ip route (\S+) (\S+) (\S+)$", "static route: reach {0}/{1} via {2} (routing checks)"),
    (r"^ip default-gateway (\S+)$", "management default gateway = {0} (Default Gateway check)"),
    (r"^ip default-network (\S+)$", "mark {0} as a default network"),
    (r"^ip routing$", "enable Layer-3 routing"),
    (r"^no ip routing$", "disable Layer-3 routing"),
    (r"^ip domain-lookup$", "enable DNS lookups for commands"),
    (r"^no ip domain-lookup$", "stop DNS lookups for mistyped commands"),
    (r"^ip domain-name (\S+)$", "set the DNS domain to {0}"),
    (r"^router ospf (\S+)$", "start OSPF process {0} (routing checks)"),
    (r"^router eigrp (\S+)$", "start EIGRP AS {0} (routing checks)"),
    (r"^router rip$", "start RIP (routing checks)"),
    (r"^network (\S+) (\S+) area (\S+)$", "advertise {0} {1} in OSPF area {2}"),
    (r"^network (\S+) (\S+)$", "add {0} {1} to the routing/DHCP network"),
    (r"^passive-interface (\S+)$", "do not send routing updates out {0}"),
    (r"^default-information originate$", "advertise the default route in this routing protocol"),
    (r"^access-list (\S+) (.+)$", "ACL {0}: {1} (ACL checks)"),
    (r"^ip access-list (\S+) (\S+)$", "edit {0} ACL {1} (ACL checks)"),
    (r"^(permit|deny) (.+)$", "ACL rule: {0} {1}"),
    (r"^ip access-group (\S+) (in|out)$", "apply ACL {0} {1}bound on the interface"),
    (r"^ip nat inside$", "mark the interface as NAT inside (NAT checks)"),
    (r"^ip nat outside$", "mark the interface as NAT outside (NAT checks)"),
    (r"^ip nat inside source list (\S+) interface (\S+)( overload)?$", "PAT: translate ACL {0} to interface {1} (NAT checks)"),
    (r"^ip nat inside source list (\S+) pool (\S+)( overload)?$", "translate ACL {0} using NAT pool {1}"),
    (r"^ip nat inside source static (\S+) (\S+)$", "static NAT: {0} <-> {1}"),
    (r"^ip nat pool (\S+) (\S+) (\S+) netmask (\S+)$", "define NAT pool {0}: {1} - {2} / {3}"),
    (r"^cdp run$", "enable CDP globally (CDP Enabled check)"),
    (r"^no cdp run$", "disable CDP globally"),
    (r"^cdp enable$", "enable CDP on the interface"),
    (r"^vlan (\S+)$", "create VLAN {0} (VLAN checks)"),
    (r"^name (\S+)$", "name the VLAN {0}"),
    (r"^switchport mode (\S+)$", "set the port to {0} mode"),
    (r"^switchport access vlan (\S+)$", "put the port in VLAN {0}"),
    (r"^switchport trunk (.*)$", "trunk setting: {0}"),
    (r"^switchport port-security(.*)$", "port-security setting{0}"),
    (r"^channel-group (\S+) mode (\S+)$", "add the port to EtherChannel {0} ({1})"),
    (r"^spanning-tree (.*)$", "spanning-tree setting: {0}"),
    (r"^ip helper-address (\S+)$", "forward DHCP broadcasts to {0}"),
    (r"^ip dhcp pool (\S+)$", "create DHCP pool {0}"),
    (r"^default-router (\S+)$", "DHCP default gateway = {0}"),
    (r"^dns-server (.+)$", "DHCP DNS server(s): {0}"),
    (r"^username (\S+) .*$", "create local user {0}"),
    (r"^enable (secret|password) .*$", "set the privileged-mode password"),
    (r"^service password-encryption$", "encrypt plaintext passwords in the config"),
    (r"^banner (motd|login) .*$", "set the login banner"),
    (r"^line (con|vty|aux) (.+)$", "open the {0} line block ({1})"),
    (r"^password .*$", "set the line password"),
    (r"^login( local)?$", "require login on these lines"),
    (r"^transport input (.+)$", "allow {0} on the VTY lines"),
    (r"^exec-timeout .*$", "set the idle timeout"),
    (r"^logging synchronous$", "keep console messages from breaking typed commands"),
    (r"^crypto (.*)$", "IPsec/ISAKMP setting: {0}"),
    (r"^tunnel (source|destination|mode) (.*)$", "tunnel {0}: {1}"),
    (r"^ipsec (.*)$", "IPsec setting: {0}"),
    (r"^ntp (.*)$", "NTP setting: {0}"),
    (r"^snmp-server (.*)$", "SNMP setting: {0}"),
    (r"^aaa (.*)$", "AAA setting: {0}"),
    (r"^ip ssh (.*)$", "SSH setting: {0}"),
    (r"^ipv6 unicast-routing$", "enable IPv6 routing"),
    (r"^ip cef$", "enable Cisco Express Forwarding"),
    (r"^vtp (.*)$", "VTP setting: {0}"),
    (r"^description (.+)$", "set the interface description to {0}"),
    (r"^speed (\S+)$", "force link speed {0}"),
    (r"^duplex (\S+)$", "force duplex {0}"),
    (r"^clock rate (\S+)$", "set the serial clock rate to {0} (DCE side)"),
    (r"^encapsulation (\S+)(.*)$", "set encapsulation {0}{1}"),
    (r"^no shutdown$", "bring the interface/port up (Physical checks)"),
    (r"^shutdown$", "administratively disable the interface"),
    (r"^no (.*)$", "remove the '{0}' setting"),
]


def explain_command(line: str) -> str:
    text = line.strip()
    for pattern, note in _EXPLAIN_RULES:
        match = re.match(pattern, text)
        if match:
            groups = tuple(g if g is not None else "" for g in match.groups())
            try:
                return note.format(*groups)
            except (IndexError, KeyError):
                return note
    return "required by the answer configuration"


# --------------------------------------------------------------------------
# Reporting helpers
# --------------------------------------------------------------------------
COMP_LABEL = {"Ip": "IP", "Acl": "ACL", "Nat": "NAT"}

KEY_NAMES = {
    "IP Address",
    "Subnet Mask",
    "Default Gateway",
    "Source",
    "Destination",
    "Port Status",
    "Port Up",
    "CDP Enabled",
    "VLAN Number",
    "VLAN Name",
}
SKIP_PATH = (
    "Entire Config",
    "LINES",
    "Startup Configuration",
    "Running Configuration",
)


def is_key_check(check: Check) -> bool:
    if any(s in "/".join(check.path) for s in SKIP_PATH):
        return False
    return check.points >= 2 or check.name in KEY_NAMES


def fmt_value(value: str, limit: int = 64) -> str:
    if not value:
        return ""
    text = " ".join(value.split())
    if len(text) > limit:
        text = text[: limit - 3] + "..."
    return text


def fmt_check(check: Check) -> str:
    parts = check.path[1:] if len(check.path) > 1 else check.path
    path = " / ".join(parts)
    label = COMP_LABEL.get(check.component, check.component)
    value = fmt_value(check.value)
    suffix = f"   ->  {value}" if value else ""
    return f"{check.points:>2}p [{label:<9}] {path}{suffix}"


def write_file(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text.rstrip() + "\n", encoding="utf-8")


def reset_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


# --------------------------------------------------------------------------
# Scoring files + console output
# --------------------------------------------------------------------------
def write_scoring_files(scoring_dir: Path, analysis: Analysis):
    all_lines = [
        f"Packet Tracer scoring report - {analysis.pka.name}",
        f"PT file version: {analysis.version}",
        f"Total graded points: {analysis.total:,}",
        f"Total individual checks: {len(analysis.checks):,}",
        "",
        "Points by category:",
    ]
    for label, value in sorted(analysis.by_comp.items(), key=lambda kv: -kv[1]):
        all_lines.append(f"  {COMP_LABEL.get(label, label):<10} {value:,}")
    all_lines.append("")
    all_lines.append("Points by device / section:")
    for label, value in sorted(analysis.by_sec.items(), key=lambda kv: -kv[1]):
        all_lines.append(f"  {label:<28} {value:,}")
    all_lines.append("")
    all_lines.append("=" * 78)
    all_lines.append("ALL CHECKS THAT AWARD POINTS")
    all_lines.append("=" * 78)
    for sec in analysis.sections:
        sec_checks = [c for c in analysis.checks if c.section == sec]
        if not sec_checks:
            continue
        all_lines.append("")
        all_lines.append(
            f"### {sec}  ({sum(c.points for c in sec_checks):,} pts, "
            f"{len(sec_checks):,} checks)"
        )
        for check in sec_checks:
            all_lines.append(fmt_check(check))

    key_lines = [
        f"KEY SCORING CHECKS - {analysis.pka.name}",
        "(2+ point checks, plus the important addressing / gateway / CDP checks)",
        f"Total points in activity: {analysis.total:,}",
        "",
    ]
    for sec in analysis.sections:
        sec_checks = [
            c for c in analysis.checks if c.section == sec and is_key_check(c)
        ]
        if not sec_checks:
            continue
        key_lines.append("")
        key_lines.append(f"### {sec}")
        for check in sec_checks:
            key_lines.append(fmt_check(check))

    all_path = scoring_dir / "scoring_all.txt"
    key_path = scoring_dir / "scoring_key.txt"
    write_file(all_path, "\n".join(all_lines))
    write_file(key_path, "\n".join(key_lines))
    return [all_path, key_path]


def print_scoring(analysis: Analysis, full_path: Path, key_path: Path) -> None:
    heading("SCORING CRITERIA")
    if not analysis.checks:
        print(
            wrap(
                "This file has no grading tree. It is probably a plain topology "
                "(.pkt) rather than a graded activity, so there is nothing to score."
            )
        )
        return
    print(f"  File          : {analysis.pka.name}")
    print(f"  PT version    : {analysis.version}")
    print(f"  Graded points : {analysis.total:,}")
    print(f"  Checks        : {len(analysis.checks):,}")
    print()
    print(
        wrap(
            "Packet Tracer keeps a grading tree inside the activity. Every leaf "
            "of that tree is one check with a point value and an expected value "
            "(the answer key). Packet Tracer adds the points you earn and turns "
            "the total into a percentage, so a 5-point check matters more than "
            "a 1-point check."
        )
    )

    section("POINTS BY CATEGORY")
    rows = sorted(analysis.by_comp.items(), key=lambda kv: -kv[1])
    max_value = max((v for _, v in rows), default=1) or 1
    for label, value in rows:
        pct = value / analysis.total * 100 if analysis.total else 0
        bar = "#" * int(round(value / max_value * 30))
        print(
            f"  {COMP_LABEL.get(label, label):<10} {value:>7,}  "
            f"{pct:>5.1f}%  {bar}"
        )

    section("POINTS BY DEVICE / SECTION")
    rows = sorted(analysis.by_sec.items(), key=lambda kv: -kv[1])
    max_value = max((v for _, v in rows), default=1) or 1
    for label, value in rows:
        pct = value / analysis.total * 100 if analysis.total else 0
        bar = "#" * int(round(value / max_value * 30))
        print(
            f"  {label:<26} {value:>7,}  {pct:>5.1f}%  {bar}"
        )

    section("KEY CHECKS (2+ points, plus addressing / gateway / CDP)")
    key_count = 0
    key_points = 0
    for sec in analysis.sections:
        sec_checks = [c for c in analysis.checks if c.section == sec]
        key = [c for c in sec_checks if is_key_check(c)]
        if not key:
            continue
        key_count += len(key)
        key_points += sum(c.points for c in key)
        print()
        print(
            f"  {C.BOLD}{sec}{C.RESET}  "
            f"({sum(c.points for c in sec_checks):,} pts, "
            f"{len(sec_checks):,} checks)"
        )
        for check in key:
            print(f"    {fmt_check(check)}")

    print()
    print(
        wrap(
            f"Showing {key_count:,} key checks worth {key_points:,} points. "
            f"The complete list of all {len(analysis.checks):,} checks is in "
            f"{full_path}."
        )
    )
    print(wrap(f"A shorter list is in {key_path}."))


# --------------------------------------------------------------------------
# Command files + console output
# --------------------------------------------------------------------------
def build_all_commands(snapshots, start_idx: int, answer_idx: int):
    start = snapshots[start_idx]
    answer = snapshots[answer_idx]
    per_device = {}
    unchanged = []
    for name in sorted(answer):
        ans = answer[name]
        if not ans.lines:
            continue
        base = start.get(name)
        commands = build_commands(base.lines if base else [], ans.lines)
        if commands:
            per_device[name] = (ans.model, commands)
        else:
            unchanged.append(name)
    return per_device, unchanged


def build_changes_report(snapshots, start_idx: int, answer_idx: int) -> str:
    start = snapshots[start_idx]
    answer = snapshots[answer_idx]
    lines = [
        "WHAT THE ANSWER CONFIG ADDS / CHANGES",
        "=" * 38,
        "",
        "  -  present in the starting config but not in the answer",
        "  +  present in the answer but not in the starting config",
        "",
    ]
    for name in sorted(answer):
        ans = answer[name]
        base = start.get(name)
        added, removed = config_delta(base.lines if base else [], ans.lines)
        if not added and not removed:
            continue
        lines.append(f"### {name}")
        for line in removed:
            lines.append(f"  - {line}")
        for line in added:
            lines.append(f"  + {line}")
        lines.append("")
    return "\n".join(lines)


def build_endpoints_text(endpoints, pdus) -> str:
    lines = [
        "ENDPOINT SETTINGS",
        "=================",
        "Set these in the device GUI (Config tab, or Desktop > IP Configuration),",
        "not in the CLI.",
        "",
    ]
    for name, info in sorted(endpoints.items()):
        if not info["model"].upper().startswith(("PC", "SERVER", "LAPTOP")):
            continue
        lines.append(f"{name}  ({info['model']})")
        for port in info["ports"]:
            gateway = f"   gateway {port['gw']}" if port["gw"] else ""
            lines.append(f"  {port['name']}: {port['ip']} {port['mask']}{gateway}")
        lines.append("")

    if pdus:
        lines.append("CONNECTIVITY TESTS (Simple PDU) THAT AWARD POINTS")
        lines.append("=" * 48)
        for index, pdu in enumerate(pdus, 1):
            lines.append(
                f"  {index}. {pdu['src']} -> {pdu['dst']} "
                f"({pdu['dstip']})   {pdu['points']} pts"
            )
    return "\n".join(lines)


def write_command_files(commands_dir: Path, pka_name: str, per_device, endpoints, pdus):
    all_blocks = [
        f"# Generated IOS commands for {pka_name}",
        "# One block per device. Paste each block into the matching device CLI.",
        "",
    ]
    explained_blocks = [
        f"GENERATED IOS COMMANDS - {pka_name}",
        "Every command with a one-line explanation above it.",
        "",
    ]
    written = []

    for name, (model, commands) in per_device.items():
        filename = re.sub(r"[^A-Za-z0-9_.-]", "_", name) + ".txt"
        header = (
            f"! {name} ({model})\n"
            f"! Generated automatically from the answer config inside {pka_name}.\n"
            f"! Paste the block below into the device CLI.\n\n"
        )
        path = commands_dir / filename
        write_file(path, header + commands)
        written.append(path)

        all_blocks.append("=" * 70)
        all_blocks.append(f"# {name}  ({model})")
        all_blocks.append("=" * 70)
        all_blocks.append(commands)
        all_blocks.append("")

        explained_blocks.append("=" * 70)
        explained_blocks.append(f" {name}  ({model})")
        explained_blocks.append("=" * 70)
        for line in commands.splitlines():
            if line.strip() != "exit":
                explained_blocks.append(f"! {explain_command(line)}")
            explained_blocks.append(line)
        explained_blocks.append("")

    all_path = commands_dir / "ALL_COMMANDS.txt"
    explained_path = commands_dir / "ALL_COMMANDS_EXPLAINED.txt"
    endpoints_path = commands_dir / "ENDPOINTS.txt"
    write_file(all_path, "\n".join(all_blocks))
    write_file(explained_path, "\n".join(explained_blocks))
    write_file(endpoints_path, build_endpoints_text(endpoints, pdus))
    written += [all_path, explained_path, endpoints_path]
    return written


def print_device_commands(name: str, model: str, commands: str) -> None:
    lines = commands.splitlines()
    print()
    print(f"  {C.BOLD}{name}{C.RESET}  ({model})   {len(lines)} lines")
    print(f"  {C.DIM}The block below is ready to paste.{C.RESET}")
    print("  " + "-" * (WIDTH - 2))
    for line in lines:
        print(f"    {line}")
    print("  " + "-" * (WIDTH - 2))
    print(f"  {C.DIM}What it does:{C.RESET}")
    for line in lines:
        if line.strip() == "exit":
            continue
        print_two_col(line, explain_command(line))


def print_commands(
    analysis: Analysis,
    snapshots,
    start_idx: int,
    answer_idx: int,
    per_device,
    unchanged,
    endpoints,
    pdus,
    all_path: Path,
) -> None:
    heading("CONFIG COMMANDS")
    print(
        wrap(
            "These commands are generated automatically. No AI writes them: the "
            "tool reads the starting running-config and the answer running-config "
            "stored inside the activity, then keeps only the lines the answer "
            "adds or changes, grouped under the right interface or router block."
        )
    )
    print()
    print(f"  Config snapshots found : {len(snapshots)}")
    print(f"  Starting snapshot      : #{start_idx + 1} (fewest key matches)")
    print(f"  Answer snapshot        : #{answer_idx + 1} (most key matches)")
    print(f"  Devices needing work   : {len(per_device)}")
    if unchanged:
        print(f"  Already matching       : {len(unchanged)}")

    for name, (model, commands) in per_device.items():
        print_device_commands(name, model, commands)

    if unchanged:
        section("DEVICES ALREADY MATCHING THE ANSWER (no commands needed)")
        print(wrap(", ".join(unchanged)))

    if endpoints:
        section("PC / SERVER / LAPTOP SETTINGS (set these in the GUI)")
        for name, info in sorted(endpoints.items()):
            if not info["model"].upper().startswith(("PC", "SERVER", "LAPTOP")):
                continue
            for port in info["ports"]:
                gateway = port["gw"] or "-"
                print(
                    f"  {name:<14} {port['ip']:<16} {port['mask']:<16} "
                    f"gw {gateway}"
                )

    if pdus:
        section("CONNECTIVITY TESTS THAT AWARD POINTS (Simple PDU)")
        for index, pdu in enumerate(pdus, 1):
            print(
                f"  {index}. {pdu['src']} -> {pdu['dst']} "
                f"({pdu['dstip']})   {pdu['points']} pts"
            )

    print()
    print(wrap(f"All device blocks in one file: {all_path}"))
    print(
        wrap(
            "Read each block before pasting. The values come from the answer "
            "key, so even an unusual value is what Packet Tracer grades."
        )
    )


# --------------------------------------------------------------------------
# Report README
# --------------------------------------------------------------------------
def build_report_readme(
    analysis: Analysis,
    mode: str,
    snapshot_count: int,
    start_idx: int,
    answer_idx: int,
    device_count: int,
    unchanged_count: int,
    endpoint_count: int,
    pdu_count: int,
) -> str:
    file_lines = ["FILES IN THIS REPORT", "--------------------"]
    if mode in ("score", "all"):
        file_lines += [
            "scoring/scoring_all.txt              every graded check with points and expected value",
            "scoring/scoring_key.txt              only the checks that matter most",
        ]
    if mode in ("commands", "all"):
        file_lines += [
            "commands/ALL_COMMANDS.txt            every device block in one paste-ready file",
            "commands/ALL_COMMANDS_EXPLAINED.txt  the same commands with an explanation each",
            "commands/<Device>.txt                one paste-ready file per device",
            "commands/ENDPOINTS.txt               PC/server settings and graded connectivity tests",
            "changes.txt                          what the answer config adds/removes per device",
        ]
    file_lines += ["README.txt                           this file", ""]

    lines = [
        "PKA SCORE INSPECTOR REPORT",
        "==========================",
        "",
        f"Activity    : {analysis.pka.name}",
        f"PT version  : {analysis.version}",
        f"Generated   : {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        f"Mode        : {mode}",
        "",
        "WHAT THIS IS",
        "------------",
        "Everything here was extracted automatically from the activity file.",
        "No AI or LLM was used at runtime: the grading tree and the answer",
        "config are read straight out of the .pka/.pkt, and the commands are a",
        "plain text diff between the starting config and the answer config.",
        "",
        "The activity file itself was NOT modified.",
        "",
        *file_lines,
        "SUMMARY",
        "-------",
        f"Graded points       : {analysis.total:,}",
        f"Individual checks   : {len(analysis.checks):,}",
    ]
    if snapshot_count:
        lines += [
            f"Config snapshots    : {snapshot_count}",
            f"Starting snapshot   : #{start_idx + 1}",
            f"Answer snapshot     : #{answer_idx + 1}",
            f"Devices with commands: {device_count}",
            f"Devices already done : {unchanged_count}",
            f"PC/server entries   : {endpoint_count}",
            f"Graded PDU tests    : {pdu_count}",
        ]
    lines += [
        "",
        "HOW THE POINTS WORK",
        "-------------------",
        "Packet Tracer stores a grading tree inside the activity. Every leaf is",
        "one check with a point value and an expected value (the answer key).",
        "Packet Tracer adds up the points you earn and converts the total to a",
        "percentage, so a 5-point check matters more than a 1-point check.",
        "",
        "Each line in scoring_all.txt looks like:",
        "",
        "    2p [IP       ] Branch1 / Ports / Tunnel1 / Destination  ->  11.11.11.10",
        "",
        "    2p            the check is worth 2 points",
        "    [IP]          grading category (Physical, IP, Switching, Routing,",
        "                  ACL, NAT, Other)",
        "    path          where the check lives",
        "    -> value      the expected value (the answer key)",
        "",
        "HOW THE COMMANDS ARE MADE",
        "-------------------------",
    ]
    if snapshot_count:
        lines += [
            f"The activity contains {snapshot_count} snapshots of the network.",
            f"Snapshot #{start_idx + 1} is the starting point. Snapshot",
            f"#{answer_idx + 1} matches the most graded expected values and is",
            "treated as the answer network. The tool compares the two",
            "running-configs and keeps only what the answer adds or changes,",
            "grouped under the right interface / router block.",
        ]
    else:
        lines += [
            "This run only generated the scoring report, so no command diff was",
            "made. Run the tool again and choose 'Config commands' or",
            "'Everything' to generate the commands.",
        ]
    lines += [
        "",
        "CAVEATS",
        "-------",
        "* Values come from the answer key stored in the activity. If a value",
        "  looks odd (for example a default gateway that points at the device",
        "  itself), it is still what Packet Tracer grades. Check it before the",
        "  actual test.",
        "* Interface names and port numbers come from the file, so they match",
        "  the topology. Read each block before pasting it.",
        "* The tool reproduces the answer config. It cannot guarantee 100% if",
        "  the activity also grades live protocol state (neighbors, convergence)",
        "  rather than config lines.",
        "",
        "Generated by PKA Score Inspector v" + APP_VERSION,
    ]
    return "\n".join(lines)


def print_written(report_dir: Path, written) -> None:
    section("FILES WRITTEN")
    print(f"  {report_dir}")
    for rel in written:
        path = report_dir / rel
        size = human_size(path.stat().st_size) if path.exists() else ""
        print(f"    {str(rel):<38} {size:>9}")
    print()
    print(wrap("The .pka was not modified. Delete the report folder to clean up."))


# --------------------------------------------------------------------------
# Menu + main
# --------------------------------------------------------------------------
def ask_mode() -> str:
    print()
    print(f"  {C.BOLD}What do you want to see?{C.RESET}")
    print()
    print("    [1] Scoring criteria")
    print("        Every graded check, its point value, and the expected answer.")
    print()
    print("    [2] Config commands")
    print("        The IOS commands that earn the points, per device.")
    print()
    print("    [3] Everything  (recommended)")
    print("        Scoring criteria first, then the config commands.")
    print()
    print("    [Q] Quit")
    while True:
        try:
            choice = input("\n  Choice [3]: ").strip().lower()
        except EOFError:
            return "all"
        if choice in ("", "3", "all", "a", "everything"):
            return "all"
        if choice in ("1", "score", "s", "scoring"):
            return "score"
        if choice in ("2", "commands", "c", "config", "cmd"):
            return "commands"
        if choice in ("q", "quit", "exit"):
            return "quit"
        print("  Please type 1, 2, 3 or Q.")


def run(pka: Path, mode: str, outdir: Path, quiet: bool) -> None:
    if not quiet:
        print()
        print(f"  {C.BOLD}{APP_NAME}{C.RESET}  v{APP_VERSION}")
        print(f"  File: {pka}")
        print("  Decrypting ...", end="", flush=True)
    text = decode_file(pka)
    root = parse_xml(text)
    if not quiet:
        print(" done")

    version = (root.findtext("VERSION") or "").strip() or "unknown"
    analysis = Analysis(root, pka, version)
    report_dir = outdir / f"{pka.stem}_report"
    written = []

    snapshots = []
    start_idx = 0
    answer_idx = 0
    per_device = {}
    unchanged = []
    endpoints = {}
    pdus = []

    if mode in ("commands", "all"):
        snapshots = collect_snapshots(root)
        if not snapshots or not any(
            dev.lines for snap in snapshots for dev in snap.values()
        ):
            raise ToolError(
                "This file has no running-config text, so there is nothing to "
                "build commands from. It may be a plain topology rather than a "
                "graded activity."
            )
        start_idx, answer_idx = pick_snapshots(snapshots, analysis.checks)
        per_device, unchanged = build_all_commands(
            snapshots, start_idx, answer_idx
        )
        endpoints = collect_endpoint_settings(root)
        pdus = collect_pdus(root)

    # Start from a clean report folder so switching modes never leaves stale
    # files behind.
    reset_dir(report_dir)

    if mode in ("score", "all"):
        scoring_dir = report_dir / "scoring"
        for path in write_scoring_files(scoring_dir, analysis):
            written.append(path.relative_to(report_dir))

    if mode in ("commands", "all"):
        commands_dir = report_dir / "commands"
        for path in write_command_files(
            commands_dir, pka.name, per_device, endpoints, pdus
        ):
            written.append(path.relative_to(report_dir))

        changes_path = report_dir / "changes.txt"
        write_file(
            changes_path, build_changes_report(snapshots, start_idx, answer_idx)
        )
        written.append(Path("changes.txt"))

    write_file(
        report_dir / "README.txt",
        build_report_readme(
            analysis,
            mode,
            len(snapshots),
            start_idx,
            answer_idx,
            len(per_device),
            len(unchanged),
            len(endpoints),
            len(pdus),
        ),
    )
    written.append(Path("README.txt"))

    if quiet:
        return

    if mode in ("score", "all"):
        print_scoring(
            analysis,
            report_dir / "scoring" / "scoring_all.txt",
            report_dir / "scoring" / "scoring_key.txt",
        )
    if mode in ("commands", "all"):
        print_commands(
            analysis,
            snapshots,
            start_idx,
            answer_idx,
            per_device,
            unchanged,
            endpoints,
            pdus,
            report_dir / "commands" / "ALL_COMMANDS.txt",
        )
    print_written(report_dir, written)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="pka_score.py",
        description=(
            "Inspect a Packet Tracer activity's grading key and generate "
            "the IOS commands that earn the points."
        ),
    )
    parser.add_argument("pka", nargs="?", help="path to a .pka or .pkt file")
    parser.add_argument(
        "--mode",
        choices=("score", "commands", "all"),
        help="skip the interactive menu",
    )
    parser.add_argument(
        "--outdir",
        help="where to create <name>_report (default: next to the file)",
    )
    parser.add_argument(
        "--no-pause",
        action="store_true",
        help="never wait for Enter (scripting)",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="write files without console output",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{APP_NAME} {APP_VERSION}",
    )
    args = parser.parse_args(argv)

    interactive = not args.no_pause and not args.quiet

    try:
        if args.mode:
            mode = args.mode
        elif not interactive:
            mode = "all"
        else:
            mode = ask_mode()
            if mode == "quit":
                return 0

        pka_arg = args.pka
        if not pka_arg:
            if not interactive:
                raise ToolError("No .pka/.pkt file given.")
            try:
                pka_arg = input("  Path to .pka/.pkt: ").strip().strip('"')
            except EOFError:
                raise ToolError("No .pka/.pkt file given.") from None
            if not pka_arg:
                raise ToolError("No .pka/.pkt file given.")

        pka = Path(pka_arg).expanduser().resolve()
        if not pka.exists():
            raise ToolError(f"File not found: {pka}")
        if pka.suffix.lower() not in (".pka", ".pkt") and not args.quiet:
            print(
                f"  warning: '{pka.suffix or 'no extension'}' is not .pka/.pkt; "
                "trying anyway"
            )

        outdir = (
            Path(args.outdir).expanduser().resolve() if args.outdir else pka.parent
        )
        run(pka, mode, outdir, args.quiet)

    except ToolError as exc:
        print()
        print(f"  {C.RED}ERROR:{C.RESET} {exc}")
        if interactive:
            pause()
        return 1
    except KeyboardInterrupt:
        print("\n  Cancelled.")
        return 130
    except Exception as exc:  # pragma: no cover
        print()
        print(f"  {C.RED}UNEXPECTED ERROR:{C.RESET} {exc}")
        import traceback

        traceback.print_exc()
        if interactive:
            pause()
        return 1

    if interactive:
        pause()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
