#!/usr/bin/env python3
"""Locate SpectatorPanel::Update from its three observer-bar format strings.

SpectatorPanel::Update is the only Sven client function that formats the
observer bottom bar, so the function that owns the unique "Health: %d" literal
must also own "Armor: %d" and "%s : %s". The walk resolves those three string
owners and requires them to agree; the inspected owner is written as
SpectatorPanel_Update.
"""

from ida_analyze_util import (
    _inspect_function_via_mcp,
    _output_for_symbol,
    write_func_yaml,
)
from ida_preprocessor_scripts._portal_layout_ida import run_layout_walk

NAME = "SpectatorPanel_Update"

WALK = """
import ida_bytes, ida_funcs, ida_nalt, idautils

def exact_string_eas(literal):
    eas = []
    strings = idautils.Strings(default_setup=False)
    strings.setup(strtypes=[ida_nalt.STRTYPE_C], minlen=4)
    for item in strings:
        if str(item) == literal:
            eas.append(int(item.ea))
    return eas

def owner_of(literal):
    eas = exact_string_eas(literal)
    if len(eas) != 1:
        raise ValueError('anchor is not unique: %s -> %r'
                         % (literal, [hex(ea) for ea in eas]))
    owners = set()
    for ref in idautils.XrefsTo(eas[0], 0):
        if not ida_bytes.is_code(ida_bytes.get_flags(ref.frm)):
            continue
        function = ida_funcs.get_func(int(ref.frm))
        if function is not None:
            owners.add(int(function.start_ea))
    if len(owners) != 1:
        raise ValueError('anchor owner is not unique: %s -> %r'
                         % (literal, sorted(hex(owner) for owner in owners)))
    return next(iter(owners))

target = owner_of('Health: %d')
for anchor in ('Armor: %d', '%s : %s'):
    if owner_of(anchor) != target:
        raise ValueError('anchor owner mismatch: ' + anchor)
result = {'target': target}
"""


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = skill_name, old_yaml_map, new_binary_dir, platform
    output = _output_for_symbol(expected_outputs, NAME)
    if output is None:
        return False
    try:
        result = await run_layout_walk(session, {}, WALK)
        function = await _inspect_function_via_mcp(session, result["target"], image_base, NAME)
        if not function:
            return False
        payload = {key: function[key] for key in ("func_name", "func_va", "func_rva", "func_size", "func_sig")}
        write_func_yaml(output, payload)
        if debug:
            print("SpectatorPanel_Update verified:", result)
        return True
    except (ValueError, KeyError) as exc:
        if debug:
            print(exc)
        return False
