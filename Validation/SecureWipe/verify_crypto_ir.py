#!/usr/bin/env python3

from __future__ import annotations

import re
import sys
from collections import deque
from dataclasses import dataclass
from pathlib import Path


SSA = r"%[-.$A-Za-z0-9_]+"
GLOBAL = r'@(?:"[^"]+"|[-.$A-Za-z0-9_]+)'
LABEL = r'(?:"([^"]+)"|([-.$A-Za-z0-9_]+))'
SECURE_WIPE_SYMBOLS = frozenset(
    f"${mangling}12SSLCore10SecureWipeO5erase_9byteCountySv_SitFZ{suffix}"
    for mangling in ("s", "e")
    for suffix in ("", "Tf4nnd_n")
)
HMAC_SHA256_STORAGE_BYTE_COUNT = 240
HMAC_SHA256_STORAGE_ALIGNMENT_MASK = 15
SHA256_UPDATE_SYMBOLS = frozenset(
    (
        f"${mangling}14SSLCrypto13SHA256ContextV6update"
        "yys4SpanVys5UInt8VGAA16CryptoInputErrorOYKF"
    )
    for mangling in ("s", "e")
)
CONSTANT_TIME_EQUAL_SYMBOLS = frozenset(
    (
        f"${mangling}12SSLCore12ConstantTimeO5equal"
        "ySbs4SpanVys5UInt8VG_AItFZ"
    )
    for mangling in ("s", "e")
)
SHA256_FINALIZE_IN_PLACE_SYMBOLS = frozenset(
    (
        f"${mangling}14SSLCrypto13SHA256ContextV15finalizeInPlace"
        "4intoys11MutableSpanVys5UInt8VGz_t"
        "AA16CryptoInputErrorOYKF"
    )
    for mangling in ("s", "e")
)
HMAC_FINALIZE_SYMBOLS = frozenset(
    (
        f"${mangling}14SSLCrypto14HMACSHA256CoreO"
        "26finalizeAuthenticationCode12innerContext05outerI04intoy"
        "AA06SHA256I0Vz_AIzs11MutableSpanVys5UInt8VGzt"
        "AA16CryptoInputErrorOYKFZ"
    )
    for mangling in ("s", "e")
)
HMAC_ONE_SHOT_SYMBOLS = frozenset(
    (
        f"${mangling}14SSLCrypto10HMACSHA256O"
        "12authenticate_5using4intoys4SpanVys5UInt8VG_"
        "AKs07MutableG0VyAJGztAA16CryptoInputErrorOYKFZ"
    )
    for mangling in ("s", "e")
)
HMAC_CONTEXT_VERIFY_SYMBOLS = frozenset(
    (
        f"${mangling}14SSLCrypto17HMACSHA256ContextV"
        "25isValidAuthenticationCodeySbs4SpanVys5UInt8VG"
        "AA16CryptoInputErrorOYKF"
    )
    for mangling in ("s", "e")
)
HKDF_EXPAND_SYMBOLS = frozenset(
    (
        f"${mangling}14SSLCrypto10HKDFSHA256O"
        "6expand15pseudorandomKey4info4intoys4SpanVys5UInt8VG_"
        "ALs07MutableI0VyAKGztAA9HKDFErrorOYKFZ"
    )
    for mangling in ("s", "e")
)
HMAC_STORAGE_DEINIT_SYMBOLS = frozenset(
    f"${mangling}14SSLCrypto24HMACSHA256ContextStorageCfD"
    for mangling in ("s", "e")
)


class VerificationError(RuntimeError):
    pass


@dataclass(frozen=True)
class Function:
    name: str
    header: str
    lines: tuple[str, ...]

    @property
    def text(self) -> str:
        return "\n".join(self.lines)

    def blocks(self) -> dict[str, tuple[str, ...]]:
        result: dict[str, list[str]] = {}
        current: str | None = None
        for line in self.lines:
            match = re.match(r'^("[^"]+"|[-.$A-Za-z0-9_]+):', line)
            if match:
                current = match.group(1).strip('"')
                result[current] = []
            elif current is not None:
                result[current].append(line)
        if not result:
            raise VerificationError(f"{self.name}: no LLVM basic blocks")
        return {name: tuple(lines) for name, lines in result.items()}


def parse_functions(ir: str) -> tuple[Function, ...]:
    lines = ir.splitlines()
    functions: list[Function] = []
    index = 0
    while index < len(lines):
        header = lines[index]
        if not header.startswith("define "):
            index += 1
            continue
        quoted = re.search(r'@"([^"]+)"', header)
        unquoted = re.search(r"@([-.$A-Za-z0-9_]+)\(", header)
        if quoted:
            name = quoted.group(1)
        elif unquoted:
            name = unquoted.group(1)
        else:
            raise VerificationError(f"Unable to parse function header: {header}")
        body: list[str] = []
        index += 1
        while index < len(lines) and lines[index] != "}":
            body.append(lines[index])
            index += 1
        if index == len(lines):
            raise VerificationError(f"{name}: unterminated LLVM function")
        functions.append(Function(name, header, tuple(body)))
        index += 1
    return tuple(functions)


def functions_containing(
    functions: tuple[Function, ...],
    fragment: str,
) -> tuple[Function, ...]:
    return tuple(function for function in functions if fragment in function.name)


def require_functions(
    functions: tuple[Function, ...],
    fragment: str,
) -> tuple[Function, ...]:
    matches = functions_containing(functions, fragment)
    if not matches:
        raise VerificationError(f"Missing production symbol: {fragment}")
    return matches


def require_exact_functions(
    functions: tuple[Function, ...],
    symbols: frozenset[str],
    responsibility: str,
) -> tuple[Function, ...]:
    matches = tuple(
        function for function in functions if function.name in symbols
    )
    if not matches:
        raise VerificationError(
            f"Missing canonical production symbol for {responsibility}"
        )
    return matches


def reachable_functions(
    functions: tuple[Function, ...],
    roots: tuple[Function, ...],
) -> tuple[Function, ...]:
    by_name: dict[str, list[Function]] = {}
    for function in functions:
        by_name.setdefault(function.name, []).append(function)

    pending = deque(function.name for function in roots)
    visited_symbols: set[str] = set()
    reachable: list[Function] = []
    while pending:
        symbol = pending.popleft()
        if symbol in visited_symbols:
            continue
        visited_symbols.add(symbol)
        bodies = by_name.get(symbol, ())
        reachable.extend(bodies)
        for body in bodies:
            for line in body.lines:
                called = called_symbol(line)
                if called in by_name and called not in visited_symbols:
                    pending.append(called)
                for reference in re.finditer(
                    r'@(?:"([^"]+)"|([-.$A-Za-z0-9_]+))',
                    line,
                ):
                    referenced = reference.group(1) or reference.group(2)
                    if (
                        referenced in by_name
                        and referenced not in visited_symbols
                    ):
                        pending.append(referenced)
    return tuple(reachable)


def assignment(line: str) -> tuple[str, str] | None:
    match = re.match(rf"\s*({SSA}) = (.*)", line)
    return (match.group(1), match.group(2)) if match else None


def ssa_tokens(text: str) -> tuple[str, ...]:
    return tuple(re.findall(SSA, text))


def called_symbol(line: str) -> str | None:
    quoted = re.search(r'\b(?:tail\s+)?call\b.*?@"([^"]+)"\(', line)
    if quoted:
        return quoted.group(1)
    unquoted = re.search(
        r"\b(?:tail\s+)?call\b.*?@([-.$A-Za-z0-9_]+)\(",
        line,
    )
    return unquoted.group(1) if unquoted else None


def is_secure_wipe_symbol(symbol: str | None) -> bool:
    return symbol in SECURE_WIPE_SYMBOLS


def is_secure_wipe_call(line: str) -> bool:
    return is_secure_wipe_symbol(called_symbol(line))


def symbol_arguments(text: str, symbol: str) -> tuple[str, ...]:
    markers = (f'@"{symbol}"(', f"@{symbol}(")
    start = next(
        (
            position + len(marker)
            for marker in markers
            if (position := text.find(marker)) >= 0
        ),
        None,
    )
    if start is None:
        raise VerificationError(f"Missing argument list for {symbol}")

    arguments: list[str] = []
    current: list[str] = []
    delimiters = {"(": ")", "[": "]", "{": "}", "<": ">"}
    closing = set(delimiters.values())
    stack: list[str] = []
    index = start
    while index < len(text):
        character = text[index]
        if character in delimiters:
            stack.append(delimiters[character])
            current.append(character)
        elif character in closing:
            if stack:
                if character != stack[-1]:
                    raise VerificationError(
                        f"Unbalanced argument list for {symbol}"
                    )
                stack.pop()
                current.append(character)
            elif character == ")":
                value = "".join(current).strip()
                if value:
                    arguments.append(value)
                return tuple(arguments)
            else:
                raise VerificationError(
                    f"Unexpected delimiter in argument list for {symbol}"
                )
        elif character == "," and not stack:
            arguments.append("".join(current).strip())
            current = []
        else:
            current.append(character)
        index += 1
    raise VerificationError(f"Unterminated argument list for {symbol}")


def argument_value(argument: str) -> str:
    values = ssa_tokens(argument)
    if values:
        return values[-1]
    global_value = re.search(rf"({GLOBAL})\s*$", argument)
    if global_value:
        return global_value.group(1)
    literal = re.search(
        r"\b(poison|null|undef|true|false|-?\d+)\s*$",
        argument,
    )
    if literal:
        return literal.group(1)
    raise VerificationError(f"Unable to identify LLVM argument value: {argument}")


def call_argument_values(line: str, symbol: str) -> tuple[str, ...]:
    return tuple(
        argument_value(argument)
        for argument in symbol_arguments(line, symbol)
    )


def integer_argument_literal(argument: str) -> int | None:
    if argument_type(argument) not in ("i32", "i64"):
        return None
    value = argument_value(argument)
    return int(value) if re.fullmatch(r"-?\d+", value) else None


def pointer_argument_value(argument: str) -> str | None:
    if argument_type(argument) != "ptr":
        return None
    matches = re.findall(rf"(?:{SSA}|{GLOBAL})", argument)
    return matches[-1] if matches else None


def formal_parameters(function: Function) -> tuple[str, ...]:
    return tuple(
        argument_value(argument)
        for argument in symbol_arguments(function.header, function.name)
    )


def argument_type(argument: str) -> str | None:
    match = re.match(r"\s*(ptr|i32|i64)\b", argument)
    return match.group(1) if match else None


def formal_parameter_types(function: Function) -> tuple[str, ...]:
    return tuple(
        argument_type(argument) or ""
        for argument in symbol_arguments(function.header, function.name)
    )


def is_swiftcc_void_function(function: Function) -> bool:
    symbol = re.escape(function.name)
    return bool(
        re.match(
            rf'^define\b.*\bswiftcc void\s+@"{symbol}"\(',
            function.header,
        )
        or re.match(
            rf"^define\b.*\bswiftcc void\s+@{symbol}\(",
            function.header,
        )
    )


def is_unassigned_swiftcc_void_call(line: str, symbol: str) -> bool:
    if assignment(line) is not None:
        return False
    escaped = re.escape(symbol)
    return bool(
        re.match(
            rf'^\s*(?:tail\s+)?call swiftcc void\s+@"{escaped}"\(',
            line,
        )
        or re.match(
            rf"^\s*(?:tail\s+)?call swiftcc void\s+@{escaped}\(",
            line,
        )
    )


def exact_pointer_count_signature(function: Function) -> bool:
    types = formal_parameter_types(function)
    return (
        is_swiftcc_void_function(function)
        and len(types) == 2
        and types[0] == "ptr"
        and types[1] in ("i32", "i64")
    )


def pointer_operands(line: str) -> tuple[str, ...]:
    attribute = (
        r"(?:nonnull|noundef|readonly|writeonly|readnone|noalias|swiftself|"
        r"swifterror|captures\(none\)|align\s+\d+|dereferenceable\(\d+\))"
    )
    return tuple(
        re.findall(rf"\bptr(?:\s+{attribute})*\s+({SSA})", line)
    )


def call_result_may_carry_address(expression: str) -> bool:
    symbol_position = expression.find("@")
    if symbol_position < 0:
        return True
    prefix = expression[:symbol_position].rstrip()
    result_type = re.search(
        r"(\{[^{}]*\}|ptr|i\d+)\s*$",
        prefix,
    )
    if result_type is None:
        return True
    value = result_type.group(1)
    if value == "ptr" or "ptr" in value:
        return True
    integer_width = re.fullmatch(r"i(\d+)", value)
    return integer_width is not None and int(integer_width.group(1)) >= 32


def assignment_may_carry_storage_address(expression: str) -> bool:
    if expression.startswith("icmp "):
        return False
    if re.match(r"(?:tail\s+)?call\b", expression):
        return call_result_may_carry_address(expression)
    return True


def top_level_comma_parts(text: str) -> tuple[str, ...]:
    delimiters = {"(": ")", "[": "]", "{": "}", "<": ">"}
    closing = set(delimiters.values())
    stack: list[str] = []
    parts: list[str] = []
    current: list[str] = []
    for character in text:
        if character in delimiters:
            stack.append(delimiters[character])
            current.append(character)
        elif character in closing:
            if stack and character == stack[-1]:
                stack.pop()
            current.append(character)
        elif character == "," and not stack:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(character)
    parts.append("".join(current).strip())
    return tuple(parts)


def stored_values_and_destination(
    line: str,
) -> tuple[tuple[str, ...], str | None] | None:
    match = re.match(r"\s*store\b(.*)", line)
    if not match:
        return None
    parts = top_level_comma_parts(match.group(1))
    if len(parts) < 2:
        return (), None
    destination_match = re.search(
        rf"\bptr(?:\s+\w+(?:\([^)]*\))?|\s+\d+)*\s+"
        rf"({SSA}|{GLOBAL})(?:\s|,|$)",
        parts[1],
    )
    return ssa_tokens(parts[0]), (
        destination_match.group(1) if destination_match else None
    )


def memory_transfer_pointer_values(
    line: str,
) -> tuple[str | None, str | None] | None:
    if "llvm.memcpy" not in line and "llvm.memmove" not in line:
        return None
    symbol = called_symbol(line)
    if symbol is None:
        return None
    arguments = symbol_arguments(line, symbol)
    if len(arguments) < 2:
        return None
    values: list[str | None] = []
    for argument in arguments[:2]:
        matches = re.findall(rf"(?:{SSA}|{GLOBAL})", argument)
        values.append(matches[-1] if matches else None)
    return values[0], values[1]


def select_values(expression: str) -> tuple[str, str] | None:
    value = rf"(?:{SSA}|null|poison|undef|-?\d+)"
    match = re.fullmatch(
        rf"select i1 {SSA}, (?:ptr|i(?:32|64)) ({value}), "
        rf"(?:ptr|i(?:32|64)) ({value})",
        expression,
    )
    return match.groups() if match else None


def phi_values(expression: str) -> tuple[str, ...] | None:
    value = rf"(?:{SSA}|null|poison|undef|-?\d+)"
    label = r'%(?:"[^"]+"|[-.$A-Za-z0-9_]+)'
    incoming = rf"\[\s*{value}\s*,\s*{label}\s*\]"
    if not re.fullmatch(
        rf"phi (?:ptr|i(?:32|64)) {incoming}(?:,\s*{incoming})*",
        expression,
    ):
        return None
    return tuple(
        match.group(1)
        for match in re.finditer(
            rf"\[\s*({value})\s*,\s*{label}\s*\]",
            expression,
        )
    )


def local_storage_locations(
    function: Function,
) -> dict[str, tuple[str, int | None]]:
    locations: dict[str, tuple[str, int | None]] = {
        result: (result, 0)
        for line in function.lines
        if (parsed := assignment(line))
        for result, expression in (parsed,)
        if expression.startswith("alloca ")
    }
    changed = True
    while changed:
        changed = False
        for line in function.lines:
            parsed = assignment(line)
            if not parsed:
                continue
            result, expression = parsed
            if result in locations:
                continue

            location: tuple[str, int | None] | None = None
            if expression.startswith("getelementptr"):
                base = next(
                    (
                        pointer
                        for pointer in pointer_operands(expression)
                        if pointer in locations
                    ),
                    None,
                )
                if base is not None:
                    root, base_offset = locations[base]
                    indices = re.findall(
                        rf"i(?:32|64)\s+(-?\d+|{SSA})",
                        expression,
                    )
                    constants = (
                        indices
                        if indices
                        and all(
                            re.fullmatch(r"-?\d+", index)
                            for index in indices
                        )
                        else ()
                    )
                    byte_element = re.search(
                        r"getelementptr(?:\s+\w+)*\s+"
                        r"(?:i8|%Ts5UInt8V),",
                        expression,
                    )
                    if constants and all(int(index) == 0 for index in constants):
                        location = (root, base_offset)
                    elif constants and byte_element and base_offset is not None:
                        location = (
                            root,
                            base_offset + sum(int(index) for index in constants),
                        )
                    else:
                        location = (root, None)
            elif expression.startswith(
                (
                    "ptrtoint",
                    "inttoptr",
                    "bitcast",
                    "addrspacecast",
                    "freeze ",
                )
            ):
                operands = [
                    token
                    for token in ssa_tokens(expression)
                    if token in locations
                ]
                if operands:
                    location = locations[operands[0]]
            elif expression.startswith("select"):
                values = select_values(expression)
                if (
                    values is not None
                    and all(value in locations for value in values)
                    and len({locations[value] for value in values}) == 1
                ):
                    location = locations[values[0]]
            elif expression.startswith("phi"):
                values = phi_values(expression)
                if (
                    values
                    and all(value in locations for value in values)
                    and len({locations[value] for value in values}) == 1
                ):
                    location = locations[values[0]]

            if location is not None:
                locations[result] = location
                changed = True
    return locations


def pointer_facts(
    function: Function,
    root: str,
    proven_offsets: tuple[tuple[str, int], ...] = (),
    strict_storage_aliases: bool = False,
    fail_unresolved_sensitive_stores: bool = False,
) -> dict[str, int | None]:
    facts: dict[str, int | None] = {root: 0}
    facts.update(proven_offsets)
    storage_locations = local_storage_locations(function)
    stored_values: list[
        tuple[
            tuple[str, ...],
            str | None,
            tuple[str, int | None] | None,
        ]
    ] = []
    for line in function.lines:
        if not re.match(r"\s*store\b", line):
            continue
        parsed_store = stored_values_and_destination(line)
        if parsed_store is None:
            continue
        values, destination = parsed_store
        destination_location = (
            storage_locations.get(destination)
            if destination is not None
            else None
        )
        stored_values.append(
            (
                values,
                destination,
                destination_location,
            )
        )
    alias_slots: dict[tuple[str, int | None], int | None] = {}
    slot_address_slots: set[tuple[str, int | None]] = set()
    storage_alias_pointers: set[str] = set()

    changed = True
    while changed:
        changed = False
        for values, destination, destination_location in stored_values:
            contains_sensitive_value = any(
                value in facts for value in values
            )
            contains_sensitive_slot_address = any(
                value in storage_alias_pointers for value in values
            )
            if (
                not contains_sensitive_value
                and not contains_sensitive_slot_address
            ):
                continue
            if destination_location is None and (
                strict_storage_aliases
                or fail_unresolved_sensitive_stores
                or contains_sensitive_slot_address
            ):
                raise VerificationError(
                    f"{function.name}: sensitive pointer escapes through "
                    f"unresolved storage {destination or '<unknown>'}"
                )
            if destination_location is None:
                continue
            if destination_location[1] is None and (
                strict_storage_aliases
                or fail_unresolved_sensitive_stores
                or contains_sensitive_slot_address
            ):
                raise VerificationError(
                    f"{function.name}: sensitive pointer is stored through "
                    "an unknown local offset"
                )
            if (
                contains_sensitive_slot_address
                and destination_location not in slot_address_slots
            ):
                slot_address_slots.add(destination_location)
                changed = True
            # A memory round trip preserves sensitivity, but not exact
            # provenance: another store, call, or memory intrinsic may clobber
            # the slot on a path this local SSA analysis cannot prove.
            offset = None
            if destination_location not in alias_slots:
                alias_slots[destination_location] = offset
                changed = True
            elif alias_slots[destination_location] is not None:
                alias_slots[destination_location] = None
                changed = True
            for alias, location in storage_locations.items():
                if (
                    location == destination_location
                    and alias not in storage_alias_pointers
                ):
                    storage_alias_pointers.add(alias)
                    changed = True

        for line in function.lines:
            transfer = memory_transfer_pointer_values(line)
            if transfer is None:
                continue
            destination, source = transfer
            source_location = (
                storage_locations.get(source)
                if source is not None
                else None
            )
            source_is_owner_value = source_location in alias_slots
            source_is_slot_address = (
                source_location in slot_address_slots
                or source in storage_alias_pointers
            )
            if not source_is_owner_value and not source_is_slot_address:
                continue
            destination_location = (
                storage_locations.get(destination)
                if destination is not None
                else None
            )
            if destination_location is None:
                if source_is_slot_address or (
                    strict_storage_aliases
                    or fail_unresolved_sensitive_stores
                ):
                    raise VerificationError(
                        f"{function.name}: sensitive slot is copied to "
                        "unresolved storage"
                    )
                continue
            if destination_location[1] is None:
                raise VerificationError(
                    f"{function.name}: sensitive slot is copied through "
                    "an unknown local offset"
                )
            if (
                source_is_owner_value
                or source in storage_alias_pointers
            ) and destination_location not in alias_slots:
                alias_slots[destination_location] = None
                changed = True
            if (
                source_is_slot_address
                and destination_location not in slot_address_slots
            ):
                slot_address_slots.add(destination_location)
                changed = True
            for alias, location in storage_locations.items():
                if (
                    location == destination_location
                    and alias not in storage_alias_pointers
                ):
                    storage_alias_pointers.add(alias)
                    changed = True

        for line in function.lines:
            parsed = assignment(line)
            if not parsed:
                continue
            result, expression = parsed
            if re.match(
                r"load(?:\s+(?:atomic|volatile))*\s+ptr,",
                expression,
            ):
                pointers = pointer_operands(expression)
                source = pointers[-1] if pointers else None
                source_location = (
                    storage_locations.get(source)
                    if source is not None
                    else None
                )
                if (
                    source_location in slot_address_slots
                    or source in storage_alias_pointers
                ) and result not in storage_alias_pointers:
                    storage_alias_pointers.add(result)
                    changed = True
            if (
                result not in storage_alias_pointers
                and assignment_may_carry_storage_address(expression)
                and any(
                    token in storage_alias_pointers
                    for token in ssa_tokens(expression)
                )
            ):
                storage_alias_pointers.add(result)
                changed = True
            if result in facts:
                continue

            offset: int | None
            if re.match(
                r"load(?:\s+(?:atomic|volatile))*\s+"
                r"(?:ptr|i32|i64),",
                expression,
            ):
                pointers = pointer_operands(expression)
                if not pointers:
                    continue
                source_location = storage_locations.get(
                    pointers[-1],
                    (pointers[-1], 0),
                )
                if source_location not in alias_slots:
                    if (
                        pointers[-1] not in facts
                        and pointers[-1] not in storage_alias_pointers
                    ):
                        continue
                    offset = None
                else:
                    offset = alias_slots[source_location]
            elif expression.startswith("load"):
                # Loading payload bytes through a sensitive pointer does not
                # make the loaded value a pointer alias.
                continue
            elif expression.startswith("getelementptr"):
                base = next(
                    (
                        pointer
                        for pointer in pointer_operands(expression)
                        if pointer in facts
                    ),
                    None,
                )
                if base is None:
                    continue
                element_is_byte = re.search(
                    r"getelementptr(?:\s+\w+)*\s+(?:i8|%Ts5UInt8V),",
                    expression,
                )
                indices = re.findall(
                    rf"i(?:32|64)\s+(-?\d+|{SSA})",
                    expression,
                )
                if (
                    element_is_byte
                    and indices
                    and facts[base] is not None
                    and all(re.fullmatch(r"-?\d+", value) for value in indices)
                ):
                    offset = facts[base] + sum(int(value) for value in indices)
                else:
                    offset = None
            elif expression.startswith(
                ("ptrtoint", "inttoptr", "bitcast", "addrspacecast")
            ):
                operands = [
                    token
                    for token in ssa_tokens(expression)
                    if token in facts
                ]
                if not operands:
                    continue
                offset = facts[operands[0]]
            elif expression.startswith("freeze "):
                operands = [
                    token
                    for token in ssa_tokens(expression)
                    if token in facts
                ]
                if not operands:
                    continue
                offset = facts[operands[0]]
            elif expression.startswith("select"):
                values = select_values(expression)
                if values is None:
                    if any(
                        token in facts for token in ssa_tokens(expression)
                    ):
                        offset = None
                    else:
                        continue
                else:
                    known = [value for value in values if value in facts]
                    if not known:
                        continue
                    if len(known) != len(values):
                        offset = None
                    else:
                        offsets = {facts[value] for value in values}
                        offset = offsets.pop() if len(offsets) == 1 else None
            elif expression.startswith("phi"):
                values = phi_values(expression)
                if values is None:
                    if any(
                        token in facts for token in ssa_tokens(expression)
                    ):
                        offset = None
                    else:
                        continue
                else:
                    known = [value for value in values if value in facts]
                    if not known:
                        continue
                    if len(known) != len(values):
                        offset = None
                    else:
                        offsets = {facts[value] for value in values}
                        offset = offsets.pop() if len(offsets) == 1 else None
            elif expression.startswith(("add ", "sub ")):
                arithmetic = re.fullmatch(
                    rf"(add|sub)(?:\s+\w+)*\s+i(?:32|64)\s+"
                    rf"({SSA}|-?\d+),\s+({SSA}|-?\d+)",
                    expression,
                )
                if not arithmetic:
                    continue
                operation, first, second = arithmetic.groups()
                known = [value for value in (first, second) if value in facts]
                if not known:
                    continue
                if first in facts and re.fullmatch(r"-?\d+", second):
                    base_offset = facts[first]
                    if base_offset is None:
                        offset = None
                    elif operation == "add":
                        offset = base_offset + int(second)
                    else:
                        offset = base_offset - int(second)
                elif (
                    operation == "add"
                    and re.fullmatch(r"-?\d+", first)
                    and second in facts
                ):
                    base_offset = facts[second]
                    offset = (
                        None
                        if base_offset is None
                        else int(first) + base_offset
                    )
                else:
                    offset = None
            elif re.match(r"(?:tail\s+)?call\b", expression):
                if (
                    not call_result_may_carry_address(expression)
                    or not any(
                        token in facts
                        or token in storage_alias_pointers
                        for token in ssa_tokens(expression)
                    )
                ):
                    continue
                offset = None
            else:
                if any(token in facts for token in ssa_tokens(expression)):
                    offset = None
                else:
                    continue
            facts[result] = offset
            changed = True
    return facts


def sensitive_storage_locations(
    function: Function,
    facts: dict[str, int | None],
) -> tuple[
    dict[str, tuple[str, int | None]],
    frozenset[tuple[str, int | None]],
]:
    storage_locations = local_storage_locations(function)
    sensitive: set[tuple[str, int | None]] = set()
    changed = True
    while changed:
        changed = False
        for line in function.lines:
            parsed_store = stored_values_and_destination(line)
            if parsed_store is not None:
                values, destination = parsed_store
                if not any(
                    value in facts
                    or storage_locations.get(value) in sensitive
                    for value in values
                ):
                    continue
                location = (
                    storage_locations.get(destination)
                    if destination is not None
                    else None
                )
                if location is None:
                    raise VerificationError(
                        f"{function.name}: sensitive value escapes "
                        "through unresolved storage"
                    )
                if location[1] is None:
                    raise VerificationError(
                        f"{function.name}: sensitive value is stored through "
                        "an unknown local offset"
                    )
                if location not in sensitive:
                    sensitive.add(location)
                    changed = True
                continue

            transfer = memory_transfer_pointer_values(line)
            if transfer is None:
                continue
            destination, source = transfer
            source_location = storage_locations.get(source)
            if source_location not in sensitive:
                continue
            destination_location = storage_locations.get(destination)
            if destination_location is None:
                raise VerificationError(
                    f"{function.name}: sensitive slot is copied to "
                    "unresolved storage"
                )
            if destination_location[1] is None:
                raise VerificationError(
                    f"{function.name}: sensitive slot is copied through "
                    "an unknown local offset"
                )
            if destination_location not in sensitive:
                sensitive.add(destination_location)
                changed = True
    return storage_locations, frozenset(sensitive)


def validate_sensitive_non_escape(
    function: Function,
    facts: dict[str, int | None],
    verified_wipe_symbols: frozenset[str],
    allowed_call_lines: frozenset[str] = frozenset(),
    allowed_helper_symbols: frozenset[str] = frozenset(),
) -> None:
    storage_locations, sensitive_locations = sensitive_storage_locations(
        function,
        facts,
    )
    for line in function.lines:
        if re.match(r"\s*(?:ret|resume)\b", line) and any(
            value in facts
            or storage_locations.get(value) in sensitive_locations
            for value in ssa_tokens(line)
        ):
            raise VerificationError(
                f"{function.name}: sensitive provenance escapes through "
                "a function exit"
            )
        if line in allowed_call_lines:
            continue
        if re.search(r"\b(?:atomicrmw|cmpxchg)\b", line):
            operands = ssa_tokens(line)
            if any(
                value in facts
                or storage_locations.get(value) in sensitive_locations
                for value in operands
            ):
                raise VerificationError(
                    f"{function.name}: atomic operation can escape "
                    "sensitive provenance"
                )

        symbol = called_symbol(line)
        if symbol is None:
            if (
                re.search(
                    r"\b(?:(?:tail|musttail)\s+)?call\b",
                    line,
                )
                or
                re.search(r"\b(?:invoke|callbr)\b", line)
                or "asm sideeffect" in line
            ) and any(
                value in facts
                or storage_locations.get(value) in sensitive_locations
                for value in ssa_tokens(line)
            ):
                raise VerificationError(
                    f"{function.name}: unverified call form receives "
                    "sensitive provenance"
                )
            continue
        arguments = symbol_arguments(line, symbol)
        values: tuple[str | None, ...] = tuple(
            (
                argument_value(argument)
                if (
                    ssa_tokens(argument)
                    or re.search(
                        r"\b(?:poison|null|undef|true|false|-?\d+)\s*$",
                        argument,
                    )
                )
                else None
            )
            for argument in arguments
        )
        relevant = tuple(
            (argument, value)
            for argument, value in zip(arguments, values)
            if value in facts
            or storage_locations.get(value) in sensitive_locations
        )
        if not relevant:
            continue
        if (
            symbol in verified_wipe_symbols
            or symbol in allowed_helper_symbols
            or symbol.startswith("llvm.lifetime.")
            or symbol
            in (
                "swift_beginAccess",
                "swift_endAccess",
                "swift_deallocClassInstance",
                "free",
            )
        ):
            continue
        if (
            symbol in SHA256_UPDATE_SYMBOLS
            or symbol in SHA256_FINALIZE_IN_PLACE_SYMBOLS
            or symbol in CONSTANT_TIME_EQUAL_SYMBOLS
            or symbol in HMAC_FINALIZE_SYMBOLS
        ):
            continue
        if symbol.startswith(
            ("llvm.memcpy.", "llvm.memmove.", "llvm.memset.")
        ):
            continue
        if all(
            argument_type(argument) == "ptr"
            and "captures(none)" in argument
            and value in facts
            and storage_locations.get(value) not in sensitive_locations
            for argument, value in relevant
        ):
            continue
        raise VerificationError(
            f"{function.name}: {symbol} can capture sensitive provenance"
        )


def wipe_event(
    line: str,
    facts: dict[str, int | None],
    verified_wipe_symbols: frozenset[str] = SECURE_WIPE_SYMBOLS,
) -> tuple[int | None, int] | None:
    symbol = called_symbol(line)
    if symbol not in verified_wipe_symbols:
        return None
    arguments = symbol_arguments(line, symbol)
    if (
        len(arguments) != 2
        or argument_type(arguments[0]) != "ptr"
        or argument_type(arguments[1]) not in ("i32", "i64")
    ):
        return None
    pointer = pointer_argument_value(arguments[0])
    count = integer_argument_literal(arguments[1])
    if (
        pointer not in facts
        or facts[pointer] is None
        or count is None
    ):
        return None
    return facts[pointer], count


def call_uses_owner_provenance(
    line: str,
    facts: dict[str, int | None],
) -> bool:
    symbol = called_symbol(line)
    if symbol is None:
        return False
    return any(
        pointer_argument_value(argument) in facts
        for argument in symbol_arguments(line, symbol)
        if argument_type(argument) == "ptr"
    )


def lifecycle_event(
    line: str,
    owner: str,
    facts: dict[str, int | None],
) -> tuple[str, int | None] | None:
    symbol = called_symbol(line)
    if symbol is None:
        return None
    if symbol.startswith("llvm.lifetime.start"):
        event = "start"
    elif symbol.startswith("llvm.lifetime.end"):
        event = "end"
    else:
        return None
    arguments = symbol_arguments(line, symbol)
    if len(arguments) != 2:
        return None
    pointer = pointer_argument_value(arguments[1])
    if pointer not in facts:
        return None
    if pointer != owner and facts[pointer] != 0:
        raise VerificationError(
            f"lifetime {event} uses a non-exact owner alias"
        )
    if facts[pointer] != 0:
        raise VerificationError(
            f"lifetime {event} uses unresolved owner provenance"
        )
    return event, integer_argument_literal(arguments[0])


def range_mask(
    offset: int | None,
    byte_count: int | None,
    ranges: tuple[tuple[int, int], ...],
    owner_extent: int | None = None,
) -> int:
    full_mask = (1 << len(ranges)) - 1
    if offset is None:
        return full_mask
    extent = (
        owner_extent
        if owner_extent is not None
        else max(range_offset + count for range_offset, count in ranges)
    )
    if byte_count is None:
        if offset < 0 or offset >= extent:
            raise VerificationError(
                f"owner-derived memory access at {offset} "
                f"exceeds [0, {extent})"
            )
        return full_mask
    if byte_count < 0:
        raise VerificationError("negative derived memory access length")
    end = offset + byte_count
    if offset < 0 or end < offset or end > extent:
        raise VerificationError(
            f"owner-derived memory access [{offset}, {end}) "
            f"exceeds [0, {extent})"
        )
    if byte_count == 0:
        return 0
    mask = 0
    for index, (range_offset, range_count) in enumerate(ranges):
        range_end = range_offset + range_count
        if offset < range_end and range_offset < end:
            mask |= 1 << index
    return mask


def stored_type_byte_count(line: str) -> int | None:
    qualifiers = r"(?:\s+(?:atomic|volatile))*"
    scalar = re.match(rf"\s*store{qualifiers}\s+i(\d+)\s", line)
    if scalar:
        return max(1, (int(scalar.group(1)) + 7) // 8)
    vector = re.match(
        rf"\s*store{qualifiers}\s+<(\d+)\s+x\s+i(\d+)>\s",
        line,
    )
    if vector:
        return int(vector.group(1)) * max(
            1,
            (int(vector.group(2)) + 7) // 8,
        )
    return None


def loaded_type_byte_count(line: str) -> int | None:
    scalar = re.search(
        r"=\s+load(?:\s+(?:atomic|volatile))*\s+i(\d+),",
        line,
    )
    if scalar:
        return max(1, (int(scalar.group(1)) + 7) // 8)
    vector = re.search(
        r"=\s+load(?:\s+(?:atomic|volatile))*\s+"
        r"<(\d+)\s+x\s+i(\d+)>,",
        line,
    )
    if vector:
        return int(vector.group(1)) * max(
            1,
            (int(vector.group(2)) + 7) // 8,
        )
    return None


def memory_access_mask(
    line: str,
    facts: dict[str, int | None],
    ranges: tuple[tuple[int, int], ...],
    verified_wipe_symbols: frozenset[str] = SECURE_WIPE_SYMBOLS,
    owner_extent: int | None = None,
) -> int:
    symbol = called_symbol(line)
    if (
        (
            symbol is not None
            and (
                symbol.startswith("llvm.lifetime.")
                or symbol == "llvm.assume"
                or symbol.startswith("llvm.experimental.noalias.")
            )
        )
        or symbol in verified_wipe_symbols
        or symbol in ("swift_beginAccess", "swift_endAccess")
    ):
        return 0

    if re.match(r"\s*store\b", line):
        pointers = pointer_operands(line)
        if pointers and pointers[-1] in facts:
            return range_mask(
                facts[pointers[-1]],
                stored_type_byte_count(line),
                ranges,
                owner_extent,
            )
        return 0

    if re.search(r"=\s+load(?:\s+(?:atomic|volatile))*\b", line):
        pointers = pointer_operands(line)
        if pointers and pointers[-1] in facts:
            return range_mask(
                facts[pointers[-1]],
                loaded_type_byte_count(line),
                ranges,
                owner_extent,
            )
        return 0

    if re.search(r"(?:=\s+)?(?:atomicrmw|cmpxchg)\b", line):
        pointer = next(
            (
                value
                for value in pointer_operands(line)
                if value in facts
            ),
            None,
        )
        if pointer in facts:
            width = re.search(
                r"\b(?:atomicrmw\s+\w+|cmpxchg)\s+"
                r"ptr\b.*?,\s+i(\d+)\b",
                line,
            )
            byte_count = (
                max(1, (int(width.group(1)) + 7) // 8)
                if width is not None
                else None
            )
            return range_mask(
                facts[pointer],
                byte_count,
                ranges,
                owner_extent,
            )

    if symbol is not None and symbol.startswith("llvm.memset."):
        arguments = symbol_arguments(line, symbol)
        pointer = (
            pointer_argument_value(arguments[0])
            if len(arguments) >= 1
            else None
        )
        if pointer in facts:
            count = (
                integer_argument_literal(arguments[2])
                if len(arguments) >= 3
                else None
            )
            return range_mask(
                facts[pointer],
                count,
                ranges,
                owner_extent,
            )

    if (
        symbol is not None
        and symbol.startswith(("llvm.memcpy.", "llvm.memmove."))
    ):
        arguments = symbol_arguments(line, symbol)
        pointers = tuple(
            pointer_argument_value(argument)
            for argument in arguments[:2]
        )
        count = (
            integer_argument_literal(arguments[2])
            if len(arguments) >= 3
            else None
        )
        mask = 0
        for pointer in pointers:
            if pointer in facts:
                mask |= range_mask(
                    facts[pointer],
                    count,
                    ranges,
                    owner_extent,
                )
        return mask

    if "call " in line or "tail call " in line:
        derived = [
            token for token in ssa_tokens(line) if token in facts
        ]
        if derived and any(
            fragment in line
            for fragment in (
                "SHA256ContextV6update",
                "finalizeInPlace",
                "initializeFreshContexts",
                "finalizeAuthenticationCode",
            )
        ):
            return (1 << len(ranges)) - 1
        mask = 0
        for token in derived:
            mask |= range_mask(
                facts[token],
                None,
                ranges,
                owner_extent,
            )
        return mask
    return 0


def referenced_labels(line: str) -> tuple[str, ...]:
    result: list[str] = []
    for quoted, plain in re.findall(rf"label\s+%{LABEL}", line):
        result.append(quoted or plain)
    return tuple(result)


def block_successors(lines: tuple[str, ...]) -> tuple[str, ...] | None:
    for line in reversed(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith(";"):
            continue
        if stripped.startswith("ret ") or stripped == "ret void":
            return ()
        if stripped.startswith("unreachable"):
            return ()
        if stripped.startswith("br ") or stripped.startswith("switch "):
            labels = referenced_labels(stripped)
            return labels if labels else None
        return None
    return None


def block_is_unreachable(lines: tuple[str, ...]) -> bool:
    return any(line.strip().startswith("unreachable") for line in lines)


def block_has_return(lines: tuple[str, ...]) -> bool:
    return any(line.strip().startswith("ret ") for line in lines)


def reject_terminal_cycles(function: Function) -> None:
    blocks = function.blocks()
    entry = next(iter(blocks))
    reachable = reachable_blocks(function, entry)
    graph = {
        block: tuple(
            successor
            for successor in (block_successors(blocks[block]) or ())
            if successor in reachable
        )
        for block in reachable
    }
    index = 0
    indices: dict[str, int] = {}
    low_links: dict[str, int] = {}
    stack: list[str] = []
    on_stack: set[str] = set()
    components: list[set[str]] = []

    def visit(block: str) -> None:
        nonlocal index
        indices[block] = index
        low_links[block] = index
        index += 1
        stack.append(block)
        on_stack.add(block)
        for successor in graph[block]:
            if successor not in indices:
                visit(successor)
                low_links[block] = min(
                    low_links[block],
                    low_links[successor],
                )
            elif successor in on_stack:
                low_links[block] = min(
                    low_links[block],
                    indices[successor],
                )
        if low_links[block] != indices[block]:
            return
        component: set[str] = set()
        while True:
            member = stack.pop()
            on_stack.remove(member)
            component.add(member)
            if member == block:
                break
        components.append(component)

    for block in reachable:
        if block not in indices:
            visit(block)

    for component in components:
        cyclic = len(component) > 1 or any(
            block in graph[block] for block in component
        )
        exits = {
            successor
            for block in component
            for successor in graph[block]
            if successor not in component
        }
        if cyclic and not exits:
            raise VerificationError(
                f"{function.name}: reachable CFG contains a terminal cycle"
            )


def exact_span_byte_count(
    assignments: dict[str, str],
    value: str,
    start: str,
    end: str,
    seen: frozenset[str] = frozenset(),
) -> bool:
    if value in seen:
        return False
    expression = assignments.get(value)
    if expression is None:
        return False

    direct = re.fullmatch(
        rf"sub(?:\s+\w+)*\s+i(?:32|64)\s+"
        rf"{re.escape(end)},\s+{re.escape(start)}",
        expression,
    )
    if direct:
        return True

    select = re.fullmatch(
        rf"select i1 ({SSA}), i(?:32|64) (0|{SSA}), "
        rf"i(?:32|64) (0|{SSA})",
        expression,
    )
    if not select:
        return False
    condition, first, second = select.groups()
    condition_expression = assignments.get(condition, "")
    null_gate = re.fullmatch(
        rf"icmp eq i(?:32|64) (?:{re.escape(start)}, 0|0, "
        rf"{re.escape(start)})",
        condition_expression,
    )
    if not null_gate:
        return False
    if first != "0" or second == "0":
        return False
    return exact_span_byte_count(
        assignments,
        second,
        start,
        end,
        seen | {value},
    )


def analyze_outlined_wipe_helper(
    function: Function,
    pointer: str,
    start: str,
    end: str,
    verified_wipe_symbols: frozenset[str] = SECURE_WIPE_SYMBOLS,
) -> None:
    reject_terminal_cycles(function)
    parameter_types = formal_parameter_types(function)
    if (
        not is_swiftcc_void_function(function)
        or parameter_types
        not in (("ptr", "i32", "i32"), ("ptr", "i64", "i64"))
    ):
        raise VerificationError(
            f"{function.name}: outlined wipe helper must be swiftcc void "
            "with an exact pointer/count signature"
        )
    blocks = function.blocks()
    entry = next(iter(blocks))
    facts = pointer_facts(
        function,
        pointer,
        ((start, 0), (end, 64)),
        strict_storage_aliases=True,
    )
    assignments = assignment_map(function)
    validate_sensitive_non_escape(
        function,
        facts,
        verified_wipe_symbols,
    )
    wipe_calls = [
        line
        for line in function.lines
        if called_symbol(line) in verified_wipe_symbols
    ]
    if len(wipe_calls) != 1:
        raise VerificationError(
            f"{function.name}: outlined wipe helper must call "
            "one verified wipe"
        )
    wipe_block = block_for_line(function, wipe_calls[0].strip())
    if (
        wipe_block is None
        or not all_paths_reach_block(function, entry, wipe_block)
    ):
        raise VerificationError(
            f"{function.name}: outlined wipe can be bypassed"
        )
    wipe_block_lines = blocks[wipe_block]
    if block_is_unreachable(wipe_block_lines):
        raise VerificationError(
            f"{function.name}: outlined wipe cannot return"
        )
    if not block_has_return(wipe_block_lines):
        successors = block_successors(wipe_block_lines)
        if (
            successors is None
            or not successors
            or not all(
                all_paths_return_without_effects(function, successor)
                for successor in successors
            )
        ):
            raise VerificationError(
                f"{function.name}: outlined wipe has no finite clean return"
            )
    pending = deque([(entry, True)])
    visited: set[tuple[str, bool]] = set()
    observed_wipe = False

    while pending:
        block_name, dirty = pending.popleft()
        if (block_name, dirty) in visited:
            continue
        visited.add((block_name, dirty))
        lines = blocks[block_name]
        for line in lines:
            symbol = called_symbol(line)
            if symbol is not None and symbol not in verified_wipe_symbols:
                raise VerificationError(
                    f"{function.name}: outlined wipe helper calls "
                    "an unverified function"
                )
            if (
                re.match(r"\s*(?:store|.*=\s*load)\b", line)
                or "llvm.memset" in line
                or "llvm.memcpy" in line
                or "llvm.memmove" in line
                or re.search(r"\b(?:atomicrmw|cmpxchg)\b", line)
            ):
                raise VerificationError(
                    f"{function.name}: outlined wipe helper contains "
                    "an unverified memory operation"
                )
            if symbol in verified_wipe_symbols:
                if not is_unassigned_swiftcc_void_call(line, symbol):
                    raise VerificationError(
                        f"{function.name}: wipe call must be unassigned "
                        "swiftcc void"
                    )
                arguments = call_argument_values(line, symbol)
                argument_types = tuple(
                    argument_type(argument) or ""
                    for argument in symbol_arguments(line, symbol)
                )
                if (
                    len(arguments) != 2
                    or argument_types
                    != (parameter_types[0], parameter_types[1])
                    or facts.get(arguments[0]) != 0
                    or not exact_span_byte_count(
                        assignments,
                        arguments[1],
                        start,
                        end,
                    )
                ):
                    raise VerificationError(
                        f"{function.name}: outlined wipe lacks exact span provenance"
                    )
                if not dirty:
                    raise VerificationError(
                        f"{function.name}: outlined span is wiped more than once"
                    )
                dirty = False
                observed_wipe = True
                continue

            access = memory_access_mask(
                line,
                facts,
                ((0, 64),),
                verified_wipe_symbols,
                64,
            )
            if access:
                dirty = True

        if block_is_unreachable(lines):
            continue
        if block_has_return(lines):
            if dirty:
                raise VerificationError(
                    f"{function.name}: outlined wipe helper returns dirty"
                )
            continue
        successors = block_successors(lines)
        if successors is None:
            raise VerificationError(
                f"{function.name}: unsupported outlined wipe terminator"
            )
        for successor in successors:
            pending.append((successor, dirty))

    if not observed_wipe:
        raise VerificationError(
            f"{function.name}: outlined wipe helper has no verified wipe"
        )


def analyze_outlined_cleanup_closure(
    function: Function,
    start: str,
    end: str,
    helper_symbol: str,
    verified_wipe_symbols: frozenset[str] = SECURE_WIPE_SYMBOLS,
) -> None:
    reject_terminal_cycles(function)
    if not is_swiftcc_void_function(function):
        raise VerificationError(
            f"{function.name}: outlined cleanup closure must be swiftcc void"
        )
    blocks = function.blocks()
    entry = next(iter(blocks))
    facts = pointer_facts(
        function,
        start,
        ((end, 64),),
        strict_storage_aliases=True,
    )
    validate_sensitive_non_escape(
        function,
        facts,
        verified_wipe_symbols,
        allowed_helper_symbols=frozenset((helper_symbol,)),
    )
    pending = deque([(entry, True)])
    visited: set[tuple[str, bool]] = set()
    observed_cleanup = False

    while pending:
        block_name, dirty = pending.popleft()
        if (block_name, dirty) in visited:
            continue
        visited.add((block_name, dirty))
        lines = blocks[block_name]
        for line in lines:
            symbol = called_symbol(line)
            if symbol == helper_symbol:
                if not is_unassigned_swiftcc_void_call(line, symbol):
                    raise VerificationError(
                        f"{function.name}: cleanup helper call must be "
                        "unassigned swiftcc void"
                    )
                arguments = call_argument_values(line, symbol)
                argument_types = tuple(
                    argument_type(argument) or ""
                    for argument in symbol_arguments(line, symbol)
                )
                width = formal_parameter_types(function)[
                    formal_parameters(function).index(start)
                ]
                if (
                    len(arguments) != 3
                    or argument_types != ("ptr", width, width)
                    or facts.get(arguments[0]) != 0
                    or arguments[1] != start
                    or arguments[2] != end
                ):
                    raise VerificationError(
                        f"{function.name}: outlined cleanup call loses span provenance"
                    )
                if not dirty:
                    raise VerificationError(
                        f"{function.name}: outlined cleanup runs twice on one path"
                    )
                dirty = False
                observed_cleanup = True
                continue
            if symbol in verified_wipe_symbols:
                if any(
                    argument in facts
                    for argument in call_argument_values(line, symbol)
                ):
                    raise VerificationError(
                        f"{function.name}: unverified direct key-block wipe"
                    )

            access = memory_access_mask(
                line,
                facts,
                ((0, 64),),
                verified_wipe_symbols,
                64,
            )
            if access:
                dirty = True

        if block_is_unreachable(lines):
            continue
        if block_has_return(lines):
            if dirty:
                raise VerificationError(
                    f"{function.name}: key block reaches return without cleanup"
                )
            continue
        successors = block_successors(lines)
        if successors is None:
            raise VerificationError(
                f"{function.name}: unsupported outlined closure terminator"
            )
        for successor in successors:
            pending.append((successor, dirty))

    if not observed_cleanup:
        raise VerificationError(
            f"{function.name}: no verified outlined cleanup call"
        )


def outlined_key_cleanup_lines(
    wrapper: Function,
    owner: str,
    functions_by_name: dict[str, Function],
    verified_wipe_symbols: frozenset[str] = SECURE_WIPE_SYMBOLS,
) -> tuple[frozenset[str], Function | None]:
    facts = pointer_facts(
        wrapper,
        owner,
        fail_unresolved_sensitive_stores=True,
    )
    candidates: list[tuple[str, Function, int, int]] = []
    for line in wrapper.lines:
        symbol = called_symbol(line)
        if (
            symbol is None
            or symbol not in functions_by_name
            or "initializeFreshContexts" not in symbol
            or "EfU_" not in symbol
            or "$defer" in symbol
        ):
            continue
        arguments = call_argument_values(line, symbol)
        derived = [
            (index, facts[value])
            for index, value in enumerate(arguments)
            if value in facts
        ]
        starts = [index for index, offset in derived if offset == 0]
        ends = [index for index, offset in derived if offset == 64]
        if len(derived) == 2 and len(starts) == 1 and len(ends) == 1:
            candidates.append(
                (line, functions_by_name[symbol], starts[0], ends[0])
            )
    if not candidates:
        return frozenset(), None
    if len(candidates) != 1:
        raise VerificationError(
            f"{wrapper.name}: ambiguous outlined key-block owner"
        )

    wrapper_call, closure, start_index, end_index = candidates[0]
    if not is_unassigned_swiftcc_void_call(
        wrapper_call,
        closure.name,
    ):
        raise VerificationError(
            f"{wrapper.name}: outlined closure call must be unassigned "
            "swiftcc void"
        )
    if not is_swiftcc_void_function(closure):
        raise VerificationError(
            f"{closure.name}: outlined closure must be swiftcc void"
        )
    parameters = formal_parameters(closure)
    if max(start_index, end_index) >= len(parameters):
        raise VerificationError(
            f"{closure.name}: outlined span parameters are missing"
        )
    start = parameters[start_index]
    end = parameters[end_index]
    closure_facts = pointer_facts(closure, start, ((end, 64),))

    helper_calls: list[tuple[str, Function]] = []
    for line in closure.lines:
        symbol = called_symbol(line)
        if (
            symbol is None
            or symbol not in functions_by_name
            or "$defer" not in symbol
        ):
            continue
        arguments = call_argument_values(line, symbol)
        if (
            len(arguments) == 3
            and closure_facts.get(arguments[0]) == 0
            and arguments[1] == start
            and arguments[2] == end
        ):
            helper_calls.append((symbol, functions_by_name[symbol]))
    helper_symbols = {symbol for symbol, _ in helper_calls}
    if len(helper_symbols) != 1:
        raise VerificationError(
            f"{closure.name}: cleanup helper is missing or ambiguous"
        )
    helper_symbol = next(iter(helper_symbols))
    helper = functions_by_name[helper_symbol]
    helper_parameters = formal_parameters(helper)
    helper_types = formal_parameter_types(helper)
    start_type = formal_parameter_types(closure)[start_index]
    end_type = formal_parameter_types(closure)[end_index]
    if (
        len(helper_parameters) != 3
        or helper_types not in (("ptr", "i32", "i32"), ("ptr", "i64", "i64"))
        or start_type != helper_types[1]
        or end_type != helper_types[2]
    ):
        raise VerificationError(
            f"{helper.name}: cleanup helper signature is not exact"
        )
    analyze_outlined_wipe_helper(
        helper,
        helper_parameters[0],
        helper_parameters[1],
        helper_parameters[2],
        verified_wipe_symbols,
    )
    analyze_outlined_cleanup_closure(
        closure,
        start,
        end,
        helper_symbol,
        verified_wipe_symbols,
    )
    return frozenset((wrapper_call,)), closure


def analyze_scoped_owner(
    function: Function,
    owner: str,
    ranges: tuple[tuple[int, int], ...],
    lifetime_byte_count: int,
    cleanup_lines: frozenset[str] = frozenset(),
    requires_lifetime_on_return: bool = False,
    verified_wipe_symbols: frozenset[str] = SECURE_WIPE_SYMBOLS,
) -> None:
    reject_terminal_cycles(function)
    blocks = function.blocks()
    entry = next(iter(blocks))
    facts = pointer_facts(
        function,
        owner,
        fail_unresolved_sensitive_stores=True,
    )
    validate_sensitive_non_escape(
        function,
        facts,
        verified_wipe_symbols,
        allowed_call_lines=cleanup_lines,
    )
    full_mask = (1 << len(ranges)) - 1
    pending = deque([(entry, False, 0, False)])
    visited: set[tuple[str, bool, int, bool]] = set()
    observed_start = False
    observed_end = False
    observed_wipes = 0

    while pending:
        block_name, active, dirty, ever_started = pending.popleft()
        state_key = (block_name, active, dirty, ever_started)
        if state_key in visited:
            continue
        visited.add(state_key)
        lines = blocks.get(block_name)
        if lines is None:
            raise VerificationError(
                f"{function.name}: unknown successor {block_name}"
        )

        for line in lines:
            if line in cleanup_lines:
                if not active:
                    raise VerificationError(
                        f"{function.name}: outlined cleanup is outside lifetime"
                    )
                dirty = 0
                observed_wipes = full_mask
                continue

            lifecycle = lifecycle_event(line, owner, facts)
            if lifecycle is not None:
                event, observed_byte_count = lifecycle
                if observed_byte_count != lifetime_byte_count:
                    raise VerificationError(
                        f"{function.name}: {owner} has lifetime size "
                        f"{observed_byte_count}, expected {lifetime_byte_count}"
                    )
            else:
                event = None
            if event == "start":
                observed_start = True
                if active:
                    raise VerificationError(
                        f"{function.name}: {owner} starts while live"
                    )
                active = True
                dirty = full_mask
                ever_started = True
                continue
            if event == "end":
                observed_end = True
                if not active or dirty:
                    raise VerificationError(
                        f"{function.name}: {owner} ends before exact cleanup"
                    )
                active = False
                continue

            wipe = wipe_event(line, facts, verified_wipe_symbols)
            if (
                called_symbol(line) in verified_wipe_symbols
                and wipe is None
                and call_uses_owner_provenance(line, facts)
            ):
                raise VerificationError(
                    f"{function.name}: {owner} reaches a non-exact "
                    "SecureWipe call"
                )
            if wipe is not None:
                if not active:
                    raise VerificationError(
                        f"{function.name}: {owner} is wiped outside its lifetime"
                    )
                try:
                    range_index = ranges.index(wipe)
                except ValueError as error:
                    raise VerificationError(
                        f"{function.name}: {owner} has non-exact wipe {wipe}"
                    ) from error
                dirty &= ~(1 << range_index)
                observed_wipes |= 1 << range_index
                continue

            access = memory_access_mask(
                line,
                facts,
                ranges,
                verified_wipe_symbols,
                lifetime_byte_count,
            )
            if access:
                if not active:
                    raise VerificationError(
                        f"{function.name}: {owner} is accessed after lifetime end"
                    )
                dirty |= access

        if block_is_unreachable(lines):
            continue
        if block_has_return(lines):
            if active:
                raise VerificationError(
                    f"{function.name}: {owner} remains live at return"
                )
            if requires_lifetime_on_return and not ever_started:
                raise VerificationError(
                    f"{function.name}: {owner} reaches return without lifetime"
                )
            continue
        successors = block_successors(lines)
        if successors is None:
            raise VerificationError(
                f"{function.name}: unsupported terminator in {block_name}"
            )
        for successor in successors:
            pending.append((successor, active, dirty, ever_started))

    if not observed_start or not observed_end or observed_wipes != full_mask:
        raise VerificationError(
            f"{function.name}: {owner} lacks reachable lifetime or exact wipes"
        )


def analyze_hmac_storage_deinit(
    function: Function,
    verified_helpers: frozenset[str] = frozenset(),
    verified_wipe_symbols: frozenset[str] = SECURE_WIPE_SYMBOLS,
) -> None:
    reject_terminal_cycles(function)
    ranges = ((16, 32), (48, 64), (128, 32), (160, 64))
    facts = pointer_facts(function, "%0")
    validate_sensitive_non_escape(
        function,
        facts,
        verified_wipe_symbols,
        allowed_helper_symbols=verified_helpers,
    )
    blocks = function.blocks()
    entry = next(iter(blocks))
    full_mask = (1 << len(ranges)) - 1
    pending = deque([(entry, full_mask)])
    visited: set[tuple[str, int]] = set()
    observed_wipes = 0

    while pending:
        block_name, dirty = pending.popleft()
        if (block_name, dirty) in visited:
            continue
        visited.add((block_name, dirty))
        lines = blocks[block_name]
        for line in lines:
            symbol = called_symbol(line)
            helper = symbol if symbol in verified_helpers else None
            if helper is not None:
                arguments = call_argument_values(line, helper)
                argument_types = tuple(
                    argument_type(argument) or ""
                    for argument in symbol_arguments(line, helper)
                )
                if (
                    not is_unassigned_swiftcc_void_call(line, helper)
                    or arguments != ("%0",)
                    or argument_types != ("ptr",)
                ):
                    raise VerificationError(
                        f"{function.name}: cleanup helper call is not exact"
                    )
                dirty = 0
                observed_wipes = full_mask
                continue
            wipe = wipe_event(line, facts, verified_wipe_symbols)
            if (
                called_symbol(line) in verified_wipe_symbols
                and wipe is None
                and call_uses_owner_provenance(line, facts)
            ):
                raise VerificationError(
                    f"{function.name}: backing reaches a non-exact "
                    "SecureWipe call"
                )
            if wipe is not None:
                try:
                    index = ranges.index(wipe)
                except ValueError as error:
                    raise VerificationError(
                        f"{function.name}: unexpected backing wipe {wipe}"
                    ) from error
                dirty &= ~(1 << index)
                observed_wipes |= 1 << index
                continue
            if symbol in ("swift_deallocClassInstance", "free"):
                arguments = symbol_arguments(line, symbol)
                argument_types = tuple(
                    argument_type(argument) or ""
                    for argument in arguments
                )
                argument_values = tuple(
                    argument_value(argument) for argument in arguments
                )
                exact_deallocation = (
                    assignment(line) is None
                    and re.match(
                        r"\s*(?:tail\s+)?call void\b",
                        line,
                    )
                    is not None
                    and (
                        (
                            symbol == "swift_deallocClassInstance"
                            and argument_types
                            in (
                                ("ptr", "i32", "i32"),
                                ("ptr", "i64", "i64"),
                            )
                            and len(argument_values) == 3
                            and facts.get(argument_values[0]) == 0
                            and integer_argument_literal(arguments[1])
                            == HMAC_SHA256_STORAGE_BYTE_COUNT
                            and (
                                integer_argument_literal(arguments[2])
                                == HMAC_SHA256_STORAGE_ALIGNMENT_MASK
                            )
                        )
                        or (
                            symbol == "free"
                            and argument_types == ("ptr",)
                            and len(argument_values) == 1
                            and facts.get(argument_values[0]) == 0
                        )
                    )
                )
                if not exact_deallocation:
                    raise VerificationError(
                        f"{function.name}: backing deallocation call is "
                        "not exact"
                    )
                if dirty:
                    raise VerificationError(
                        f"{function.name}: backing deallocated before all wipes"
                    )
                continue
            dirty |= memory_access_mask(
                line,
                facts,
                ranges,
                verified_wipe_symbols,
                HMAC_SHA256_STORAGE_BYTE_COUNT,
            )

        if block_is_unreachable(lines):
            continue
        if block_has_return(lines):
            if dirty:
                raise VerificationError(
                    f"{function.name}: backing returns before all wipes"
                )
            continue
        successors = block_successors(lines)
        if successors is None:
            raise VerificationError(
                f"{function.name}: unsupported deinit terminator"
            )
        for successor in successors:
            pending.append((successor, dirty))

    if observed_wipes != full_mask:
        raise VerificationError(
            f"{function.name}: inner and outer backing ranges are not distinct"
        )


def alloca_owners(
    function: Function,
    name_fragments: tuple[str, ...],
    type_fragment: str,
) -> tuple[str, ...]:
    owners: list[str] = []
    for line in function.lines:
        parsed = assignment(line)
        if not parsed or "alloca " not in parsed[1]:
            continue
        owner, expression = parsed
        if type_fragment not in expression:
            continue
        if any(fragment in owner for fragment in name_fragments):
            owners.append(owner)
    return tuple(dict.fromkeys(owners))


def assignment_map(function: Function) -> dict[str, str]:
    return {
        result: expression
        for line in function.lines
        if (parsed := assignment(line))
        for result, expression in (parsed,)
    }


def dependencies(
    assignments: dict[str, str],
    value: str,
) -> set[str]:
    result: set[str] = {value}
    pending = [value]
    while pending:
        current = pending.pop()
        expression = assignments.get(current)
        if expression is None:
            continue
        for token in ssa_tokens(expression):
            if token not in result:
                result.add(token)
                pending.append(token)
    return result


def branch_successors(function: Function, condition: str) -> tuple[str, str] | None:
    for lines in function.blocks().values():
        for line in lines:
            if re.search(rf"\bbr i1 {re.escape(condition)}\b", line):
                labels = referenced_labels(line)
                if len(labels) == 2:
                    return labels[0], labels[1]
    return None


def reachable_blocks(function: Function, start: str) -> set[str]:
    blocks = function.blocks()
    result: set[str] = set()
    pending = [start]
    while pending:
        block = pending.pop()
        if block in result:
            continue
        result.add(block)
        successors = block_successors(blocks[block])
        if successors:
            pending.extend(successors)
    return result


def pointer_path(
    value: str,
    assignments: dict[str, str],
    seen: frozenset[str] = frozenset(),
    roots: tuple[str, str] = ("%0", "%2"),
) -> tuple[str, tuple[str, ...]] | None:
    """Return a symbolic input root and GEP index path for a pointer SSA value."""
    if value in roots:
        return value, ()
    if value in seen:
        return None
    expression = assignments.get(value)
    if expression is None:
        return None
    next_seen = seen | {value}
    if expression.startswith("getelementptr"):
        bases = pointer_operands(expression)
        if not bases:
            return None
        base = pointer_path(bases[0], assignments, next_seen, roots)
        if base is None:
            return None
        indices = tuple(
            re.findall(rf"\bi(?:32|64)\s+(-?\d+|{SSA})", expression)
        )
        return base[0], base[1] + indices
    if expression.startswith(
        ("inttoptr", "ptrtoint", "bitcast", "addrspacecast", "freeze ")
    ):
        operands = ssa_tokens(expression)
        if not operands:
            return None
        return pointer_path(operands[-1], assignments, next_seen, roots)
    return None


def depends_on(
    assignments: dict[str, str],
    value: str,
    root: str,
) -> bool:
    return root in dependencies(assignments, value)


def verify_constant_time(function: Function) -> None:
    if "memcmp" in function.text or "bcmp" in function.text:
        raise VerificationError(f"{function.name}: library comparison detected")

    lhs_facts = pointer_facts(function, "%0")
    rhs_facts = pointer_facts(function, "%2")
    assignments = assignment_map(function)
    lhs_loads: set[str] = set()
    rhs_loads: set[str] = set()
    load_blocks: dict[str, str] = {}
    data_load_blocks: set[str] = set()
    current_block = ""
    for line in function.lines:
        label_match = re.match(r'^("[^"]+"|[-.$A-Za-z0-9_]+):', line)
        if label_match:
            current_block = label_match.group(1).strip('"')
        parsed = assignment(line)
        if not parsed or "= load " not in f"= {parsed[1]}":
            continue
        pointers = pointer_operands(line)
        if not pointers:
            continue
        pointer = pointers[-1]
        lhs = pointer in lhs_facts and pointer not in rhs_facts
        rhs = pointer in rhs_facts and pointer not in lhs_facts
        if lhs or rhs:
            if lhs:
                lhs_loads.add(parsed[0])
            if rhs:
                rhs_loads.add(parsed[0])
            load_blocks[parsed[0]] = current_block
            data_load_blocks.add(current_block)
    data_loads = lhs_loads | rhs_loads
    if not lhs_loads or not rhs_loads:
        raise VerificationError(
            f"{function.name}: comparison does not load both inputs"
        )

    xor_pairs: list[tuple[str, str, str]] = []
    for result, expression in assignments.items():
        if not expression.startswith("xor "):
            continue
        operands = ssa_tokens(expression)
        lhs_operands = tuple(value for value in operands if value in lhs_loads)
        rhs_operands = tuple(value for value in operands if value in rhs_loads)
        if len(lhs_operands) == 1 and len(rhs_operands) == 1:
            xor_pairs.append((result, lhs_operands[0], rhs_operands[0]))
    if not xor_pairs:
        raise VerificationError(
            f"{function.name}: no paired input XOR reduction"
        )
    paired_lhs = [pair[1] for pair in xor_pairs]
    paired_rhs = [pair[2] for pair in xor_pairs]
    if len(set(paired_lhs)) != len(paired_lhs) or len(set(paired_rhs)) != len(
        paired_rhs
    ):
        raise VerificationError(
            f"{function.name}: an input load participates in multiple XORs"
        )
    if set(paired_lhs) != lhs_loads or set(paired_rhs) != rhs_loads:
        raise VerificationError(
            f"{function.name}: an input load is not paired in the reduction"
        )
    for _, lhs_load, rhs_load in xor_pairs:
        lhs_path = pointer_path(
            pointer_operands(next(
                line
                for line in function.lines
                if assignment(line)
                and assignment(line)[0] == lhs_load
            ))[-1],
            assignments,
        )
        rhs_path = pointer_path(
            pointer_operands(next(
                line
                for line in function.lines
                if assignment(line)
                and assignment(line)[0] == rhs_load
            ))[-1],
            assignments,
        )
        if (
            lhs_path is None
            or rhs_path is None
            or lhs_path[0] != "%0"
            or rhs_path[0] != "%2"
            or lhs_path[1] != rhs_path[1]
        ):
            raise VerificationError(
                f"{function.name}: input XOR operands do not share an index path"
            )

    tainted = set(data_loads)
    changed = True
    while changed:
        changed = False
        for result, expression in assignments.items():
            if result in tainted:
                continue
            if any(token in tainted for token in ssa_tokens(expression)):
                if expression.startswith("getelementptr"):
                    raise VerificationError(
                        f"{function.name}: secret data controls an address"
                    )
                tainted.add(result)
                changed = True

    for line in function.lines:
        if re.search(r"\b(?:br i1|switch)\b", line):
            conditions = ssa_tokens(line.split("label", 1)[0])
            if any(condition in tainted for condition in conditions):
                raise VerificationError(
                    f"{function.name}: secret data controls a branch"
                )
        if re.match(r"\s*store\b", line):
            stored = ssa_tokens(line.split(", ptr", 1)[0])
            if any(value in tainted for value in stored):
                raise VerificationError(
                    f"{function.name}: secret reduction escapes to memory"
                )
        if "call " in line:
            values = set(ssa_tokens(line))
            if values & tainted and "llvm.vector.reduce.or" not in line:
                raise VerificationError(
                    f"{function.name}: secret data reaches an unknown call"
                )

    final_comparisons: set[str] = set()
    for result, expression in assignments.items():
        match = re.fullmatch(
            rf"icmp eq i(?:8|16|32|64) ({SSA}|0), ({SSA}|0)",
            expression,
        )
        if not match:
            continue
        first, second = match.groups()
        reduction = second if first == "0" else first
        if reduction != "0" and reduction in tainted and (
            first == "0" or second == "0"
        ):
            final_comparisons.add(result)
    if len(final_comparisons) != 1:
        raise VerificationError(
            f"{function.name}: reduction must be compared with equality to zero"
        )
    final_comparison = next(iter(final_comparisons))
    for result, expression in assignments.items():
        if result in tainted and re.match(r"icmp ne ", expression):
            if any(token in tainted for token in ssa_tokens(expression)):
                raise VerificationError(
                    f"{function.name}: reduction polarity is inverted"
                )

    return_values = {
        token
        for line in function.lines
        if line.strip().startswith("ret i1 ")
        for token in ssa_tokens(line)
    }
    returned_dependencies = set().union(
        *(dependencies(assignments, value) for value in return_values)
    )
    if final_comparison not in returned_dependencies:
        raise VerificationError(
            f"{function.name}: equality result does not feed the return value"
        )
    for value in returned_dependencies:
        expression = assignments.get(value, "")
        if re.match(r"xor i1 ", expression):
            raise VerificationError(
                f"{function.name}: equality result is inverted before return"
            )

    length_condition = None
    for result, expression in assignments.items():
        if re.search(
            r"icmp eq i(?:32|64) %1, %3|icmp eq i(?:32|64) %3, %1",
            expression,
        ):
            length_condition = result
            break
    if length_condition is None:
        raise VerificationError(
            f"{function.name}: missing pre-load equal-length gate"
        )
    successors = branch_successors(function, length_condition)
    if successors is None:
        raise VerificationError(
            f"{function.name}: length gate does not control the CFG"
        )
    mismatch_blocks = reachable_blocks(function, successors[1])
    if mismatch_blocks & data_load_blocks:
        raise VerificationError(
            f"{function.name}: mismatch path can read secret data"
        )
    equal_blocks = reachable_blocks(function, successors[0])
    dominator_map = dominators(function)
    if any(
        block not in equal_blocks
        or branch_block not in dominator_map.get(block, set())
        for block in data_load_blocks
        for branch_block in (branch_for_condition(function, length_condition) or ("",))[0:1]
    ):
        raise VerificationError(
            f"{function.name}: input loads bypass the equal-length gate"
        )

    paired_blocks = {load_blocks[value] for value in data_loads}
    cyclic = cyclic_blocks(function)
    if not paired_blocks <= cyclic:
        raise VerificationError(
            f"{function.name}: paired input loads are not covered by a loop"
        )
    if not any(
        any(
            "icmp " in line
            and any(
                token == "%1" or depends_on(assignments, token, "%1")
                for token in ssa_tokens(line)
            )
            for line in function.blocks()[block]
        )
        for block in paired_blocks
    ):
        raise VerificationError(
            f"{function.name}: reduction loop is not bounded by lhs.count"
        )


def block_for_line(function: Function, needle: str) -> str | None:
    current = None
    for line in function.lines:
        match = re.match(r'^("[^"]+"|[-.$A-Za-z0-9_]+):', line)
        if match:
            current = match.group(1).strip('"')
        elif needle in line:
            return current
    return None


def cyclic_blocks(function: Function) -> set[str]:
    blocks = function.blocks()
    cyclic: set[str] = set()
    for block in blocks:
        for successor in block_successors(blocks[block]) or ():
            if block in reachable_blocks(function, successor):
                cyclic.add(block)
                cyclic.add(successor)
    return cyclic


def dominators(function: Function) -> dict[str, set[str]]:
    blocks = function.blocks()
    entry = next(iter(blocks))
    predecessors: dict[str, set[str]] = {block: set() for block in blocks}
    for block, lines in blocks.items():
        for successor in block_successors(lines) or ():
            predecessors[successor].add(block)
    all_blocks = set(blocks)
    result = {
        block: ({entry} if block == entry else set(all_blocks))
        for block in blocks
    }
    changed = True
    while changed:
        changed = False
        for block in blocks:
            if block == entry:
                continue
            incoming = predecessors[block]
            new = {block}
            if incoming:
                new |= set.intersection(*(result[item] for item in incoming))
            if new != result[block]:
                result[block] = new
                changed = True
    return result


def span_base_and_count(
    function: Function,
    span: str,
) -> tuple[str | None, int | None]:
    facts = pointer_facts(function, span)
    base: str | None = None
    count: int | None = None
    for line in function.lines:
        if not re.match(r"\s*store\b", line):
            continue
        pointers = pointer_operands(line)
        if not pointers or pointers[-1] not in facts:
            continue
        offset = facts[pointers[-1]]
        values = ssa_tokens(line.split(", ptr", 1)[0])
        literals = re.findall(r"store i(?:32|64)\s+(\d+)", line)
        if offset == 0 and values:
            base = values[-1]
        elif offset in (4, 8) and literals:
            count = int(literals[0])
    return base, count


def verify_partial_copy_bounds(
    function: Function,
    copy_line: str,
    count: str,
    count_dependencies: set[str],
) -> None:
    """Prove that the exact copy path is guarded by 0 <= count < 32."""
    copy_block = block_for_line(function, copy_line.strip())
    if copy_block is None:
        raise VerificationError(
            f"{function.name}: partial copy block is not identifiable"
        )
    dom = dominators(function)
    lower_guard = False
    upper_guard = False
    assignments = assignment_map(function)
    for result, expression in assignments.items():
        match = re.fullmatch(
            rf"icmp slt i(?:32|64) ({SSA}), (-?\d+)",
            expression,
        )
        if not match:
            continue
        candidate, literal = match.groups()
        if candidate not in count_dependencies:
            continue
        branch = branch_for_condition(function, result)
        if branch is None or branch[0] not in dom.get(copy_block, set()):
            continue
        dominated_by_copy = dom.get(copy_block, set())
        if literal == "0":
            if (
                branch[2] in dominated_by_copy
                and branch[1] not in dominated_by_copy
            ):
                lower_guard = True
        elif literal == "32":
            if (
                branch[1] in dominated_by_copy
                and branch[2] not in dominated_by_copy
            ):
                upper_guard = True
    if not lower_guard:
        raise VerificationError(
            f"{function.name}: partial copy lacks a dominating negative-count guard"
        )
    if not upper_guard:
        raise VerificationError(
            f"{function.name}: partial copy lacks a dominating 32-byte clamp"
        )


def verify_hkdf_output(function: Function) -> None:
    full_blocks = alloca_owners(
        function,
        ("fullBlock",),
        "SIMD32",
    )
    if len(full_blocks) != 1:
        raise VerificationError(f"{function.name}: missing partial block owner")
    full_block = full_blocks[0]
    full_facts = pointer_facts(function, full_block)

    output_base = None
    output_count = None
    for line in function.lines:
        parsed = assignment(line)
        if not parsed or not parsed[1].startswith("load i"):
            continue
        pointers = pointer_operands(line)
        if pointers and pointers[-1] == "%4":
            if "getelementptr" in parsed[1]:
                continue
            output_base = parsed[0]
            break
    for line in function.lines:
        parsed = assignment(line)
        if not parsed or not parsed[1].startswith("load i"):
            continue
        pointers = pointer_operands(line)
        if pointers and pointers[-1].endswith("._count"):
            output_count = parsed[0]
            break
    if output_base is None or output_count is None:
        raise VerificationError(
            f"{function.name}: caller output fields are not identifiable"
        )
    output_facts = pointer_facts(function, output_base)

    block_outputs = alloca_owners(
        function,
        ("blockOutput",),
        "MutableSpan",
    )
    direct_span = False
    partial_span = False
    for span in block_outputs:
        base, count = span_base_and_count(function, span)
        if base is None or count != 32:
            continue
        finalized = any(
            "finalizeInPlace" in line and span in line
            for line in function.lines
        )
        if not finalized:
            continue
        if base in output_facts:
            direct_span = True
        if base in full_facts:
            partial_span = True
    if not direct_span or not partial_span:
        raise VerificationError(
            f"{function.name}: direct and partial exact output spans are missing"
        )

    verified_copies = 0
    assignments = assignment_map(function)
    for line in function.lines:
        if "llvm.memcpy" not in line and "llvm.memmove" not in line:
            continue
        pointers = pointer_operands(line)
        if len(pointers) < 2:
            continue
        destination, source = pointers[0], pointers[1]
        if destination not in output_facts or source not in full_facts:
            continue
        symbol = called_symbol(line)
        if symbol is None:
            raise VerificationError(
                f"{function.name}: partial copy call is not identifiable"
            )
        arguments = symbol_arguments(line, symbol)
        if len(arguments) < 3:
            raise VerificationError(
                f"{function.name}: partial copy lacks a dynamic bounded count"
            )
        count = argument_value(arguments[2])
        if not re.fullmatch(SSA, count):
            raise VerificationError(
                f"{function.name}: partial copy length is not an SSA value"
            )
        count_dependencies = dependencies(assignments, count)
        if output_count not in count_dependencies:
            raise VerificationError(
                f"{function.name}: partial count is not output-derived"
            )
        verify_partial_copy_bounds(function, line, count, count_dependencies)
        verified_copies += 1
    if verified_copies != 1:
        raise VerificationError(
            f"{function.name}: expected one provenance-bound partial copy"
        )


def verify_inline_constant_time(
    function: Function,
    lhs_root: str,
    rhs_root: str,
    count: int,
) -> str:
    """Verify a constant-time loop after the optimizer has inlined the helper."""
    if "memcmp" in function.text or "bcmp" in function.text:
        raise VerificationError(f"{function.name}: library comparison detected")
    assignments = assignment_map(function)
    lhs_facts = pointer_facts(function, lhs_root)
    rhs_facts = pointer_facts(function, rhs_root)
    load_sides: dict[str, str] = {}
    load_blocks: dict[str, str] = {}
    current_block = ""
    for line in function.lines:
        label_match = re.match(r'^("[^"]+"|[-.$A-Za-z0-9_]+):', line)
        if label_match:
            current_block = label_match.group(1).strip('"')
        parsed = assignment(line)
        if not parsed or "= load " not in f"= {parsed[1]}":
            continue
        pointers = pointer_operands(line)
        if not pointers:
            continue
        pointer = pointers[-1]
        lhs = pointer in lhs_facts and pointer not in rhs_facts
        rhs = pointer in rhs_facts and pointer not in lhs_facts
        if lhs:
            load_sides[parsed[0]] = "lhs"
        if rhs:
            load_sides[parsed[0]] = "rhs"
        if lhs or rhs:
            load_blocks[parsed[0]] = current_block
    lhs_loads = {value for value, side in load_sides.items() if side == "lhs"}
    rhs_loads = {value for value, side in load_sides.items() if side == "rhs"}
    if not lhs_loads or not rhs_loads:
        raise VerificationError(
            f"{function.name}: inlined comparison does not load both inputs"
        )
    xor_pairs: list[tuple[str, str, str]] = []
    for result, expression in assignments.items():
        if not expression.startswith("xor "):
            continue
        operands = ssa_tokens(expression)
        lhs_operands = tuple(value for value in operands if value in lhs_loads)
        rhs_operands = tuple(value for value in operands if value in rhs_loads)
        if len(lhs_operands) == 1 and len(rhs_operands) == 1:
            xor_pairs.append((result, lhs_operands[0], rhs_operands[0]))
    if not xor_pairs:
        raise VerificationError(f"{function.name}: inlined comparison lacks XORs")
    if {
        pair[1] for pair in xor_pairs
    } != lhs_loads or {pair[2] for pair in xor_pairs} != rhs_loads:
        raise VerificationError(
            f"{function.name}: inlined comparison has unpaired input loads"
        )
    for _, lhs_load, rhs_load in xor_pairs:
        lhs_pointer = next(
            pointer_operands(line)[-1]
            for line in function.lines
            if assignment(line)
            and assignment(line)[0] == lhs_load
            and pointer_operands(line)
        )
        rhs_pointer = next(
            pointer_operands(line)[-1]
            for line in function.lines
            if assignment(line)
            and assignment(line)[0] == rhs_load
            and pointer_operands(line)
        )
        lhs_path = pointer_path(
            lhs_pointer, assignments, roots=(lhs_root, rhs_root)
        )
        rhs_path = pointer_path(
            rhs_pointer, assignments, roots=(lhs_root, rhs_root)
        )
        if (
            lhs_path is None
            or rhs_path is None
            or lhs_path[0] != lhs_root
            or rhs_path[0] != rhs_root
            or lhs_path[1] != rhs_path[1]
        ):
            raise VerificationError(
                f"{function.name}: inlined comparison index paths differ"
            )
    tainted = set(lhs_loads) | set(rhs_loads)
    changed = True
    while changed:
        changed = False
        for result, expression in assignments.items():
            if result in tainted:
                continue
            if any(token in tainted for token in ssa_tokens(expression)):
                if expression.startswith("getelementptr"):
                    raise VerificationError(
                        f"{function.name}: secret data controls an address"
                    )
                tainted.add(result)
                changed = True
    for line in function.lines:
        if re.search(r"\b(?:br i1|switch)\b", line):
            if any(
                token in tainted
                for token in ssa_tokens(line.split("label", 1)[0])
            ):
                raise VerificationError(
                    f"{function.name}: secret data controls a branch"
                )
    final_comparisons = {
        result
        for result, expression in assignments.items()
        if (
            re.fullmatch(
                rf"icmp eq i(?:8|16|32|64) ({SSA}|0), ({SSA}|0)",
                expression,
            )
            and any(
                value != "0" and value in tainted
                for value in ssa_tokens(expression)
            )
        )
    }
    if len(final_comparisons) != 1:
        raise VerificationError(
            f"{function.name}: inlined reduction is not compared with eq zero"
        )
    final_result = next(iter(final_comparisons))
    returns = {
        token
        for line in function.lines
        if line.strip().startswith("ret ")
        for token in ssa_tokens(line)
    }
    if final_result not in set().union(
        *(dependencies(assignments, value) for value in returns)
    ):
        raise VerificationError(
            f"{function.name}: inlined comparison result is ignored"
        )
    loop_blocks = {load_blocks[value] for value in load_sides}
    if not loop_blocks <= cyclic_blocks(function):
        raise VerificationError(
            f"{function.name}: inlined comparison is not loop-bounded"
        )
    if not any(
        any(
            re.search(r"icmp eq i(?:32|64) ", line) is not None
            and str(count) in line
            for line in function.blocks()[block]
        )
        for block in loop_blocks
    ):
        raise VerificationError(
            f"{function.name}: inlined comparison does not cover exactly {count} bytes"
        )
    return final_result


def verify_hmac_verification(function: Function) -> None:
    """Bind finalization, calculated-tag storage, and the success result."""
    calculated_owners = alloca_owners(
        function,
        ("calculatedCode",),
        "SIMD32",
    )
    output_owners = alloca_owners(function, ("output",), "MutableSpan")
    if calculated_owners != ("%calculatedCode",) or output_owners != ("%output",):
        raise VerificationError(
            f"{function.name}: canonical authentication owners are missing"
        )
    calculated = calculated_owners[0]
    output = output_owners[0]
    calculated_facts = pointer_facts(function, calculated)
    output_base, output_count = span_base_and_count(function, output)
    if output_base is None or output_count != 32:
        raise VerificationError(
            f"{function.name}: calculated-code span is not exactly 32 bytes"
        )
    if calculated_facts.get(output_base) != 0:
        raise VerificationError(
            f"{function.name}: output span does not point at calculated code"
        )

    finalize_lines = [
        line
        for line in function.lines
        if called_symbol(line) in HMAC_FINALIZE_SYMBOLS
    ]
    if len(finalize_lines) != 1:
        raise VerificationError(
            f"{function.name}: canonical HMAC finalization is not unique"
        )
    finalize = finalize_lines[0]
    finalize_symbol = called_symbol(finalize)
    assert finalize_symbol is not None
    finalize_arguments = symbol_arguments(finalize, finalize_symbol)
    pointer_arguments = [
        argument_value(argument)
        for argument in finalize_arguments
        if argument_type(argument) == "ptr"
    ]
    if output not in pointer_arguments:
        raise VerificationError(
            f"{function.name}: HMAC finalization writes an unrelated span"
        )

    comparison_lines = [
        line
        for line in function.lines
        if called_symbol(line) in CONSTANT_TIME_EQUAL_SYMBOLS
    ]
    inline_comparison_result: str | None = None
    if not comparison_lines:
        inline_comparison_result = verify_inline_constant_time(
            function,
            "%0",
            calculated,
            32,
        )
    elif len(comparison_lines) != 1:
        raise VerificationError(
            f"{function.name}: canonical authentication comparison is not unique"
        )
    if inline_comparison_result is not None:
        comparison_result_value = inline_comparison_result
        assignments = assignment_map(function)
        comparison_block = block_for_line(
            function,
            next(
                line
                for line in function.lines
                if assignment(line)
                and assignment(line)[0] == inline_comparison_result
            ).strip(),
        )
        if comparison_block is None:
            raise VerificationError(
                f"{function.name}: inlined comparison block is not identifiable"
            )
    else:
        comparison = comparison_lines[0]
        comparison_symbol = called_symbol(comparison)
        assert comparison_symbol is not None
        comparison_arguments = symbol_arguments(comparison, comparison_symbol)
        if len(comparison_arguments) != 4:
            raise VerificationError(
                f"{function.name}: constant-time comparison has an invalid arity"
            )
        comparison_values = tuple(
            argument_value(argument) for argument in comparison_arguments
        )
        if comparison_values[0] != "%0" or comparison_values[1] != "32":
            raise VerificationError(
                f"{function.name}: authentication input is not compared at 32 bytes"
            )
        if comparison_values[3] != "32":
            raise VerificationError(
                f"{function.name}: calculated-code comparison length is not 32 bytes"
            )
        if calculated_facts.get(comparison_values[2]) != 0:
            raise VerificationError(
                f"{function.name}: comparison does not use calculated code"
            )
        if comparison_values[2] == "%0":
            raise VerificationError(
                f"{function.name}: authentication comparison aliases both inputs"
            )
        comparison_assignment = assignment(comparison)
        if comparison_assignment is None:
            raise VerificationError(
                f"{function.name}: comparison result is discarded"
            )
        comparison_result_value = comparison_assignment[0]
        assignments = assignment_map(function)
        comparison_block = block_for_line(function, comparison.strip())
        if comparison_block is None:
            raise VerificationError(
                f"{function.name}: comparison block is not identifiable"
            )
    dom = dominators(function)
    for block, lines in function.blocks().items():
        if not any(re.match(r"\s*ret\b", line) for line in lines):
            continue
        if comparison_block not in dom.get(block, set()):
            continue
        return_values = [
            token
            for line in lines
            if line.strip().startswith("ret ")
            for token in ssa_tokens(line)
        ]
        returned_dependencies = set().union(
            *(dependencies(assignments, value) for value in return_values)
        )
        if comparison_result_value not in returned_dependencies:
            raise VerificationError(
                f"{function.name}: comparison result is ignored on success"
            )


def verify_secret_bytes_ir(
    label: str,
    ir: str,
    embedded: bool = False,
) -> None:
    """Check SecretBytes cleanup on every CFG path that reaches deallocation."""
    functions = parse_functions(ir)

    def exact_wipe(line: str, owner: str, count: str) -> bool:
        symbol = called_symbol(line)
        if symbol not in SECURE_WIPE_SYMBOLS:
            return False
        arguments = symbol_arguments(line, symbol)
        return (
            len(arguments) == 2
            and argument_value(arguments[0]) == owner
            and argument_value(arguments[1]) == count
        )

    def deallocation(line: str, owner: str) -> bool:
        symbol = called_symbol(line)
        if symbol not in ("swift_slowDealloc", "free"):
            return False
        arguments = symbol_arguments(line, symbol)
        return bool(arguments) and argument_value(arguments[0]) == owner

    def verify_paths(
        function: Function,
        owner: str,
        count: str,
        require_deallocation: bool,
    ) -> None:
        blocks = function.blocks()
        entry = next(iter(blocks))
        pending = deque([(entry, False, False, frozenset())])
        dealloc_seen = False
        while pending:
            block, wiped, deallocated, path = pending.popleft()
            state = (block, wiped, deallocated)
            if state in path:
                raise VerificationError(
                    f"{function.name}: cleanup CFG contains an unbounded cycle"
                )
            next_path = path | {state}
            for line in blocks[block]:
                if exact_wipe(line, owner, count):
                    wiped = True
                if deallocation(line, owner):
                    if not wiped:
                        raise VerificationError(
                            f"{function.name}: deallocation bypasses SecureWipe"
                        )
                    deallocated = True
                    dealloc_seen = True
            if block_has_return(blocks[block]):
                if require_deallocation and not deallocated:
                    raise VerificationError(
                        f"{function.name}: return path lacks deallocation"
                    )
                continue
            if block_is_unreachable(blocks[block]):
                continue
            successors = block_successors(blocks[block])
            if not successors:
                raise VerificationError(
                    f"{function.name}: cleanup path terminates without return"
                )
            pending.extend(
                (successor, wiped, deallocated, next_path)
                for successor in successors
            )
        if not dealloc_seen and not embedded:
            raise VerificationError(
                f"{function.name}: no deallocation path was verified"
            )

    deinitializers = [
        function
        for function in functions
        if "SecretBytesVfD" in function.name
    ]
    if len(deinitializers) != 1:
        raise VerificationError(
            f"{label}: expected one canonical SecretBytes deinitializer"
        )
    deinitializer = deinitializers[0]
    deinit_types = formal_parameter_types(deinitializer)
    if len(deinit_types) != 2 or deinit_types[0] != "ptr" or deinit_types[1] not in (
        "i32",
        "i64",
    ):
        raise VerificationError(
            f"{deinitializer.name}: unexpected deinitializer signature"
        )
    verify_paths(deinitializer, "%0", "%1", True)

    value_witnesses = [
        function
        for function in functions
        if "SecretBytesVwxx" in function.name
    ]
    for witness in value_witnesses:
        deinit_calls = [
            line
            for line in witness.lines
            if "SecretBytesVfD" in (called_symbol(line) or "")
        ]
        if not deinit_calls:
            verify_paths(witness, "%0", "%1", True)
            continue
        for line in deinit_calls:
            symbol = called_symbol(line)
            if symbol is None:
                continue
            arguments = symbol_arguments(line, symbol)
            if len(arguments) < 2 or argument_value(arguments[0]) != "%0":
                raise VerificationError(
                    f"{witness.name}: value witness passes the wrong owner"
                )
        blocks = witness.blocks()
        entry = next(iter(blocks))
        pending = deque([(entry, False, frozenset())])
        while pending:
            block, called, path = pending.popleft()
            state = (block, called)
            if state in path:
                raise VerificationError(
                    f"{witness.name}: value-witness cleanup contains a cycle"
                )
            next_path = path | {state}
            for line in blocks[block]:
                if called_symbol(line) in (
                    called_symbol(candidate) for candidate in deinit_calls
                ):
                    called = True
                if deallocation(line, "%0") and not called:
                    raise VerificationError(
                        f"{witness.name}: value witness deallocates before cleanup"
                    )
            if block_has_return(blocks[block]):
                if not called:
                    raise VerificationError(
                        f"{witness.name}: value witness has a dirty return path"
                    )
                continue
            successors = block_successors(blocks[block])
            if not successors:
                raise VerificationError(
                    f"{witness.name}: value witness path terminates without return"
                )
            pending.extend(
                (successor, called, next_path) for successor in successors
            )

    constructors = [
        function
        for function in functions
        if "SecretBytesV9byteCount16initializingWith" in function.name
    ]
    if not embedded:
        if len(constructors) != 1:
            raise VerificationError(
                f"{label}: expected one canonical SecretBytes initializer"
            )
        constructor = constructors[0]
        allocation_results = [
            parsed[0]
            for line in constructor.lines
            if (parsed := assignment(line))
            and "swift_slowAlloc" in parsed[1]
        ]
        if len(allocation_results) != 1:
            raise VerificationError(
                f"{constructor.name}: secret allocation is not unique"
            )
        verify_paths(constructor, allocation_results[0], "%0", False)


def verify_schedule_placement(function: Function) -> None:
    call_lines = [
        line
        for line in function.lines
        if "call " in line and "initializeFreshContexts" in line
    ]
    if len(call_lines) != 1:
        raise VerificationError(
            f"{function.name}: prepared key schedule is not statically unique"
        )
    call_block = block_for_line(function, call_lines[0].strip())
    if call_block is None or call_block in cyclic_blocks(function):
        raise VerificationError(
            f"{function.name}: prepared key schedule is inside a cycle"
        )
    working_owners = alloca_owners(
        function,
        ("innerContext", "outerContext"),
        "SHA256Context",
    )[2:]
    dom = dominators(function)
    for owner in working_owners:
        owner_start_block = None
        current = None
        for line in function.lines:
            match = re.match(r'^("[^"]+"|[-.$A-Za-z0-9_]+):', line)
            if match:
                current = match.group(1).strip('"')
            elif (
                "llvm.lifetime.start" in line
                and owner in pointer_operands(line)
            ):
                owner_start_block = current
                break
        if owner_start_block is None or call_block not in dom[owner_start_block]:
            raise VerificationError(
                f"{function.name}: key schedule does not dominate {owner}"
            )


def phi_incomings(expression: str) -> tuple[tuple[str, str], ...] | None:
    value = rf"(?:{SSA}|null|poison|undef|-?\d+)"
    label = r'%(?:"([^"]+)"|([-.$A-Za-z0-9_]+))'
    incoming = rf"\[\s*({value})\s*,\s*{label}\s*\]"
    if not re.fullmatch(
        rf"phi (?:ptr|i(?:32|64)) "
        rf"\[\s*{value}\s*,\s*%(?:\"[^\"]+\"|[-.$A-Za-z0-9_]+)\s*\]"
        rf"(?:,\s*\[\s*{value}\s*,\s*"
        rf"%(?:\"[^\"]+\"|[-.$A-Za-z0-9_]+)\s*\])*",
        expression,
    ):
        return None
    return tuple(
        (match.group(1), match.group(2) or match.group(3))
        for match in re.finditer(incoming, expression)
    )


def branch_for_condition(
    function: Function,
    condition: str,
) -> tuple[str, str, str] | None:
    current = ""
    for line in function.lines:
        label_match = re.match(r'^("[^"]+"|[-.$A-Za-z0-9_]+):', line)
        if label_match:
            current = label_match.group(1).strip('"')
            continue
        if re.search(rf"\bbr i1 {re.escape(condition)}\b", line):
            successors = referenced_labels(line)
            if len(successors) == 2:
                return current, successors[0], successors[1]
    return None


def comparison_result(
    assignments: dict[str, str],
    predicate: str,
    first: str,
    second: str,
) -> str | None:
    for result, expression in assignments.items():
        match = re.fullmatch(
            rf"icmp(?:\s+samesign)? {predicate}(?:\s+\w+)* i(?:32|64) "
            rf"({SSA}|-?\d+),\s*({SSA}|-?\d+)",
            expression,
        )
        if match and (
            match.groups() == (first, second)
            or (
                predicate in ("eq", "ne")
                and match.groups() == (second, first)
            )
        ):
            return result
    return None


def binary_result(
    assignments: dict[str, str],
    operation: str,
    first: str,
    second: str,
) -> str | None:
    for result, expression in assignments.items():
        match = re.fullmatch(
            rf"{operation}(?:\s+\w+)*\s+i(?:32|64) "
            rf"({SSA}|-?\d+),\s*({SSA}|-?\d+)",
            expression,
        )
        if not match:
            continue
        operands = match.groups()
        if operands == (first, second) or (
            operation in ("add", "and") and operands == (second, first)
        ):
            return result
    return None


def integer_width(
    function: Function,
    assignments: dict[str, str],
    value: str,
) -> int | None:
    parameters = formal_parameters(function)
    if value in parameters:
        parameter_types = formal_parameter_types(function)
        type_name = parameter_types[parameters.index(value)]
        if type_name in ("i32", "i64"):
            return int(type_name[1:])
        return None
    expression = assignments.get(value, "")
    match = re.search(r"\bi(32|64)\b", expression)
    return int(match.group(1)) if match else None


def volatile_zero_store_lines(
    function: Function,
    pointer_facts_by_value: dict[str, int | None],
) -> tuple[tuple[str, str], ...]:
    stores: list[tuple[str, str]] = []
    current_block = ""
    for line in function.lines:
        label_match = re.match(r'^("[^"]+"|[-.$A-Za-z0-9_]+):', line)
        if label_match:
            current_block = label_match.group(1).strip('"')
            continue
        if not re.match(r"\s*store\b", line):
            continue
        if not re.match(
            r"\s*store(?=[^,]*\batomic\b)(?=[^,]*\bvolatile\b)"
            r"[^,]*\bi8\s+0,\s+ptr\b",
            line,
        ):
            raise VerificationError(
                f"{function.name}: SecureWipe contains a non-zeroing store"
            )
        pointers = pointer_operands(line)
        if not pointers or pointers[-1] not in pointer_facts_by_value:
            raise VerificationError(
                f"{function.name}: volatile zero store is not "
                "pointer-derived"
            )
        stores.append((current_block, pointers[-1]))
    return tuple(stores)


def effective_count_value(
    assignments: dict[str, str],
    count: str,
) -> str:
    frozen = [
        result
        for result, expression in assignments.items()
        if re.fullmatch(
            rf"freeze i(?:32|64) {re.escape(count)}",
            expression,
        )
    ]
    if len(frozen) > 1:
        raise VerificationError("SecureWipe has ambiguous frozen byteCount")
    return frozen[0] if frozen else count


def all_paths_trap_without_effects(
    function: Function,
    start: str,
) -> bool:
    blocks = function.blocks()
    pending = deque([(start, False)])
    visited: set[tuple[str, bool]] = set()
    while pending:
        block_name, trapped = pending.popleft()
        if (block_name, trapped) in visited:
            return False
        visited.add((block_name, trapped))
        lines = blocks[block_name]
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith(";"):
                continue
            symbol = called_symbol(line)
            if symbol == "llvm.trap":
                trapped = True
                continue
            if (
                symbol is not None
                or re.match(r"\s*store\b", line)
                or re.search(r"(?:=\s+)?load\b", line)
                or stripped.startswith("fence ")
                or "llvm.memset" in line
                or "llvm.memcpy" in line
                or "llvm.memmove" in line
                or re.search(r"\b(?:atomicrmw|cmpxchg)\b", line)
            ):
                return False
        if block_has_return(lines):
            return False
        if block_is_unreachable(lines):
            if not trapped:
                return False
            continue
        successors = block_successors(lines)
        if successors is None or not successors:
            return False
        for successor in successors:
            pending.append((successor, trapped))
    return True


def verify_wipe_guards(
    function: Function,
    assignments: dict[str, str],
    effective_count: str,
    store_blocks: frozenset[str],
) -> str:
    blocks = function.blocks()
    negative = comparison_result(
        assignments,
        "slt",
        effective_count,
        "0",
    )
    if negative is None:
        raise VerificationError(
            f"{function.name}: SecureWipe lacks the negative-count guard"
        )
    negative_branch = branch_for_condition(function, negative)
    if negative_branch is None:
        raise VerificationError(
            f"{function.name}: negative-count guard does not control the CFG"
        )
    negative_block, trap_successor, nonnegative_successor = negative_branch
    entry = next(iter(blocks))
    if not all_paths_reach_block(function, entry, negative_block):
        raise VerificationError(
            f"{function.name}: entry can bypass the negative-count guard"
        )
    trap_blocks = reachable_blocks(function, trap_successor)
    if not all_paths_trap_without_effects(function, trap_successor):
        raise VerificationError(
            f"{function.name}: negative byteCount does not exclusively trap"
        )
    if trap_blocks & store_blocks:
        raise VerificationError(
            f"{function.name}: negative byteCount can reach a wipe store"
        )

    zero = comparison_result(
        assignments,
        "eq",
        effective_count,
        "0",
    )
    if zero is None:
        raise VerificationError(
            f"{function.name}: SecureWipe lacks the zero-count guard"
        )
    zero_branch = branch_for_condition(function, zero)
    if zero_branch is None:
        raise VerificationError(
            f"{function.name}: zero-count guard does not control the CFG"
        )
    zero_block, zero_successor, positive_successor = zero_branch
    if not all_paths_reach_block(
        function,
        nonnegative_successor,
        zero_block,
    ):
        raise VerificationError(
            f"{function.name}: zero-count guard bypasses the nonnegative path"
        )
    zero_reachable = reachable_blocks(function, zero_successor)
    if zero_reachable & store_blocks or not any(
        block_has_return(blocks[block]) for block in zero_reachable
    ) or not all_paths_return_without_effects(function, zero_successor):
        raise VerificationError(
            f"{function.name}: zero byteCount does not return without stores"
        )

    return positive_successor


def all_paths_reach_block(
    function: Function,
    start: str,
    target: str,
) -> bool:
    if start == target:
        return True
    blocks = function.blocks()
    pending = [start]
    visited: set[str] = set()
    reached_target = False
    edges: dict[str, tuple[str, ...]] = {}
    while pending:
        block = pending.pop()
        if block == target:
            reached_target = True
            continue
        if block in visited:
            continue
        visited.add(block)
        lines = blocks[block]
        if block_has_return(lines) or block_is_unreachable(lines):
            return False
        successors = block_successors(lines)
        if successors is None or not successors:
            return False
        edges[block] = successors
        pending.extend(successors)

    visiting: set[str] = set()
    completed: set[str] = set()

    def has_cycle(block: str) -> bool:
        if block == target:
            return False
        if block in completed:
            return False
        if block in visiting:
            return True
        visiting.add(block)
        for successor in edges.get(block, ()):
            if has_cycle(successor):
                return True
        visiting.remove(block)
        completed.add(block)
        return False

    return reached_target and not has_cycle(start)


def all_paths_return_without_effects(
    function: Function,
    start: str,
) -> bool:
    blocks = function.blocks()
    pending = [start]
    visited: set[str] = set()
    edges: dict[str, tuple[str, ...]] = {}
    observed_return = False
    while pending:
        block = pending.pop()
        if block in visited:
            continue
        visited.add(block)
        lines = blocks[block]
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith(";"):
                continue
            if (
                called_symbol(line) is not None
                or re.match(r"\s*store\b", line)
                or re.search(r"(?:=\s+)?load\b", line)
                or stripped.startswith("fence ")
                or "llvm.memset" in line
                or "llvm.memcpy" in line
                or "llvm.memmove" in line
                or re.search(r"\b(?:atomicrmw|cmpxchg)\b", line)
                or re.search(r"\b(?:invoke|callbr)\b", line)
                or "asm sideeffect" in line
            ):
                return False
        if block_is_unreachable(lines):
            return False
        if block_has_return(lines):
            if not any(line.strip() == "ret void" for line in lines):
                return False
            observed_return = True
            continue
        successors = block_successors(lines)
        if successors is None or not successors:
            return False
        edges[block] = successors
        pending.extend(successors)

    visiting: set[str] = set()
    completed: set[str] = set()

    def has_cycle(block: str) -> bool:
        if block in completed:
            return False
        if block in visiting:
            return True
        visiting.add(block)
        for successor in edges.get(block, ()):
            if has_cycle(successor):
                return True
        visiting.remove(block)
        completed.add(block)
        return False

    return observed_return and not has_cycle(start)


def byte_gep_base_and_index(
    expression: str,
) -> tuple[str, str] | None:
    if not expression.startswith("getelementptr"):
        return None
    if not re.search(
        r"getelementptr(?:\s+\w+)*\s+(?:i8|%Ts5UInt8V),",
        expression,
    ):
        return None
    pointers = pointer_operands(expression)
    indices = re.findall(rf"i(?:32|64)\s+({SSA}|-?\d+)", expression)
    if not pointers or len(indices) != 1:
        return None
    return pointers[-1], indices[0]


def affine_pointer_offset(
    assignments: dict[str, str],
    pointer: str,
    root: str,
    index: str,
    seen: frozenset[str] = frozenset(),
) -> int | None:
    if pointer in seen:
        return None
    if pointer == root:
        return 0
    expression = assignments.get(pointer)
    if expression is None:
        return None
    parsed = byte_gep_base_and_index(expression)
    if parsed is None:
        return None
    base, value = parsed
    base_offset = affine_pointer_offset(
        assignments,
        base,
        root,
        index,
        seen | {pointer},
    )
    if base_offset is None:
        return None
    if value == index:
        return base_offset
    if re.fullmatch(r"-?\d+", value):
        return base_offset + int(value)
    return None


def verify_simple_wipe_loop(
    function: Function,
    pointer: str,
    effective_count: str,
    stores: tuple[tuple[str, str], ...],
    assignments: dict[str, str],
    positive_successor: str,
) -> bool:
    store_blocks = {block for block, _ in stores}
    if len(stores) != 1 or len(store_blocks) != 1:
        return False
    loop = next(iter(store_blocks))
    if not all_paths_reach_block(function, positive_successor, loop):
        return False
    address = stores[0][1]
    address_expression = assignments.get(address, "")
    parsed_address = byte_gep_base_and_index(address_expression)
    if parsed_address is None or parsed_address[0] != pointer:
        return False
    index = parsed_address[1]
    index_incomings = phi_incomings(assignments.get(index, ""))
    if not index_incomings or len(index_incomings) != 2:
        return False
    zero_incoming = [
        label for value, label in index_incomings if value == "0"
    ]
    backedge = [
        value for value, label in index_incomings if label == loop
    ]
    if len(zero_incoming) != 1 or len(backedge) != 1:
        return False
    next_index = backedge[0]
    expected_width = integer_width(
        function,
        assignments,
        effective_count,
    )
    if (
        expected_width is None
        or integer_width(function, assignments, index) != expected_width
        or integer_width(function, assignments, next_index)
        != expected_width
    ):
        return False
    if binary_result(assignments, "add", index, "1") != next_index:
        return False
    done = comparison_result(
        assignments,
        "eq",
        next_index,
        effective_count,
    )
    branch = branch_for_condition(function, done) if done else None
    if branch is None or branch[0] != loop:
        return False
    _, completed, repeated = branch
    if repeated != loop or completed == loop:
        return False
    return all_paths_return_without_effects(function, completed)


def verify_unrolled_wipe_loop(
    function: Function,
    pointer: str,
    effective_count: str,
    stores: tuple[tuple[str, str], ...],
    assignments: dict[str, str],
    positive_successor: str,
) -> bool:
    remainder = binary_result(
        assignments,
        "and",
        effective_count,
        "7",
    )
    chunk_end = binary_result(
        assignments,
        "and",
        effective_count,
        "-8",
    )
    if chunk_end is None:
        count_width = integer_width(function, assignments, effective_count)
        nonnegative_chunk_mask = {
            32: "2147483640",
            64: "9223372036854775800",
        }.get(count_width)
        if nonnegative_chunk_mask is not None:
            chunk_end = binary_result(
                assignments,
                "and",
                effective_count,
                nonnegative_chunk_mask,
            )
    if remainder is None or chunk_end is None:
        return False

    stores_by_block: dict[str, list[str]] = {}
    for block, address in stores:
        stores_by_block.setdefault(block, []).append(address)
    main_candidates = [
        block for block, addresses in stores_by_block.items()
        if len(addresses) == 8
    ]
    epilogue_candidates = [
        block for block, addresses in stores_by_block.items()
        if len(addresses) == 1
    ]
    if len(main_candidates) != 1 or len(epilogue_candidates) != 1:
        return False
    main = main_candidates[0]
    epilogue = epilogue_candidates[0]
    if set(stores_by_block) != {main, epilogue}:
        return False

    main_indices: list[tuple[str, str]] = []
    for result, expression in assignments.items():
        incoming = phi_incomings(expression)
        if not incoming or len(incoming) != 2:
            continue
        if not any(value == "0" for value, _ in incoming):
            continue
        backedges = [value for value, label in incoming if label == main]
        if len(backedges) == 1:
            main_indices.append((result, backedges[0]))
    address_index = None
    address_next = None
    for index, next_index in main_indices:
        offsets = {
            affine_pointer_offset(
                assignments,
                address,
                pointer,
                index,
            )
            for address in stores_by_block[main]
        }
        if offsets == set(range(8)):
            address_index = index
            address_next = next_index
            break
    if (
        address_index is None
        or address_next is None
        or binary_result(
            assignments,
            "add",
            address_index,
            "8",
        )
        != address_next
    ):
        return False

    expected_width = integer_width(
        function,
        assignments,
        effective_count,
    )
    if (
        expected_width is None
        or integer_width(function, assignments, remainder) != expected_width
        or integer_width(function, assignments, chunk_end) != expected_width
        or integer_width(function, assignments, address_index)
        != expected_width
        or integer_width(function, assignments, address_next)
        != expected_width
    ):
        return False

    counter_match = False
    main_completed = None
    main_counter = None
    main_next_counter = None
    for counter, next_counter in main_indices:
        if binary_result(assignments, "add", counter, "8") != next_counter:
            continue
        done = comparison_result(
            assignments,
            "eq",
            next_counter,
            chunk_end,
        )
        branch = branch_for_condition(function, done) if done else None
        if (
            branch is not None
            and branch[0] == main
            and branch[2] == main
            and branch[1] != main
        ):
            counter_match = True
            main_completed = branch[1]
            main_counter = counter
            main_next_counter = next_counter
            break
    if not counter_match or main_completed is None:
        return False

    epilogue_indices: list[tuple[str, str]] = []
    for result, expression in assignments.items():
        incoming = phi_incomings(expression)
        if not incoming or len(incoming) != 2:
            continue
        backedges = [
            value for value, label in incoming if label == epilogue
        ]
        if len(backedges) == 1:
            epilogue_indices.append((result, backedges[0]))
    epilogue_address_index = None
    for index, next_index in epilogue_indices:
        if (
            affine_pointer_offset(
                assignments,
                stores_by_block[epilogue][0],
                pointer,
                index,
            )
            == 0
            and binary_result(assignments, "add", index, "1")
            == next_index
        ):
            epilogue_address_index = index
            break
    if epilogue_address_index is None:
        return False

    if (
        main_counter is None
        or main_next_counter is None
        or integer_width(function, assignments, main_counter)
        != expected_width
        or integer_width(function, assignments, main_next_counter)
        != expected_width
    ):
        return False

    epilogue_counter_match = False
    epilogue_completed = None
    epilogue_counter = None
    epilogue_next_counter = None
    for counter, next_counter in epilogue_indices:
        incoming = phi_incomings(assignments[counter])
        if (
            not incoming
            or not any(value == "0" for value, _ in incoming)
            or binary_result(assignments, "add", counter, "1")
            != next_counter
        ):
            continue
        done = comparison_result(
            assignments,
            "eq",
            next_counter,
            remainder,
        )
        branch = branch_for_condition(function, done) if done else None
        if (
            branch is not None
            and branch[0] == epilogue
            and branch[2] == epilogue
            and branch[1] != epilogue
        ):
            epilogue_counter_match = True
            epilogue_completed = branch[1]
            epilogue_counter = counter
            epilogue_next_counter = next_counter
            break
    if not epilogue_counter_match or epilogue_completed is None:
        return False
    epilogue_address_next = next(
        (
            next_index
            for index, next_index in epilogue_indices
            if index == epilogue_address_index
        ),
        None,
    )
    if (
        epilogue_address_next is None
        or epilogue_counter is None
        or epilogue_next_counter is None
        or any(
            integer_width(function, assignments, value) != expected_width
            for value in (
                epilogue_address_index,
                epilogue_address_next,
                epilogue_counter,
                epilogue_next_counter,
            )
        )
    ):
        return False

    epilogue_index_incomings = phi_incomings(
        assignments.get(epilogue_address_index, "")
    )
    if not epilogue_index_incomings:
        return False
    initial_values = [
        value
        for value, label in epilogue_index_incomings
        if label != epilogue
    ]
    if len(initial_values) != 1:
        return False
    start_incomings = phi_incomings(
        assignments.get(initial_values[0], "")
    )
    if not start_incomings:
        return False
    start_values = {value for value, _ in start_incomings}
    if start_values not in ({"0", address_next}, {"0", chunk_end}):
        return False

    small_count = comparison_result(
        assignments,
        "ult",
        effective_count,
        "8",
    )
    if small_count is not None:
        small_branch = branch_for_condition(function, small_count)
        if small_branch is None:
            return False
        small_block, small_path, large_path = small_branch
    else:
        large_count = comparison_result(
            assignments,
            "ugt",
            effective_count,
            "7",
        )
        large_branch = (
            branch_for_condition(function, large_count)
            if large_count
            else None
        )
        if large_branch is None:
            return False
        small_block, large_path, small_path = large_branch
    if not all_paths_reach_block(
        function,
        positive_successor,
        small_block,
    ):
        return False
    if not all_paths_reach_block(function, large_path, main):
        return False
    if main in reachable_blocks(function, small_path):
        return False
    if main not in reachable_blocks(function, large_path):
        return False

    remainder_dispatches = []
    for result, expression in assignments.items():
        match = re.fullmatch(
            rf"icmp eq(?:\s+\w+)* i(?:32|64) "
            rf"({SSA}|-?\d+),\s*({SSA}|-?\d+)",
            expression,
        )
        if match is None or set(match.groups()) != {remainder, "0"}:
            continue
        branch = branch_for_condition(function, result)
        if branch is not None:
            remainder_dispatches.append(branch)

    def validates_remainder_dispatch(start: str) -> bool:
        for block, completed, continued in remainder_dispatches:
            if not all_paths_reach_block(function, start, block):
                continue
            if not all_paths_return_without_effects(function, completed):
                continue
            if not all_paths_reach_block(function, continued, epilogue):
                continue
            return True
        return False

    if not validates_remainder_dispatch(small_path):
        return False
    if not validates_remainder_dispatch(main_completed):
        return False
    if not all_paths_return_without_effects(function, epilogue_completed):
        return False
    return True


def verify_direct_secure_wipe_body(function: Function) -> None:
    reject_terminal_cycles(function)
    if not exact_pointer_count_signature(function):
        raise VerificationError(
            f"{function.name}: SecureWipe implementation has an invalid ABI"
        )
    pointer, count = formal_parameters(function)
    facts = pointer_facts(
        function,
        pointer,
        strict_storage_aliases=True,
    )
    assignments = assignment_map(function)
    effective_count = effective_count_value(assignments, count)

    for line in function.lines:
        stripped = line.strip()
        if not stripped or stripped.startswith(";"):
            continue
        if re.match(r'^("[^"]+"|[-.$A-Za-z0-9_]+):', line):
            continue
        symbol = called_symbol(line)
        if symbol is not None and symbol != "llvm.trap":
            raise VerificationError(
                f"{function.name}: SecureWipe calls an unverified function: {symbol}"
            )
        parsed = assignment(line)
        if parsed is not None:
            _, expression = parsed
            if not expression.startswith(
                (
                    "freeze ",
                    "icmp ",
                    "and ",
                    "add ",
                    "getelementptr",
                    "phi ",
                )
            ):
                raise VerificationError(
                    f"{function.name}: SecureWipe contains an "
                    f"unverified assignment: {expression}"
                )
            continue
        if re.match(r"\s*store\b", line):
            continue
        if symbol == "llvm.trap":
            continue
        if stripped.startswith(
            ("br ", "ret ", "unreachable", "switch ")
        ):
            continue
        if (
            "llvm.memset" in line
            or "llvm.memcpy" in line
            or "llvm.memmove" in line
            or re.search(r"\b(?:atomicrmw|cmpxchg)\b", line)
            or re.search(r"\b(?:invoke|callbr)\b", line)
            or "asm sideeffect" in line
        ):
            raise VerificationError(
                f"{function.name}: SecureWipe contains an unsupported write"
            )
        raise VerificationError(
            f"{function.name}: SecureWipe contains an unverified instruction"
        )

    stores = volatile_zero_store_lines(function, facts)
    if not stores:
        raise VerificationError(
            f"{function.name}: SecureWipe lacks volatile zero stores"
        )
    store_blocks = frozenset(block for block, _ in stores)
    positive_successor = verify_wipe_guards(
        function,
        assignments,
        effective_count,
        store_blocks,
    )
    if not (
        verify_simple_wipe_loop(
            function,
            pointer,
            effective_count,
            stores,
            assignments,
            positive_successor,
        )
        or verify_unrolled_wipe_loop(
            function,
            pointer,
            effective_count,
            stores,
            assignments,
            positive_successor,
        )
    ):
        raise VerificationError(
            f"{function.name}: SecureWipe loop does not prove exact coverage"
        )


def verify_secure_wipe_wrapper(
    function: Function,
    target_symbol: str,
    verify_symbol,
) -> None:
    reject_terminal_cycles(function)
    if not exact_pointer_count_signature(function):
        raise VerificationError(
            f"{function.name}: SecureWipe wrapper has an invalid ABI"
        )
    pointer, count = formal_parameters(function)
    parameter_types = formal_parameter_types(function)
    calls = [
        line
        for line in function.lines
        if called_symbol(line) in SECURE_WIPE_SYMBOLS
    ]
    if len(calls) != 1 or called_symbol(calls[0]) != target_symbol:
        raise VerificationError(
            f"{function.name}: SecureWipe wrapper must have one exact target"
        )
    call = calls[0]
    if not is_unassigned_swiftcc_void_call(call, target_symbol):
        raise VerificationError(
            f"{function.name}: SecureWipe wrapper call has an invalid ABI"
        )
    if call_argument_values(call, target_symbol) != (pointer, count):
        raise VerificationError(
            f"{function.name}: SecureWipe wrapper changes pointer or byteCount"
        )
    call_types = tuple(
        argument_type(argument) or ""
        for argument in symbol_arguments(call, target_symbol)
    )
    if call_types != parameter_types:
        raise VerificationError(
            f"{function.name}: SecureWipe wrapper changes argument width"
        )

    verify_symbol(target_symbol)

    blocks = function.blocks()
    entry = next(iter(blocks))
    call_block = block_for_line(function, call.strip())
    if (
        call_block is None
        or not all_paths_reach_block(function, entry, call_block)
    ):
        raise VerificationError(
            f"{function.name}: SecureWipe target can be bypassed"
        )
    call_block_lines = blocks[call_block]
    if block_is_unreachable(call_block_lines):
        raise VerificationError(
            f"{function.name}: SecureWipe wrapper cannot return"
        )
    if not block_has_return(call_block_lines):
        successors = block_successors(call_block_lines)
        if (
            successors is None
            or not successors
            or not all(
                all_paths_return_without_effects(function, successor)
                for successor in successors
            )
        ):
            raise VerificationError(
                f"{function.name}: SecureWipe wrapper has no finite return"
            )
    pending = deque([(entry, False)])
    visited: set[tuple[str, bool]] = set()
    while pending:
        block_name, called = pending.popleft()
        if (block_name, called) in visited:
            continue
        visited.add((block_name, called))
        lines = blocks[block_name]
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith(";"):
                continue
            if line == call:
                if called:
                    raise VerificationError(
                        f"{function.name}: SecureWipe target runs twice"
                    )
                called = True
            elif (
                called_symbol(line) in SECURE_WIPE_SYMBOLS
                or re.match(r"\s*store\b", line)
            ):
                raise VerificationError(
                    f"{function.name}: SecureWipe wrapper has extra effects"
                )
            elif not stripped.startswith(
                ("ret ", "br ", "switch ", "unreachable")
            ):
                raise VerificationError(
                    f"{function.name}: SecureWipe wrapper has an "
                    "unverified instruction"
                )
        if block_is_unreachable(lines):
            continue
        if block_has_return(lines):
            if not called:
                raise VerificationError(
                    f"{function.name}: SecureWipe wrapper can skip its target"
                )
            continue
        successors = block_successors(lines)
        if successors is None:
            raise VerificationError(
                f"{function.name}: unsupported SecureWipe wrapper terminator"
            )
        for successor in successors:
            pending.append((successor, called))


def verified_secure_wipe_symbols(
    functions: tuple[Function, ...],
    include_definitions_as_roots: bool = False,
) -> frozenset[str]:
    definitions: dict[str, list[Function]] = {}
    roots: set[str] = set()
    for function in functions:
        if is_secure_wipe_symbol(function.name):
            definitions.setdefault(function.name, []).append(function)
            if include_definitions_as_roots:
                roots.add(function.name)
        for line in function.lines:
            symbol = called_symbol(line)
            if is_secure_wipe_symbol(symbol):
                roots.add(symbol)
    if not roots:
        raise VerificationError("No SecureWipe call targets were emitted")

    verified: set[str] = set()
    verifying: set[str] = set()

    def verify_symbol(symbol: str) -> None:
        if symbol in verified:
            return
        if symbol in verifying:
            raise VerificationError(
                f"{symbol}: recursive SecureWipe wrapper cycle"
            )
        bodies = definitions.get(symbol, [])
        if not bodies:
            raise VerificationError(
                f"{symbol}: called SecureWipe symbol has no definition"
            )
        verifying.add(symbol)
        for body in bodies:
            targets = {
                called_symbol(line)
                for line in body.lines
                if is_secure_wipe_symbol(called_symbol(line))
            }
            if targets:
                if len(targets) != 1:
                    raise VerificationError(
                        f"{symbol}: ambiguous SecureWipe wrapper targets"
                    )
                verify_secure_wipe_wrapper(
                    body,
                    next(iter(targets)),
                    verify_symbol,
                )
            else:
                verify_direct_secure_wipe_body(body)
        verifying.remove(symbol)
        verified.add(symbol)

    for root in roots:
        verify_symbol(root)
    return frozenset(verified)


def verify_crypto_ir(
    label: str,
    crypto_ir: str,
    core_ir: str,
) -> None:
    crypto_functions = parse_functions(crypto_ir)
    core_functions = parse_functions(core_ir)
    verified_wipes = verified_secure_wipe_symbols(
        crypto_functions + core_functions
    )
    all_functions = crypto_functions + core_functions
    crypto_functions_by_name = {
        function.name: function for function in crypto_functions
    }

    one_shot_functions = require_exact_functions(
        crypto_functions,
        HMAC_ONE_SHOT_SYMBOLS,
        "HMAC-SHA-256 one-shot authentication",
    )
    hkdf_functions = require_exact_functions(
        crypto_functions,
        HKDF_EXPAND_SYMBOLS,
        "HKDF-SHA-256 expand",
    )
    verification_roots = require_exact_functions(
        crypto_functions,
        HMAC_CONTEXT_VERIFY_SYMBOLS,
        "HMAC-SHA-256 authentication-code verification",
    )
    critical_reachable = reachable_functions(
        all_functions,
        one_shot_functions + hkdf_functions + verification_roots,
    )

    deinitializers = require_exact_functions(
        crypto_functions,
        HMAC_STORAGE_DEINIT_SYMBOLS,
        "HMAC-SHA-256 context storage deinitialization",
    )
    verified_helpers = frozenset(
        function.name
        for function in functions_containing(
            crypto_functions,
            "HMACSHA256ContextStorageC19eraseSensitiveState",
        )
        if not _raises(
            lambda: analyze_hmac_storage_deinit(
                function,
                verified_wipe_symbols=verified_wipes,
            )
        )
    )
    for function in deinitializers:
        analyze_hmac_storage_deinit(
            function,
            verified_helpers,
            verified_wipes,
        )

    key_functions = tuple(
        function
        for function in critical_reachable
        if "%keyBlock = alloca" in function.text
    )
    if not key_functions:
        raise VerificationError("Missing allocation-free HMAC key block")
    for function in key_functions:
        cleanup_lines, cleanup_closure = outlined_key_cleanup_lines(
            function,
            "%keyBlock",
            crypto_functions_by_name,
            verified_wipes,
        )
        analyze_scoped_owner(
            function,
            "%keyBlock",
            ((0, 64),),
            64,
            cleanup_lines,
            requires_lifetime_on_return=True,
            verified_wipe_symbols=verified_wipes,
        )
        normalization_functions = (function,) + (
            (cleanup_closure,) if cleanup_closure is not None else ()
        )
        normalization = tuple(
            (owner_function, owner)
            for owner_function in normalization_functions
            for owner in alloca_owners(
                owner_function,
                ("normalizationContext",),
                "SHA256Context",
            )
        )
        if not normalization:
            raise VerificationError(
                f"{function.name}: missing normalization context"
            )
        for owner_function, owner in normalization:
            analyze_scoped_owner(
                owner_function,
                owner,
                ((0, 32), (32, 64)),
                112,
                verified_wipe_symbols=verified_wipes,
            )

    for one_shot in one_shot_functions:
        if any(
            operation in one_shot.text
            for operation in (
                "swift_allocObject",
                "swift_retain",
                "swift_release",
                "malloc(",
                "call void @free",
            )
        ):
            raise VerificationError(
                "Canonical one-shot HMAC performs heap ownership traffic"
            )
        one_shot_contexts = alloca_owners(
            one_shot,
            ("innerContext", "outerContext"),
            "SHA256Context",
        )
        if len(one_shot_contexts) != 4:
            raise VerificationError(
                "Canonical one-shot HMAC does not have four scoped contexts"
            )
        for owner in one_shot_contexts:
            analyze_scoped_owner(
                one_shot,
                owner,
                ((0, 32), (32, 64)),
                112,
                verified_wipe_symbols=verified_wipes,
            )

    for hkdf in hkdf_functions:
        if any(
            operation in hkdf.text
            for operation in (
                "swift_allocObject",
                "swift_retain",
                "swift_release",
                "malloc(",
                "call void @free",
            )
        ):
            raise VerificationError(
                "Canonical HKDF expand performs heap ownership traffic"
            )
        hkdf_contexts = alloca_owners(
            hkdf,
            ("innerContext", "outerContext"),
            "SHA256Context",
        )
        if len(hkdf_contexts) != 4:
            raise VerificationError(
                "Canonical HKDF does not have four scoped contexts"
            )
        for owner in hkdf_contexts:
            analyze_scoped_owner(
                hkdf,
                owner,
                ((0, 32), (32, 64)),
                112,
                verified_wipe_symbols=verified_wipes,
            )
        verify_schedule_placement(hkdf)
        verify_hkdf_output(hkdf)

    hmac_verification_functions = tuple(
        function
        for function in critical_reachable
        if (
            (
                "HMACSHA256ContextV25isValidAuthenticationCode" in function.name
                or "HMACSHA256ContextStorageC25isValidAuthenticationCode"
                in function.name
            )
            and "%calculatedCode = alloca" in function.text
        )
    )
    if len(hmac_verification_functions) != 1:
        raise VerificationError(
            "Canonical HMAC verification storage body is missing or duplicated"
        )
    verify_hmac_verification(hmac_verification_functions[0])

    byte_owner_count = 0
    for function in critical_reachable:
        owners = alloca_owners(
            function,
            ("innerDigest", "fullBlock", "calculatedCode"),
            "SIMD32",
        )
        for owner in owners:
            analyze_scoped_owner(
                function,
                owner,
                ((0, 32),),
                32,
                verified_wipe_symbols=verified_wipes,
            )
            byte_owner_count += 1
    if byte_owner_count < 4:
        raise VerificationError("Scoped 32-byte secret owners are missing")

    constant_time_functions = require_exact_functions(
        all_functions,
        CONSTANT_TIME_EQUAL_SYMBOLS,
        "constant-time equality",
    )
    reachable_names = {
        function.name
        for function in reachable_functions(
            all_functions,
            verification_roots,
        )
    }
    inline_constant_time_verified = any(
        not any(
            called_symbol(line) in CONSTANT_TIME_EQUAL_SYMBOLS
            for line in function.lines
        )
        for function in hmac_verification_functions
    )
    if not (reachable_names & CONSTANT_TIME_EQUAL_SYMBOLS) and not inline_constant_time_verified:
        raise VerificationError(
            "Canonical HMAC verification does not reach ConstantTime.equal"
        )
    for function in constant_time_functions:
        verify_constant_time(function)

    print(
        f"{label}: exact cleanup CFG, HKDF output provenance, "
        "and constant-time IR verified"
    )


def _raises(operation) -> bool:
    try:
        operation()
    except VerificationError:
        return True
    return False


def run_self_tests() -> None:
    callback = Function(
        "callback",
        'define void @"callback"() {',
        ("entry:", "  ret void"),
    )
    shared_thunk = Function(
        "shared-thunk",
        'define void @"shared-thunk"(ptr %callback) {',
        ("entry:", "  ret void"),
    )
    thunk_root = Function(
        "thunk-root",
        'define void @"thunk-root"() {',
        (
            "entry:",
            (
                '  call void @"shared-thunk"('
                'ptr @"callback")'
            ),
            "  ret void",
        ),
    )
    reachable_through_callback = {
        function.name
        for function in reachable_functions(
            (thunk_root, shared_thunk, callback),
            (thunk_root,),
        )
    }
    if reachable_through_callback != {
        "thunk-root",
        "shared-thunk",
        "callback",
    }:
        raise VerificationError(
            "Self-test failed to follow a referenced function argument"
        )

    duplicate_deinit = Function(
        "duplicate",
        "",
        (
            "entry:",
            '  call void @"$s12SSLCore10SecureWipeO5erase_9byteCountySv_SitFZ"(ptr %1, i64 32)',
            '  call void @"$s12SSLCore10SecureWipeO5erase_9byteCountySv_SitFZ"(ptr %pending, i64 64)',
            '  call void @"$s12SSLCore10SecureWipeO5erase_9byteCountySv_SitFZ"(ptr %1, i64 32)',
            '  call void @"$s12SSLCore10SecureWipeO5erase_9byteCountySv_SitFZ"(ptr %pending, i64 64)',
            "  ret void",
        ),
    )
    if not _raises(lambda: analyze_hmac_storage_deinit(duplicate_deinit)):
        raise VerificationError("Self-test accepted duplicate inner cleanup")

    early_wipe = Function(
        "early-wipe",
        "",
        (
            "entry:",
            "  %secret = alloca %SIMD32, align 16",
            "  call void @llvm.lifetime.start.p0(i64 32, ptr %secret)",
            '  call void @"$s12SSLCore10SecureWipeO5erase_9byteCountySv_SitFZ"(ptr %secret, i64 32)',
            "  store i8 1, ptr %secret",
            "  call void @llvm.lifetime.end.p0(i64 32, ptr %secret)",
            "  ret void",
        ),
    )
    if not _raises(
        lambda: analyze_scoped_owner(
            early_wipe,
            "%secret",
            ((0, 32),),
            32,
        )
    ):
        raise VerificationError("Self-test accepted mutation after cleanup")

    wrong_count_helper = Function(
        "wrong-count-helper",
        (
            'define swiftcc void @"wrong-count-helper"'
            "(ptr %0, i32 %1, i32 %2) {"
        ),
        (
            "entry:",
            '  call swiftcc void @"$s12SSLCore10SecureWipeO5erase_9byteCountySv_SitFZ"(ptr %0, i32 63)',
            "  ret void",
        ),
    )
    if not _raises(
        lambda: analyze_outlined_wipe_helper(
            wrong_count_helper,
            "%0",
            "%1",
            "%2",
        )
    ):
        raise VerificationError(
            "Self-test accepted an outlined wipe with the wrong length"
        )

    deceptive_wipe_helper = Function(
        "deceptive-wipe-helper",
        (
            'define swiftcc void @"deceptive-wipe-helper"'
            "(ptr %0, i32 %1, i32 %2) {"
        ),
        (
            "entry:",
            "  %3 = icmp eq i32 %1, 0",
            "  %4 = sub i32 %2, %1",
            "  %5 = select i1 %3, i32 0, i32 %4",
            (
                '  call swiftcc void @"$s12SSLCore10SecureWipeO5erase_'
                '9byteCountySv_SitFZ_noop"(ptr %0, i32 %5)'
            ),
            "  ret void",
        ),
    )
    if not _raises(
        lambda: analyze_outlined_wipe_helper(
            deceptive_wipe_helper,
            "%0",
            "%1",
            "%2",
        )
    ):
        raise VerificationError(
            "Self-test accepted a deceptive wipe symbol"
        )

    reversed_null_select = {
        "%condition": "icmp eq i32 %start, 0",
        "%length": "sub i32 %end, %start",
        "%count": "select i1 %condition, i32 %length, i32 0",
    }
    if exact_span_byte_count(
        reversed_null_select,
        "%count",
        "%start",
        "%end",
    ):
        raise VerificationError(
            "Self-test accepted a zero-byte wipe for a nonnull span"
        )

    mixed_provenance = Function(
        "mixed-provenance",
        "",
        (
            "entry:",
            "  %selected = select i1 %condition, ptr %owner, ptr %other",
            "  %merged = phi ptr [ %owner, %left ], [ %other, %right ]",
            "  ret void",
        ),
    )
    mixed_facts = pointer_facts(mixed_provenance, "%owner")
    if (
        "%selected" not in mixed_facts
        or mixed_facts["%selected"] is not None
        or "%merged" not in mixed_facts
        or mixed_facts["%merged"] is not None
    ):
        raise VerificationError(
            "Self-test treated mixed pointer provenance as exact"
        )

    incomplete_phi = Function(
        "incomplete-phi",
        "",
        (
            "entry:",
            (
                "  %mixed = phi ptr [ %owner, %left ], "
                "[ getelementptr (i8, ptr @other, i64 1), %right ]"
            ),
            "  ret void",
        ),
    )
    incomplete_phi_facts = pointer_facts(incomplete_phi, "%owner")
    if (
        "%mixed" not in incomplete_phi_facts
        or incomplete_phi_facts["%mixed"] is not None
    ):
        raise VerificationError(
            "Self-test accepted a partially parsed phi as exact"
        )

    aggregate_alias = Function(
        "aggregate-alias",
        "",
        (
            "entry:",
            (
                "  %pair = call { ptr, i64 } @aliasPair("
                "ptr captures(none) %owner)"
            ),
            "  %alias = extractvalue { ptr, i64 } %pair, 0",
            "  ret void",
        ),
    )
    aggregate_alias_facts = pointer_facts(aggregate_alias, "%owner")
    if (
        aggregate_alias_facts.get("%pair", 0) is not None
        or aggregate_alias_facts.get("%alias", 0) is not None
    ):
        raise VerificationError(
            "Self-test lost aggregate call-result provenance"
        )

    post_wipe_alias_helper = Function(
        "post-wipe-alias-helper",
        (
            'define swiftcc void @"post-wipe-alias-helper"'
            "(ptr %0, i32 %1, i32 %2) {"
        ),
        (
            "entry:",
            "  %3 = icmp eq i32 %1, 0",
            "  %4 = sub i32 %2, %1",
            "  %5 = select i1 %3, i32 0, i32 %4",
            '  call swiftcc void @"$s12SSLCore10SecureWipeO5erase_9byteCountySv_SitFZ"(ptr %0, i32 %5)',
            "  %6 = sub i32 %2, 64",
            "  %7 = inttoptr i32 %6 to ptr",
            "  store i8 1, ptr %7",
            "  ret void",
        ),
    )
    if not _raises(
        lambda: analyze_outlined_wipe_helper(
            post_wipe_alias_helper,
            "%0",
            "%1",
            "%2",
        )
    ):
        raise VerificationError(
            "Self-test accepted an alias access after an outlined wipe"
        )

    laundered_alias_helper = Function(
        "laundered-alias-helper",
        (
            'define swiftcc void @"laundered-alias-helper"'
            "(ptr %0, i32 %1, i32 %2) {"
        ),
        (
            "entry:",
            "  %slot = alloca ptr",
            "  store ptr %0, ptr %slot",
            "  %3 = icmp eq i32 %1, 0",
            "  %4 = sub i32 %2, %1",
            "  %5 = select i1 %3, i32 0, i32 %4",
            (
                '  call swiftcc void @"$s12SSLCore10SecureWipeO5erase_'
                '9byteCountySv_SitFZ"(ptr %0, i32 %5)'
            ),
            "  %6 = load ptr, ptr %slot",
            "  store i8 1, ptr %6",
            "  ret void",
        ),
    )
    if not _raises(
        lambda: analyze_outlined_wipe_helper(
            laundered_alias_helper,
            "%0",
            "%1",
            "%2",
        )
    ):
        raise VerificationError(
            "Self-test accepted a laundered alias after an outlined wipe"
        )

    missing_cleanup_closure = Function(
        "missing-cleanup-closure",
        (
            'define swiftcc void @"missing-cleanup-closure"'
            "(i32 %0, i32 %1, i1 %2) {"
        ),
        (
            "entry:",
            "  %3 = inttoptr i32 %0 to ptr",
            "  br i1 %2, label %clean, label %dirty",
            "clean:",
            '  call swiftcc void @"cleanup"(ptr %3, i32 %0, i32 %1)',
            "  ret void",
            "dirty:",
            "  ret void",
        ),
    )
    if not _raises(
        lambda: analyze_outlined_cleanup_closure(
            missing_cleanup_closure,
            "%0",
            "%1",
            "cleanup",
        )
    ):
        raise VerificationError(
            "Self-test accepted an outlined return without cleanup"
        )

    post_cleanup_alias_closure = Function(
        "post-cleanup-alias-closure",
        (
            'define swiftcc void @"post-cleanup-alias-closure"'
            "(i32 %0, i32 %1) {"
        ),
        (
            "entry:",
            "  %2 = inttoptr i32 %0 to ptr",
            '  call swiftcc void @"cleanup"(ptr %2, i32 %0, i32 %1)',
            "  %3 = sub i32 %1, 64",
            "  %4 = inttoptr i32 %3 to ptr",
            "  %5 = load i8, ptr %4",
            "  ret void",
        ),
    )
    if not _raises(
        lambda: analyze_outlined_cleanup_closure(
            post_cleanup_alias_closure,
            "%0",
            "%1",
            "cleanup",
        )
    ):
        raise VerificationError(
            "Self-test accepted an alias access after outlined cleanup"
        )

    def outlined_helper(
        name: str,
        before_wipe: tuple[str, ...] = (),
        after_wipe: tuple[str, ...] = (),
    ) -> Function:
        return Function(
            name,
            (
                f'define swiftcc void @"{name}"'
                "(ptr %0, i32 %1, i32 %2) {"
            ),
            (
                "entry:",
                *before_wipe,
                "  %condition = icmp eq i32 %1, 0",
                "  %length = sub i32 %2, %1",
                (
                    "  %count = select i1 %condition, "
                    "i32 0, i32 %length"
                ),
                (
                    '  call swiftcc void @"$s12SSLCore10SecureWipeO'
                    '5erase_9byteCountySv_SitFZ"(ptr %0, i32 %count)'
                ),
                *after_wipe,
                "  ret void",
            ),
        )

    alias_fixtures = (
        (
            "zero-gep-slot-alias",
            (
                "  %slot = alloca ptr",
                (
                    "  %slot.zero = getelementptr i8, "
                    "ptr %slot, i32 0"
                ),
                "  store ptr %0, ptr %slot.zero",
            ),
            (
                "  %alias = load ptr, ptr %slot",
                "  store i8 1, ptr %alias",
            ),
        ),
        (
            "volatile-slot-alias",
            (
                "  %slot = alloca ptr",
                "  store ptr %0, ptr %slot",
            ),
            (
                "  %alias = load volatile ptr, ptr %slot",
                "  store i8 1, ptr %alias",
            ),
        ),
        (
            "freeze-alias",
            (),
            (
                "  %alias = freeze ptr %0",
                "  store i8 1, ptr %alias",
            ),
        ),
        (
            "ptr-int-slot-alias",
            (
                "  %slot = alloca ptr",
                "  %slot.integer = ptrtoint ptr %slot to i32",
                "  %slot.pointer = inttoptr i32 %slot.integer to ptr",
                "  store ptr %0, ptr %slot.pointer",
            ),
            (
                "  %alias = load ptr, ptr %slot",
                "  store i8 1, ptr %alias",
            ),
        ),
        (
            "unknown-callee-slot-alias",
            (
                "  %slot = alloca ptr",
                "  store ptr %0, ptr %slot",
                "  %alias = call ptr @readSlot(ptr %slot)",
            ),
            ("  store i8 1, ptr %alias",),
        ),
    )
    for name, before_wipe, after_wipe in alias_fixtures:
        fixture = outlined_helper(name, before_wipe, after_wipe)
        if not _raises(
            lambda fixture=fixture: analyze_outlined_wipe_helper(
                fixture,
                "%0",
                "%1",
                "%2",
            )
        ):
            raise VerificationError(
                f"Self-test accepted post-wipe alias fixture {name}"
            )

    unresolved_storage_fixtures = (
        (
            "global-pointer-escape",
            ("  store ptr %0, ptr @saved",),
        ),
        (
            "mixed-slot-destination",
            (
                "  %slot.a = alloca ptr",
                "  %slot.b = alloca ptr",
                (
                    "  %destination = select i1 %choice, "
                    "ptr %slot.a, ptr %slot.b"
                ),
                "  store ptr %0, ptr %destination",
            ),
        ),
    )
    for name, before_wipe in unresolved_storage_fixtures:
        fixture = outlined_helper(name, before_wipe)
        if not _raises(
            lambda fixture=fixture: analyze_outlined_wipe_helper(
                fixture,
                "%0",
                "%1",
                "%2",
            )
        ):
            raise VerificationError(
                f"Self-test accepted unresolved storage fixture {name}"
            )

    clobbered_slot = Function(
        "clobbered-slot",
        (
            'define swiftcc void @"clobbered-slot"'
            "(ptr %0, i32 %1, i32 %2) {"
        ),
        (
            "entry:",
            "  %slot = alloca ptr",
            "  store ptr %0, ptr %slot",
            "  call void @clobber(ptr %slot)",
            "  %alias = load ptr, ptr %slot",
            "  %length = sub i32 %2, %1",
            (
                '  call swiftcc void @"$s12SSLCore10SecureWipeO'
                '5erase_9byteCountySv_SitFZ"(ptr %alias, i32 %length)'
            ),
            "  ret void",
        ),
    )
    if not _raises(
        lambda: analyze_outlined_wipe_helper(
            clobbered_slot,
            "%0",
            "%1",
            "%2",
        )
    ):
        raise VerificationError(
            "Self-test accepted an exact wipe through a clobbered slot"
        )

    for instruction in (
        "  %old = atomicrmw add ptr %secret, i8 1 monotonic",
        (
            "  %old = cmpxchg ptr %secret, i8 0, i8 1 "
            "monotonic monotonic"
        ),
    ):
        atomic_access = Function(
            "post-wipe-atomic-access",
            "",
            (
                "entry:",
                "  %secret = alloca %SIMD32, align 16",
                "  call void @llvm.lifetime.start.p0(i64 32, ptr %secret)",
                (
                    '  call void @"$s12SSLCore10SecureWipeO'
                    '5erase_9byteCountySv_SitFZ"(ptr %secret, i64 32)'
                ),
                instruction,
                "  call void @llvm.lifetime.end.p0(i64 32, ptr %secret)",
                "  ret void",
            ),
        )
        if not _raises(
            lambda atomic_access=atomic_access: analyze_scoped_owner(
                atomic_access,
                "%secret",
                ((0, 32),),
                32,
            )
        ):
            raise VerificationError(
                "Self-test accepted an atomic access after cleanup"
            )

    wrong_lifetime_size = Function(
        "wrong-lifetime-size",
        "",
        (
            "entry:",
            "  %secret = alloca %SIMD32, align 16",
            "  call void @llvm.lifetime.start.p0(i64 31, ptr %secret)",
            (
                '  call void @"$s12SSLCore10SecureWipeO'
                '5erase_9byteCountySv_SitFZ"(ptr %secret, i64 32)'
            ),
            "  call void @llvm.lifetime.end.p0(i64 31, ptr %secret)",
            "  ret void",
        ),
    )
    if not _raises(
        lambda: analyze_scoped_owner(
            wrong_lifetime_size,
            "%secret",
            ((0, 32),),
            32,
        )
    ):
        raise VerificationError(
            "Self-test accepted a mismatched lifetime size"
        )

    early_alias_lifetime_end = Function(
        "early-alias-lifetime-end",
        "",
        (
            "entry:",
            "  %secret = alloca %SIMD32, align 16",
            "  %alias = getelementptr i8, ptr %secret, i64 0",
            "  call void @llvm.lifetime.start.p0(i64 32, ptr %secret)",
            "  call void @llvm.lifetime.end.p0(i64 32, ptr %alias)",
            (
                '  call void @"$s12SSLCore10SecureWipeO'
                '5erase_9byteCountySv_SitFZ"(ptr %secret, i64 32)'
            ),
            "  call void @llvm.lifetime.end.p0(i64 32, ptr %secret)",
            "  ret void",
        ),
    )
    if not _raises(
        lambda: analyze_scoped_owner(
            early_alias_lifetime_end,
            "%secret",
            ((0, 32),),
            32,
        )
    ):
        raise VerificationError(
            "Self-test accepted cleanup after an alias lifetime end"
        )

    skipped_lifetime = Function(
        "skipped-lifetime",
        "",
        (
            "entry:",
            "  %secret = alloca %SIMD32, align 16",
            "  br i1 %condition, label %live, label %skip",
            "live:",
            "  call void @llvm.lifetime.start.p0(i64 32, ptr %secret)",
            (
                '  call void @"$s12SSLCore10SecureWipeO'
                '5erase_9byteCountySv_SitFZ"(ptr %secret, i64 32)'
            ),
            "  call void @llvm.lifetime.end.p0(i64 32, ptr %secret)",
            "  ret void",
            "skip:",
            "  ret void",
        ),
    )
    if not _raises(
        lambda: analyze_scoped_owner(
            skipped_lifetime,
            "%secret",
            ((0, 32),),
            32,
            requires_lifetime_on_return=True,
        )
    ):
        raise VerificationError(
            "Self-test accepted a return that skipped a required lifetime"
        )

    def scoped_alias_fixture(
        name: str,
        before_wipe: tuple[str, ...] = (),
        after_wipe: tuple[str, ...] = (),
        ranges: tuple[tuple[int, int], ...] = ((0, 32),),
        lifetime_byte_count: int = 32,
        wipe_lines: tuple[str, ...] = (
            (
                '  call void @"$s12SSLCore10SecureWipeO'
                '5erase_9byteCountySv_SitFZ"(ptr %secret, i64 32)'
            ),
        ),
    ) -> tuple[Function, tuple[tuple[int, int], ...], int]:
        return (
            Function(
                name,
                "",
                (
                    "entry:",
                    (
                        f"  %secret = alloca "
                        f"[{lifetime_byte_count} x i8], align 16"
                    ),
                    (
                        "  call void @llvm.lifetime.start.p0("
                        f"i64 {lifetime_byte_count}, ptr %secret)"
                    ),
                    *before_wipe,
                    *wipe_lines,
                    *after_wipe,
                    (
                        "  call void @llvm.lifetime.end.p0("
                        f"i64 {lifetime_byte_count}, ptr %secret)"
                    ),
                    "  ret void",
                ),
            ),
            ranges,
            lifetime_byte_count,
        )

    scoped_alias_fixtures = (
        scoped_alias_fixture(
            "two-stage-slot-address-alias",
            before_wipe=(
                "  %slot.a = alloca ptr",
                "  %slot.pointer = alloca ptr",
                "  store ptr %secret, ptr %slot.a",
                "  store ptr %slot.a, ptr %slot.pointer",
                "  %loaded.slot = load ptr, ptr %slot.pointer",
                "  %alias = load ptr, ptr %loaded.slot",
            ),
            after_wipe=("  store i8 1, ptr %alias",),
        ),
        scoped_alias_fixture(
            "dynamic-slot-store-constant-load",
            before_wipe=(
                "  %slots = alloca [2 x ptr]",
                (
                    "  %dynamic.slot = getelementptr i8, "
                    "ptr %slots, i64 %slot.index"
                ),
                "  store ptr %secret, ptr %dynamic.slot",
                (
                    "  %slot.zero = getelementptr i8, "
                    "ptr %slots, i64 0"
                ),
                "  %alias = load ptr, ptr %slot.zero",
            ),
            after_wipe=("  store i8 1, ptr %alias",),
        ),
        scoped_alias_fixture(
            "global-slot-address-escape",
            before_wipe=(
                "  %slot = alloca ptr",
                "  store ptr %secret, ptr %slot",
                "  store ptr %slot, ptr @savedSlot",
            ),
        ),
        scoped_alias_fixture(
            "loaded-slot-address-memcpy-escape",
            before_wipe=(
                "  %slot.a = alloca ptr",
                "  %slot.pointer = alloca ptr",
                "  store ptr %secret, ptr %slot.a",
                "  store ptr %slot.a, ptr %slot.pointer",
                "  %loaded.slot = load ptr, ptr %slot.pointer",
                (
                    "  call void @llvm.memcpy.p0.p0.i64("
                    "ptr @saved, ptr %loaded.slot, i64 8, i1 false)"
                ),
            ),
        ),
        scoped_alias_fixture(
            "native-integer-slot-address-memcpy-escape",
            before_wipe=(
                "  %slot = alloca ptr",
                "  store ptr %secret, ptr %slot",
                "  %slot.integer = ptrtoint ptr %slot to i64",
                "  %same.integer = xor i64 %slot.integer, 0",
                "  %loaded.slot = inttoptr i64 %same.integer to ptr",
                (
                    "  call void @llvm.memcpy.p0.p0.i64("
                    "ptr @saved, ptr %loaded.slot, i64 8, i1 false)"
                ),
            ),
        ),
        scoped_alias_fixture(
            "wasm-integer-slot-address-memcpy-escape",
            before_wipe=(
                "  %slot = alloca ptr",
                "  store ptr %secret, ptr %slot",
                "  %slot.integer = ptrtoint ptr %slot to i32",
                "  %same.integer = xor i32 %slot.integer, 0",
                "  %loaded.slot = inttoptr i32 %same.integer to ptr",
                (
                    "  call void @llvm.memcpy.p0.p0.i32("
                    "ptr @saved, ptr %loaded.slot, i32 4, i1 false)"
                ),
            ),
        ),
        scoped_alias_fixture(
            "mixed-sensitive-load",
            before_wipe=(
                "  %slot.a = alloca ptr",
                "  %slot.b = alloca ptr",
                "  store ptr %secret, ptr %slot.a",
                (
                    "  %source = select i1 %choice, "
                    "ptr %slot.a, ptr %slot.b"
                ),
                "  %alias = load ptr, ptr %source",
            ),
            after_wipe=("  store i8 1, ptr %alias",),
        ),
        scoped_alias_fixture(
            "local-slot-memcpy",
            before_wipe=(
                "  %slot.a = alloca ptr",
                "  %slot.b = alloca ptr",
                "  store ptr %secret, ptr %slot.a",
                (
                    "  call void @llvm.memcpy.p0.p0.i64("
                    "ptr %slot.b, ptr %slot.a, i64 8, i1 false)"
                ),
                "  %alias = load ptr, ptr %slot.b",
            ),
            after_wipe=("  store i8 1, ptr %alias",),
        ),
        scoped_alias_fixture(
            "global-slot-memcpy",
            before_wipe=(
                "  %slot = alloca ptr",
                "  store ptr %secret, ptr %slot",
                (
                    "  call void @llvm.memcpy.p0.p0.i64("
                    "ptr @saved, ptr %slot, i64 8, i1 false)"
                ),
            ),
        ),
        scoped_alias_fixture(
            "indirect-capture",
            before_wipe=("  call void %function(ptr %secret)",),
        ),
        scoped_alias_fixture(
            "aggregate-alias-return",
            before_wipe=(
                (
                    "  %pair = call { ptr, i64 } "
                    "@aliasPair(ptr %secret)"
                ),
                (
                    "  %alias = extractvalue "
                    "{ ptr, i64 } %pair, 0"
                ),
            ),
            after_wipe=("  store i8 1, ptr %alias",),
        ),
        scoped_alias_fixture(
            "nonescaping-slot-reader",
            before_wipe=(
                "  %slot = alloca ptr",
                "  store ptr %secret, ptr %slot",
                (
                    "  %alias = call ptr @readSlot("
                    "ptr captures(none) %slot)"
                ),
            ),
            after_wipe=("  store i8 1, ptr %alias",),
        ),
        scoped_alias_fixture(
            "nonexact-second-wipe",
            after_wipe=(
                (
                    '  call void @"$s12SSLCore10SecureWipeO'
                    '5erase_9byteCountySv_SitFZ"'
                    "(ptr %secret, i64 %dynamicCount)"
                ),
            ),
        ),
        scoped_alias_fixture(
            "operand-bundle-fake-wipe",
            wipe_lines=(
                (
                    '  call swiftcc void @"$s12SSLCore10SecureWipeO'
                    '5erase_9byteCountySv_SitFZ"'
                    "(ptr %other, i64 %dynamicCount) "
                    '[ "deopt"(ptr %secret, i64 32) ]'
                ),
            ),
        ),
        scoped_alias_fixture(
            "operand-bundle-memset-count",
            after_wipe=(
                (
                    "  call void @llvm.memset.p0.i64("
                    "ptr %secret, i8 1, i64 %dynamicCount, i1 false) "
                    '[ "deopt"(i64 0) ]'
                ),
            ),
        ),
        scoped_alias_fixture(
            "intrinsic-looking-alias-redirty",
            after_wipe=(
                (
                    "  %llvm.lifetime.alias = getelementptr i8, "
                    "ptr %secret, i64 0"
                ),
                "  store i8 1, ptr %llvm.lifetime.alias",
            ),
        ),
        scoped_alias_fixture(
            "out-of-range-write",
            after_wipe=(
                (
                    "  %before = getelementptr i8, "
                    "ptr %secret, i64 -1"
                ),
                "  store i8 1, ptr %before",
            ),
        ),
        scoped_alias_fixture(
            "cross-range-wide-store",
            after_wipe=(
                (
                    "  %boundary = getelementptr i8, "
                    "ptr %secret, i64 31"
                ),
                "  store volatile i64 1, ptr %boundary",
                (
                    '  call void @"$s12SSLCore10SecureWipeO'
                    '5erase_9byteCountySv_SitFZ"'
                    "(ptr %secret, i64 32)"
                ),
            ),
            ranges=((0, 32), (32, 32)),
            lifetime_byte_count=64,
            wipe_lines=(
                (
                    '  call void @"$s12SSLCore10SecureWipeO'
                    '5erase_9byteCountySv_SitFZ"'
                    "(ptr %secret, i64 32)"
                ),
                (
                    "  %second = getelementptr i8, "
                    "ptr %secret, i64 32"
                ),
                (
                    '  call void @"$s12SSLCore10SecureWipeO'
                    '5erase_9byteCountySv_SitFZ"'
                    "(ptr %second, i64 32)"
                ),
            ),
        ),
    )
    for fixture, ranges, lifetime_byte_count in scoped_alias_fixtures:
        if not _raises(
            lambda fixture=fixture, ranges=ranges,
            lifetime_byte_count=lifetime_byte_count:
                analyze_scoped_owner(
                    fixture,
                    "%secret",
                    ranges,
                    lifetime_byte_count,
                )
        ):
            raise VerificationError(
                f"Self-test accepted scoped alias fixture {fixture.name}"
            )

    sensitive_return = Function(
        "sensitive-return",
        'define ptr @"sensitive-return"() {',
        (
            "entry:",
            "  %secret = alloca [32 x i8], align 16",
            "  %alias = getelementptr i8, ptr %secret, i64 0",
            "  call void @llvm.lifetime.start.p0(i64 32, ptr %secret)",
            (
                '  call void @"$s12SSLCore10SecureWipeO'
                '5erase_9byteCountySv_SitFZ"(ptr %secret, i64 32)'
            ),
            "  call void @llvm.lifetime.end.p0(i64 32, ptr %secret)",
            "  ret ptr %alias",
        ),
    )
    if not _raises(
        lambda: analyze_scoped_owner(
            sensitive_return,
            "%secret",
            ((0, 32),),
            32,
        )
    ):
        raise VerificationError(
            "Self-test accepted a sensitive alias return"
        )

    fake_deallocator = Function(
        "fake-deallocator",
        "",
        (
            "entry:",
            "  %innerState = getelementptr i8, ptr %0, i64 16",
            (
                '  call void @"$s12SSLCore10SecureWipeO'
                '5erase_9byteCountySv_SitFZ"(ptr %innerState, i64 32)'
            ),
            "  %innerBlock = getelementptr i8, ptr %0, i64 48",
            (
                '  call void @"$s12SSLCore10SecureWipeO'
                '5erase_9byteCountySv_SitFZ"(ptr %innerBlock, i64 64)'
            ),
            "  %outerState = getelementptr i8, ptr %0, i64 128",
            (
                '  call void @"$s12SSLCore10SecureWipeO'
                '5erase_9byteCountySv_SitFZ"(ptr %outerState, i64 32)'
            ),
            "  %outerBlock = getelementptr i8, ptr %0, i64 160",
            (
                '  call void @"$s12SSLCore10SecureWipeO'
                '5erase_9byteCountySv_SitFZ"(ptr %outerBlock, i64 64)'
            ),
            (
                "  call void @redirty_swift_deallocClassInstance("
                "ptr captures(none) %0)"
            ),
            "  ret void",
        ),
    )
    if not _raises(
        lambda: analyze_hmac_storage_deinit(fake_deallocator)
    ):
        raise VerificationError(
            "Self-test accepted a fake deallocator symbol"
        )

    wrong_alignment_deallocator = Function(
        "wrong-alignment-deallocator",
        "",
        fake_deallocator.lines[:-2]
        + (
            (
                "  call void @swift_deallocClassInstance("
                "ptr %0, i64 240, i64 0)"
            ),
            "  ret void",
        ),
    )
    if not _raises(
        lambda: analyze_hmac_storage_deinit(
            wrong_alignment_deallocator
        )
    ):
        raise VerificationError(
            "Self-test accepted a wrong deallocator alignment mask"
        )

    canonical_deinit = next(
        symbol
        for symbol in HMAC_STORAGE_DEINIT_SYMBOLS
        if symbol.startswith("$s")
    )
    broken_canonical_deinit = Function(
        canonical_deinit,
        "",
        ("entry:", "  ret void"),
    )
    valid_deinit_decoy = Function(
        f"{canonical_deinit}decoy",
        "",
        fake_deallocator.lines[:-2] + ("  ret void",),
    )
    if _raises(
        lambda: analyze_hmac_storage_deinit(valid_deinit_decoy)
    ):
        raise VerificationError(
            "Self-test constructed an invalid deinitializer decoy"
        )
    selected_deinitializers = require_exact_functions(
        (valid_deinit_decoy, broken_canonical_deinit),
        HMAC_STORAGE_DEINIT_SYMBOLS,
        "self-test deinitializer",
    )
    if selected_deinitializers != (broken_canonical_deinit,) or not all(
        _raises(lambda function=function: analyze_hmac_storage_deinit(function))
        for function in selected_deinitializers
    ):
        raise VerificationError(
            "Self-test allowed a valid decoy to mask a broken canonical body"
        )

    pointer_returning_helper = Function(
        "pointer-returning-helper",
        (
            'define swiftcc ptr @"pointer-returning-helper"'
            "(ptr %0, i32 %1, i32 %2) {"
        ),
        (
            "entry:",
            "  %length = sub i32 %2, %1",
            (
                '  call swiftcc void @"$s12SSLCore10SecureWipeO'
                '5erase_9byteCountySv_SitFZ"(ptr %0, i32 %length)'
            ),
            "  ret ptr %0",
        ),
    )
    if not _raises(
        lambda: analyze_outlined_wipe_helper(
            pointer_returning_helper,
            "%0",
            "%1",
            "%2",
        )
    ):
        raise VerificationError(
            "Self-test accepted a pointer-returning cleanup helper"
        )

    assigned_cleanup_call = Function(
        "assigned-cleanup-call",
        (
            'define swiftcc void @"assigned-cleanup-call"'
            "(i32 %0, i32 %1) {"
        ),
        (
            "entry:",
            "  %pointer = inttoptr i32 %0 to ptr",
            (
                '  %escaped = call swiftcc ptr @"cleanup"'
                "(ptr %pointer, i32 %0, i32 %1)"
            ),
            "  ret void",
        ),
    )
    if not _raises(
        lambda: analyze_outlined_cleanup_closure(
            assigned_cleanup_call,
            "%0",
            "%1",
            "cleanup",
        )
    ):
        raise VerificationError(
            "Self-test accepted an assigned cleanup call"
        )

    base_wipe = (
        "$s12SSLCore10SecureWipeO5erase_9byteCountySv_SitFZ"
    )
    specialization = f"{base_wipe}Tf4nnd_n"

    def direct_wipe_fixture(
        name: str,
        start: int = 0,
        stride: int = 1,
        positive_prefix: tuple[str, ...] = (),
        exit_prefix: tuple[str, ...] = (),
        negative_expression: str = "icmp slt i64 %1, 0",
        exit_terminator: str = "ret void",
    ) -> Function:
        return Function(
            name,
            (
                f'define swiftcc void @"{name}"'
                "(ptr %0, i64 %1) {"
            ),
            (
                "entry:",
                f"  %negative = {negative_expression}",
                (
                    "  br i1 %negative, "
                    "label %trap, label %nonnegative"
                ),
                "nonnegative:",
                "  %zero = icmp eq i64 %1, 0",
                "  br i1 %zero, label %exit, label %positive",
                "positive:",
                *positive_prefix,
                "  br label %loop",
                "loop:",
                (
                    f"  %index = phi i64 [ {start}, %positive ], "
                    "[ %next, %loop ]"
                ),
                (
                    "  %address = getelementptr i8, "
                    "ptr %0, i64 %index"
                ),
                (
                    "  store atomic volatile i8 0, ptr %address "
                    "monotonic, align 1"
                ),
                f"  %next = add i64 %index, {stride}",
                "  %done = icmp eq i64 %next, %1",
                "  br i1 %done, label %exit, label %loop",
                "exit:",
                *exit_prefix,
                f"  {exit_terminator}",
                "trap:",
                "  call void @llvm.trap()",
                "  unreachable",
            ),
        )

    valid_direct_wipe = direct_wipe_fixture(specialization)
    if _raises(
        lambda: verify_direct_secure_wipe_body(valid_direct_wipe)
    ):
        raise VerificationError(
            "Self-test rejected an exact direct wipe loop"
        )

    bypass_direct_wipe = direct_wipe_fixture(
        "bypass-direct-wipe",
        positive_prefix=(
            "  br i1 %skip, label %exit, label %wipe.entry",
            "wipe.entry:",
        ),
    )
    for invalid_wipe, reason in (
        (bypass_direct_wipe, "positive-count bypass"),
        (
            direct_wipe_fixture("wrong-start-wipe", start=64),
            "nonzero loop origin",
        ),
        (
            direct_wipe_fixture("wrong-stride-wipe", stride=2),
            "non-unit loop stride",
        ),
        (
            direct_wipe_fixture(
                "reversed-negative-guard",
                negative_expression="icmp slt i64 0, %1",
            ),
            "reversed negative guard",
        ),
        (
            direct_wipe_fixture(
                "nonreturning-completion",
                exit_terminator="unreachable",
            ),
            "nonreturning completion",
        ),
        (
            direct_wipe_fixture(
                "redirty-after-wipe",
                exit_prefix=("  store i8 1, ptr %0",),
            ),
            "post-wipe mutation",
        ),
    ):
        if not _raises(
            lambda invalid_wipe=invalid_wipe:
                verify_direct_secure_wipe_body(invalid_wipe)
        ):
            raise VerificationError(
                f"Self-test accepted direct wipe {reason}"
            )

    unrolled_wipe_lines = (
        "entry:",
        "  %2 = freeze i32 %1",
        "  %3 = icmp slt i32 %2, 0",
        "  br i1 %3, label %trap, label %nonnegative",
        "nonnegative:",
        "  %4 = icmp eq i32 %2, 0",
        "  br i1 %4, label %exit, label %dispatch",
        "dispatch:",
        "  %remainder = and i32 %2, 7",
        "  %small = icmp ult i32 %2, 8",
        "  br i1 %small, label %remainder.dispatch, label %main.setup",
        "main.setup:",
        "  %chunk.end = and i32 %2, -8",
        "  %base.1 = getelementptr i8, ptr %0, i32 1",
        "  %base.2 = getelementptr i8, ptr %0, i32 2",
        "  %base.3 = getelementptr i8, ptr %0, i32 3",
        "  %base.4 = getelementptr i8, ptr %0, i32 4",
        "  %base.5 = getelementptr i8, ptr %0, i32 5",
        "  %base.6 = getelementptr i8, ptr %0, i32 6",
        "  %base.7 = getelementptr i8, ptr %0, i32 7",
        "  br label %main",
        "main:",
        "  %index = phi i32 [ 0, %main.setup ], [ %index.next, %main ]",
        "  %counter = phi i32 [ 0, %main.setup ], [ %counter.next, %main ]",
        "  %address.0 = getelementptr i8, ptr %0, i32 %index",
        "  store atomic volatile i8 0, ptr %address.0 monotonic, align 1",
        "  %address.1 = getelementptr i8, ptr %base.1, i32 %index",
        "  store atomic volatile i8 0, ptr %address.1 monotonic, align 1",
        "  %address.2 = getelementptr i8, ptr %base.2, i32 %index",
        "  store atomic volatile i8 0, ptr %address.2 monotonic, align 1",
        "  %address.3 = getelementptr i8, ptr %base.3, i32 %index",
        "  store atomic volatile i8 0, ptr %address.3 monotonic, align 1",
        "  %address.4 = getelementptr i8, ptr %base.4, i32 %index",
        "  store atomic volatile i8 0, ptr %address.4 monotonic, align 1",
        "  %address.5 = getelementptr i8, ptr %base.5, i32 %index",
        "  store atomic volatile i8 0, ptr %address.5 monotonic, align 1",
        "  %address.6 = getelementptr i8, ptr %base.6, i32 %index",
        "  store atomic volatile i8 0, ptr %address.6 monotonic, align 1",
        "  %index.next = add i32 %index, 8",
        "  %address.7 = getelementptr i8, ptr %base.7, i32 %index",
        "  store atomic volatile i8 0, ptr %address.7 monotonic, align 1",
        "  %counter.next = add i32 %counter, 8",
        "  %main.done = icmp eq i32 %counter.next, %chunk.end",
        "  br i1 %main.done, label %remainder.dispatch, label %main",
        "remainder.dispatch:",
        "  %epilogue.start = phi i32 [ 0, %dispatch ], [ %index.next, %main ]",
        "  %remainder.zero = icmp eq i32 %remainder, 0",
        "  br i1 %remainder.zero, label %exit, label %epilogue",
        "epilogue:",
        (
            "  %epilogue.index = phi i32 "
            "[ %epilogue.start, %remainder.dispatch ], "
            "[ %epilogue.index.next, %epilogue ]"
        ),
        (
            "  %epilogue.counter = phi i32 "
            "[ 0, %remainder.dispatch ], "
            "[ %epilogue.counter.next, %epilogue ]"
        ),
        "  %epilogue.index.next = add i32 %epilogue.index, 1",
        (
            "  %epilogue.address = getelementptr i8, "
            "ptr %0, i32 %epilogue.index"
        ),
        (
            "  store atomic volatile i8 0, ptr %epilogue.address "
            "monotonic, align 1"
        ),
        "  %epilogue.counter.next = add i32 %epilogue.counter, 1",
        (
            "  %epilogue.done = icmp eq i32 "
            "%epilogue.counter.next, %remainder"
        ),
        "  br i1 %epilogue.done, label %exit, label %epilogue",
        "exit:",
        "  ret void",
        "trap:",
        "  call void @llvm.trap()",
        "  unreachable",
    )

    def unrolled_wipe_fixture(
        name: str,
        replacements: tuple[tuple[str, str], ...] = (),
        extra_main_setup_lines: tuple[str, ...] = (),
    ) -> Function:
        replacement_map = dict(replacements)
        lines: list[str] = []
        for line in unrolled_wipe_lines:
            lines.append(replacement_map.get(line, line))
            if line == "main.setup:":
                lines.extend(extra_main_setup_lines)
        return Function(
            name,
            f'define swiftcc void @"{name}"(ptr %0, i32 %1) {{',
            tuple(lines),
        )

    valid_unrolled_wipe = unrolled_wipe_fixture(
        "valid-unrolled-wipe"
    )
    if _raises(
        lambda: verify_direct_secure_wipe_body(valid_unrolled_wipe)
    ):
        raise VerificationError(
            "Self-test rejected an exact unrolled wipe loop"
        )

    optimized_unrolled_wipe_lines = (
        "entry:",
        "  %negative = icmp slt i64 %1, 0",
        "  br i1 %negative, label %trap, label %nonnegative",
        "nonnegative:",
        "  %zero = icmp eq i64 %1, 0",
        "  br i1 %zero, label %exit, label %dispatch",
        "dispatch:",
        "  %chunk.end = and i64 %1, 9223372036854775800",
        "  %remainder = and i64 %1, 7",
        "  %large = icmp samesign ugt i64 %1, 7",
        "  br i1 %large, label %main, label %small.dispatch",
        "main:",
        "  %index = phi i64 [ %index.next, %main ], [ 0, %dispatch ]",
        "  %address.0 = getelementptr inbounds nuw i8, ptr %0, i64 %index",
        "  store atomic volatile i8 0, ptr %address.0 monotonic, align 1",
        "  %address.1 = getelementptr i8, ptr %address.0, i64 1",
        "  store atomic volatile i8 0, ptr %address.1 monotonic, align 1",
        "  %address.2 = getelementptr i8, ptr %address.0, i64 2",
        "  store atomic volatile i8 0, ptr %address.2 monotonic, align 1",
        "  %address.3 = getelementptr i8, ptr %address.0, i64 3",
        "  store atomic volatile i8 0, ptr %address.3 monotonic, align 1",
        "  %address.4 = getelementptr i8, ptr %address.0, i64 4",
        "  store atomic volatile i8 0, ptr %address.4 monotonic, align 1",
        "  %address.5 = getelementptr i8, ptr %address.0, i64 5",
        "  store atomic volatile i8 0, ptr %address.5 monotonic, align 1",
        "  %address.6 = getelementptr i8, ptr %address.0, i64 6",
        "  store atomic volatile i8 0, ptr %address.6 monotonic, align 1",
        "  %address.7 = getelementptr i8, ptr %address.0, i64 7",
        "  store atomic volatile i8 0, ptr %address.7 monotonic, align 1",
        "  %index.next = add nuw nsw i64 %index, 8",
        "  %main.done = icmp eq i64 %index.next, %chunk.end",
        "  br i1 %main.done, label %main.dispatch, label %main",
        "small.dispatch:",
        "  %small.empty = icmp eq i64 %remainder, 0",
        "  br i1 %small.empty, label %exit, label %tail.setup",
        "main.dispatch:",
        "  %main.empty = icmp eq i64 %remainder, 0",
        "  br i1 %main.empty, label %exit, label %tail.setup",
        "tail.setup:",
        (
            "  %tail.start = phi i64 "
            "[ 0, %small.dispatch ], [ %chunk.end, %main.dispatch ]"
        ),
        "  br label %tail",
        "tail:",
        "  %tail.counter = phi i64 [ %tail.counter.next, %tail ], [ 0, %tail.setup ]",
        "  %tail.index = phi i64 [ %tail.index.next, %tail ], [ %tail.start, %tail.setup ]",
        "  %tail.address = getelementptr inbounds i8, ptr %0, i64 %tail.index",
        "  store atomic volatile i8 0, ptr %tail.address monotonic, align 1",
        "  %tail.index.next = add i64 %tail.index, 1",
        "  %tail.counter.next = add i64 %tail.counter, 1",
        "  %tail.done = icmp eq i64 %tail.counter.next, %remainder",
        "  br i1 %tail.done, label %exit, label %tail",
        "exit:",
        "  ret void",
        "trap:",
        "  call void @llvm.trap()",
        "  unreachable",
    )

    def optimized_unrolled_wipe_fixture(
        name: str,
        replacements: tuple[tuple[str, str], ...] = (),
    ) -> Function:
        replacement_map = dict(replacements)
        return Function(
            name,
            f'define swiftcc void @"{name}"(ptr %0, i64 %1) {{',
            tuple(
                replacement_map.get(line, line)
                for line in optimized_unrolled_wipe_lines
            ),
        )

    optimized_unrolled_wipe = optimized_unrolled_wipe_fixture(
        "optimized-unrolled-wipe"
    )
    if _raises(
        lambda: verify_direct_secure_wipe_body(optimized_unrolled_wipe)
    ):
        raise VerificationError(
            "Self-test rejected the optimized unrolled wipe CFG"
        )

    for invalid_unrolled, reason in (
        (
            optimized_unrolled_wipe_fixture(
                "optimized-wrong-chunk-mask",
                ((
                    "  %chunk.end = and i64 %1, 9223372036854775800",
                    "  %chunk.end = and i64 %1, 9223372036854775792",
                ),),
            ),
            "wrong nonnegative chunk mask",
        ),
        (
            optimized_unrolled_wipe_fixture(
                "optimized-reversed-large-guard",
                ((
                    "  %large = icmp samesign ugt i64 %1, 7",
                    "  %large = icmp samesign ugt i64 7, %1",
                ),),
            ),
            "reversed samesign large-count guard",
        ),
        (
            optimized_unrolled_wipe_fixture(
                "optimized-small-tail-bypass",
                ((
                    "  br i1 %small.empty, label %exit, label %tail.setup",
                    "  br i1 %small.empty, label %exit, label %exit",
                ),),
            ),
            "small-count tail bypass",
        ),
    ):
        if not _raises(
            lambda invalid_unrolled=invalid_unrolled:
                verify_direct_secure_wipe_body(invalid_unrolled)
        ):
            raise VerificationError(
                f"Self-test accepted optimized unrolled wipe {reason}"
            )

    unrolled_width_replacements = (
        (
            (
                "  %index = phi i32 "
                "[ 0, %main.setup ], [ %index.next, %main ]"
            ),
            (
                "  %index = phi i64 "
                "[ 0, %main.setup ], [ %index.next, %main ]"
            ),
        ),
        (
            "  %index.next = add i32 %index, 8",
            "  %index.next = add i64 %index, 8",
        ),
    ) + tuple(
        (
            f"  %address.{index} = getelementptr i8, "
            f"ptr {'%0' if index == 0 else f'%base.{index}'}, i32 %index",
            f"  %address.{index} = getelementptr i8, "
            f"ptr {'%0' if index == 0 else f'%base.{index}'}, i64 %index",
        )
        for index in range(8)
    )
    for invalid_unrolled, reason in (
        (
            unrolled_wipe_fixture(
                "unrolled-reversed-small-guard",
                (
                    (
                        "  %small = icmp ult i32 %2, 8",
                        "  %small = icmp ult i32 8, %2",
                    ),
                ),
            ),
            "reversed small-count guard",
        ),
        (
            unrolled_wipe_fixture(
                "unrolled-extra-store-block",
                extra_main_setup_lines=(
                    (
                        "  store atomic volatile i8 0, ptr %0 "
                        "monotonic, align 1"
                    ),
                ),
            ),
            "extra store block",
        ),
        (
            unrolled_wipe_fixture(
                "unrolled-large-path-bypass",
                (
                    (
                        (
                            "  br i1 %small, label %remainder.dispatch, "
                            "label %main.setup"
                        ),
                        (
                            "  br i1 %small, label %remainder.dispatch, "
                            "label %remainder.dispatch"
                        ),
                    ),
                ),
            ),
            "large-count main-loop bypass",
        ),
        (
            unrolled_wipe_fixture(
                "unrolled-address-width-mismatch",
                unrolled_width_replacements,
            ),
            "address/count width mismatch",
        ),
    ):
        if not _raises(
            lambda invalid_unrolled=invalid_unrolled:
                verify_direct_secure_wipe_body(invalid_unrolled)
        ):
            raise VerificationError(
                f"Self-test accepted unrolled wipe {reason}"
            )

    no_op_wipe = Function(
        base_wipe,
        (
            f'define swiftcc void @"{base_wipe}"'
            "(ptr %0, i64 %1) {"
        ),
        ("entry:", "  ret void"),
    )
    wipe_consumer = Function(
        "wipe-consumer",
        'define swiftcc void @"wipe-consumer"(ptr %0, i64 %1) {',
        (
            "entry:",
            f'  call swiftcc void @"{base_wipe}"(ptr %0, i64 %1)',
            "  ret void",
        ),
    )
    if not _raises(
        lambda: verified_secure_wipe_symbols(
            (wipe_consumer, no_op_wipe, valid_direct_wipe)
        )
    ):
        raise VerificationError(
            "Self-test accepted an unused valid wipe beside a no-op target"
        )

    for instruction, reason in (
        ("  call void @redirty(ptr %0)", "unknown redirty call"),
        (
            "  call void @llvm.memset.p0.i64("
            "ptr %0, i8 1, i64 %1, i1 false)",
            "memset redirty call",
        ),
    ):
        redirty_wrapper = Function(
            base_wipe,
            (
                f'define swiftcc void @"{base_wipe}"'
                "(ptr %0, i64 %1) {"
            ),
            (
                "entry:",
                (
                    f'  call swiftcc void @"{specialization}"'
                    "(ptr %0, i64 %1)"
                ),
                instruction,
                "  ret void",
            ),
        )
        if not _raises(
            lambda redirty_wrapper=redirty_wrapper:
                verified_secure_wipe_symbols(
                    (wipe_consumer, redirty_wrapper, valid_direct_wipe)
                )
        ):
            raise VerificationError(
                f"Self-test accepted SecureWipe wrapper {reason}"
            )

    def constant_time_fixture(
        final_predicate: str = "eq",
        limit: str = "%1",
        bypass_load: bool = False,
        include_rhs: bool = True,
    ) -> Function:
        entry_loads = (
            (
                "  %early.ptr = getelementptr i8, ptr %0, i32 0",
                "  %early = load i8, ptr %early.ptr",
            )
            if bypass_load
            else ()
        )
        rhs_lines = (
            (
                "  %rhs.ptr = getelementptr i8, ptr %2, i32 %index",
                "  %rhs = load i8, ptr %rhs.ptr",
                "  %difference = xor i8 %lhs, %rhs",
            )
            if include_rhs
            else (
                "  %difference = xor i8 %lhs, %lhs",
            )
        )
        return Function(
            "constant-time-fixture",
            "define i1 @constant-time-fixture(i32 %0, i32 %1, i32 %2, i32 %3) {",
            (
                "entry:",
                *entry_loads,
                "  %length.ok = icmp eq i32 %1, %3",
                "  br i1 %length.ok, label %equal, label %mismatch",
                "equal:",
                "  br label %loop",
                "loop:",
                "  %index = phi i32 [ 0, %equal ], [ %next, %loop ]",
                "  %acc = phi i8 [ 0, %equal ], [ %reduced, %loop ]",
                "  %lhs.ptr = getelementptr i8, ptr %0, i32 %index",
                "  %lhs = load i8, ptr %lhs.ptr",
                *rhs_lines,
                "  %reduced = or i8 %difference, %acc",
                "  %next = add i32 %index, 1",
                f"  %done = icmp eq i32 %next, {limit}",
                "  br i1 %done, label %finish, label %loop",
                "finish:",
                f"  %result = icmp {final_predicate} i8 %reduced, 0",
                "  ret i1 %result",
                "mismatch:",
                "  ret i1 false",
            ),
        )

    valid_constant_time = constant_time_fixture()
    verify_constant_time(valid_constant_time)
    for fixture, reason in (
        (constant_time_fixture(include_rhs=False), "unpaired lhs loads"),
        (constant_time_fixture(final_predicate="ne"), "reversed equality"),
        (constant_time_fixture(limit="%4"), "partial-prefix loop"),
        (constant_time_fixture(bypass_load=True), "length-gate bypass"),
    ):
        if not _raises(lambda fixture=fixture: verify_constant_time(fixture)):
            raise VerificationError(
                f"Self-test accepted constant-time fixture {reason}"
            )

    secret_deinitializer = (
        '$s12SSLCore11SecretBytesVfD'
    )
    secret_wipe = next(iter(SECURE_WIPE_SYMBOLS))
    dirty_secret_ir = "\n".join(
        (
            f'define swiftcc void @"{secret_deinitializer}"(ptr %0, i64 %1) {{',
            "entry:",
            "  br i1 %condition, label %clean, label %dirty",
            "clean:",
            f'  call swiftcc void @"{secret_wipe}"(ptr %0, i64 %1)',
            "  call void @swift_slowDealloc(ptr %0, i64 -1, i64 -1)",
            "  ret void",
            "dirty:",
            "  call void @swift_slowDealloc(ptr %0, i64 -1, i64 -1)",
            "  ret void",
            "}",
        )
    )
    if not _raises(
        lambda: verify_secret_bytes_ir(
            "secret-bytes-dirty-path",
            dirty_secret_ir,
            embedded=True,
        )
    ):
        raise VerificationError(
            "Self-test accepted a SecretBytes deallocation bypass"
        )
    print("crypto IR validator self-tests: ok")


def main() -> int:
    if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
        run_self_tests()
        return 0
    if len(sys.argv) == 4 and sys.argv[1] == "--verify-wipe":
        label = sys.argv[2]
        ir = Path(sys.argv[3]).read_text(encoding="utf-8")
        try:
            verified_secure_wipe_symbols(
                parse_functions(ir),
                include_definitions_as_roots=True,
            )
        except VerificationError as error:
            print(f"{label}: {error}", file=sys.stderr)
            return 1
        print(f"{label}: SecureWipe call targets and bodies verified")
        return 0
    if len(sys.argv) != 4:
        print(
            "usage: verify_crypto_ir.py <label> <crypto.ll> <core.ll>\n"
            "       verify_crypto_ir.py --verify-wipe <label> <ir>",
            file=sys.stderr,
        )
        return 2
    label = sys.argv[1]
    crypto_ir = Path(sys.argv[2]).read_text(encoding="utf-8")
    core_ir = Path(sys.argv[3]).read_text(encoding="utf-8")
    try:
        verify_crypto_ir(label, crypto_ir, core_ir)
    except VerificationError as error:
        print(f"{label}: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
