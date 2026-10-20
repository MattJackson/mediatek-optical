"""Execute held INTM Thumb instructions offline with Unicorn 2.1.4.

Run with MTK_HOARD_ROOT set, using a Python environment containing unicorn.
This is bounded evidence, not a complete receiver or hardware emulator:
* signature runs start at range selection, after header handling;
* programming runs summarize diagnostic helpers and hardware erase/program I/O;
* unknown paths fail instead of being treated as successful checks.
No drive access is performed. Firmware is read from the private hoard only.
"""
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn.arm_const import (
    UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R4,
    UC_ARM_REG_R5, UC_ARM_REG_R7, UC_ARM_REG_SP, UC_ARM_REG_PC,
    UC_ARM_REG_LR,
    UC_ARM_REG_R3,
)

SIZE = 0x200000
STAGING = 0x02200000
KEY = "5e9e4f0094ef20ab52e35e736acb2324"


def firmware(digest):
    paths = list(Path(os.environ["MTK_HOARD_ROOT"]).joinpath("images/mediatek").rglob(digest + ".bin"))
    assert len(paths) == 1
    data = paths[0].read_bytes()
    assert hashlib.sha256(data).hexdigest() == digest
    return data


def machine(current, wire):
    cpu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    cpu.mem_map(0, SIZE)
    cpu.mem_write(0, current)
    cpu.mem_map(0x01ff0000, 0x10000)
    cpu.mem_map(0x02000000, 0x600000)
    cpu.mem_write(STAGING, wire)
    cpu.mem_map(0x04000000, 0x10000)
    cpu.reg_write(UC_ARM_REG_SP, 0x02080000)
    return cpu


def put(cpu, address, value):
    cpu.mem_write(address, struct.pack("<I", value))


def get(cpu, address):
    return struct.unpack("<I", cpu.mem_read(address, 4))[0]


def header_path(current, wire, flags):
    cpu = machine(current, wire)
    put(cpu, 0x02000c34, STAGING)
    put(cpu, 0x04002058, flags)
    cpu.reg_write(UC_ARM_REG_R5, 1)
    calls = []
    stopped = False

    def step(cpu, address, size, _):
        nonlocal stopped
        if address == 0x9b024:
            source = cpu.reg_read(UC_ARM_REG_R0)
            destination = cpu.reg_read(UC_ARM_REG_R1)
            length = cpu.reg_read(UC_ARM_REG_R2)
            assert source == STAGING + 0x3000 and length == 16
            assert destination == 0x02080014
            plaintext = subprocess.run(
                ["openssl", "enc", "-d", "-aes-128-ecb", "-K", KEY, "-nopad"],
                input=bytes(cpu.mem_read(source, length)), capture_output=True, check=True,
            ).stdout
            cpu.mem_write(destination, plaintext)
            calls.append([source - STAGING, destination, length])
            cpu.reg_write(UC_ARM_REG_PC, cpu.reg_read(UC_ARM_REG_LR))
        elif address == 0xcad8c:
            cpu.reg_write(UC_ARM_REG_PC, cpu.reg_read(UC_ARM_REG_LR))
        elif address == 0x9d4f4:
            stopped = True
            cpu.emu_stop()
        elif not 0x9d478 <= address < 0x9d4f4:
            raise AssertionError(f"unexpected header path {address:x}")

    cpu.hook_add(UC_HOOK_CODE, step)
    cpu.emu_start(0x9d479, 0x200000, count=1000)
    assert stopped and len(calls) == 1
    assert bytes(cpu.mem_read(STAGING, SIZE)) == wire, "scratch decode changed staging"
    header_state = struct.unpack_from("<I", current, 0x9d7d8)[0]
    return {"accepted_header": cpu.mem_read(header_state, 1)[0] == 1,
            "initial_flags": flags, "final_flags": get(cpu, 0x04002058),
            "decode_calls": calls, "aes_primitive": "openssl_model"}


def signature_path(current, wire, flags, through_verifier_wrapper=False):
    cpu = machine(current, wire)
    put(cpu, 0x02000c34, STAGING)
    put(cpu, 0x02000c6c, SIZE)
    put(cpu, 0x04002058, flags)
    cpu.reg_write(UC_ARM_REG_R4, 0x02000c6c)
    cpu.reg_write(UC_ARM_REG_R5, 1)
    cpu.reg_write(UC_ARM_REG_R7, 0x02000c22)
    trace = []

    def step(cpu, address, size, _):
        trace.append(address)
        # Stop before the opaque verifier, or before recording a mismatch.
        endpoint = 0xca62c if through_verifier_wrapper else 0x139938
        if address in (endpoint, 0x9d602):
            cpu.emu_stop()
        elif through_verifier_wrapper and (
            0x139938 <= address <= 0x139972
            or 0xa2178 <= address <= 0xa2240
            or 0xa1f72 <= address <= 0xa1f86
        ):
            pass
        elif not 0x9d522 <= address < 0x9d602:
            raise AssertionError(f"unexpected signature path {address:x}")

    cpu.hook_add(UC_HOOK_CODE, step)
    cpu.emu_start(0x9d523, 0x200000, count=10000)
    endpoint = 0xca62c if through_verifier_wrapper else 0x139938
    assert trace[-1] in (endpoint, 0x9d602), "instruction budget exhausted"
    result = {"flags": flags, "stop": hex(trace[-1]),
            "result": "opaque_verifier_reached" if trace[-1] == 0x139938 else "signature_mismatch",
            "selected_start": get(cpu, 0x02000c68),
            "selected_length": get(cpu, 0x02000c6c), "instructions": len(trace)}
    if trace[-1] == 0xca62c:
        assert cpu.reg_read(UC_ARM_REG_R0) == 0x72
        assert get(cpu, cpu.reg_read(UC_ARM_REG_R1) + 8) == 0x220000
        payload_length = int.from_bytes(cpu.mem_read(STAGING + 0x220000, 4), "big")
        assert payload_length == 0xc00
        assert int.from_bytes(cpu.mem_read(STAGING + 0x22000c, 4), "big") == 0x230028
        payload = bytes(cpu.mem_read(STAGING + 0x220010, payload_length))
        metadata = bytes(cpu.mem_read(STAGING + 0x230000, 0x28))
        assert payload == wire[0x14000:0x14c00]
        assert metadata == wire[0x10618:0x10640]
        result.update(result="secure_dispatch_reached",
                      secure_inputs={"payload_length": payload_length,
                                     "payload_sha256": hashlib.sha256(payload).hexdigest(),
                                     "metadata_sha256": hashlib.sha256(metadata).hexdigest()})
    return result


def acceptance_path(current, wire, flags, secure_result):
    """Execute acceptance control flow with explicit crypto/hardware summaries.

    The opaque secure verifier return is an input, never inferred from a valid
    signature. Tests exercise both returns; request equivalence is tested above.
    """
    cpu = machine(current, wire)
    put(cpu, 0x02000c34, STAGING)
    put(cpu, 0x04002058, flags)
    put(cpu, struct.unpack_from("<I", current, 0x9d7d4)[0], SIZE)
    cpu.reg_write(UC_ARM_REG_R5, 1)
    cpu.reg_write(UC_ARM_REG_R7, 0x02000c22)
    outcome = None
    cmac_checks = []
    summaries = set()

    def returned(value=None):
        if value is not None:
            cpu.reg_write(UC_ARM_REG_R0, value)
        cpu.reg_write(UC_ARM_REG_PC, cpu.reg_read(UC_ARM_REG_LR))

    def step(cpu, address, size, _):
        nonlocal outcome
        if address == 0x9b024:
            assert cpu.reg_read(UC_ARM_REG_R0) == STAGING + 0x3000
            assert cpu.reg_read(UC_ARM_REG_R2) == 16
            decoded = subprocess.run(
                ["openssl", "enc", "-d", "-aes-128-ecb", "-K", KEY, "-nopad"],
                input=wire[0x3000:0x3010], capture_output=True, check=True,
            ).stdout
            cpu.mem_write(cpu.reg_read(UC_ARM_REG_R1), decoded)
            summaries.add("header_AES")
            returned(1)
        elif address == 0x139938:
            # Do not supply a modeled success to different protected content.
            offset = cpu.reg_read(UC_ARM_REG_R0)
            length = cpu.reg_read(UC_ARM_REG_R1)
            metadata = cpu.reg_read(UC_ARM_REG_R2)
            assert (offset, length, metadata) == (0x14000, 0xc00, 0x10618)
            assert wire[offset:offset+length] == current[offset:offset+length]
            assert wire[metadata:metadata+0x28] == current[metadata:metadata+0x28]
            summaries.add("opaque_verifier_return_parameter")
            returned(secure_result)
        elif address == 0x1406ec:
            start = cpu.reg_read(UC_ARM_REG_R0) - STAGING
            end = cpu.reg_read(UC_ARM_REG_R1) - STAGING
            tag = cpu.reg_read(UC_ARM_REG_R2) - STAGING
            assert 0 <= start <= end < SIZE and 0 <= tag <= SIZE - 16
            data = bytes(cpu.mem_read(STAGING + start, end - start + 1))
            reversed_blocks = b"".join(data[i:i+16][::-1] for i in range(0, len(data), 16))
            digest = subprocess.run(
                ["openssl", "dgst", "-mac", "cmac", "-macopt", "cipher:aes-128-cbc",
                 "-macopt", "hexkey:BD209408E35E526A36235234434FE8AB", "-binary"],
                input=reversed_blocks, capture_output=True, check=True,
            ).stdout[::-1]
            valid = digest == bytes(cpu.mem_read(STAGING + tag, 16))
            cmac_checks.append({"start": start, "end": end, "tag": tag, "valid": valid})
            summaries.add("CMAC_primitive")
            returned(int(valid))
        elif address in (0xcad8c, 0x140988, 0x2d4, 0x18032, 0x3bef8, 0xa0eee):
            summaries.add(hex(address))
            returned(0)
        elif address == 0x140a5a:
            assert cpu.reg_read(UC_ARM_REG_R3) == 3
            outcome = {"result": "program_call", "destination": cpu.reg_read(UC_ARM_REG_R0),
                       "source": cpu.reg_read(UC_ARM_REG_R1), "length": cpu.reg_read(UC_ARM_REG_R2)}
            cpu.emu_stop()
        elif address in (0x9d34a, 0x9d602, 0x9d632, 0x9d664, 0x9d678):
            outcome = {"result": "rejected", "address": hex(address)}
            cpu.emu_stop()
        elif not (0x9d478 <= address <= 0x9d69e or 0x9cc90 <= address <= 0x9cd6a
                  or 0x140886 <= address <= 0x140944):
            raise AssertionError(f"unexpected acceptance path {address:x}")

    cpu.hook_add(UC_HOOK_CODE, step)
    cpu.emu_start(0x9d479, 0x200000, count=10000)
    assert outcome is not None, "instruction budget exhausted"
    return {**outcome, "flags": flags, "secure_return": secure_result,
            "cmac_checks": cmac_checks, "summaries": sorted(summaries)}


def program_path(current, wire, start):
    cpu = machine(current, wire)
    # Enter the real mode-three wrapper with the arguments produced by the
    # receiver. Poison its output cells: the wrapper must establish all three.
    for cell in (0x02000c60, 0x02000c68, 0x02000c6c):
        put(cpu, cell, 0xdeadbeef)
    cpu.reg_write(UC_ARM_REG_R0, start)
    cpu.reg_write(UC_ARM_REG_R1, start)
    cpu.reg_write(UC_ARM_REG_R2, SIZE - start)
    cpu.reg_write(UC_ARM_REG_R3, 3)
    summaries = set()
    wrapper_bound = False
    programmed = []
    erased = []
    stopped = False
    instructions = 0

    def step(cpu, address, size, _):
        nonlocal stopped, instructions, wrapper_bound
        instructions += 1
        if address in (0x2d4, 0xa2afe, 0x3feca, 0x1409e2, 0xa07ae, 0xa0776):
            # IRQ / hardware setup only; preserve ABI callee-saved arguments.
            summaries.add(hex(address))
            cpu.reg_write(UC_ARM_REG_R0, 0)
            cpu.reg_write(UC_ARM_REG_PC, cpu.reg_read(UC_ARM_REG_LR))
        elif address == 0x13fb74:
            # Model a present programmable flash device, not a firmware check.
            summaries.add("flash_device_present")
            cpu.reg_write(UC_ARM_REG_R0, 1)
            cpu.reg_write(UC_ARM_REG_PC, cpu.reg_read(UC_ARM_REG_LR))
        elif address == 0x17000:
            assert get(cpu, 0x02000c60) == start
            assert get(cpu, 0x02000c68) == start
            assert get(cpu, 0x02000c6c) == SIZE - start
            wrapper_bound = True
            # Skip hardware register initialization and its polling loop. The
            # loop entry itself still establishes its pointers and 64KiB unit.
            summaries.add("flash_loop_hardware_initialization")
            cpu.reg_write(UC_ARM_REG_PC, 0x172e1)
        elif address == 0x17284:
            stopped = True
            cpu.emu_stop()
        elif address in (0x173c4, 0x17dba):
            # Diagnostic output / watchdog: no mutation of the selected cells.
            cpu.reg_write(UC_ARM_REG_PC, cpu.reg_read(UC_ARM_REG_LR))
        elif address in (0x170dc, 0x171ba):
            # Hardware erase routines are outside the arithmetic model. Record
            # their requested sector and continue with the actual argument setup.
            length = 0x1000 if address == 0x170dc else 0x10000
            erased.append([get(cpu, 0x02000c60), length])
            cpu.reg_write(UC_ARM_REG_PC, (0x17178 if length == 0x1000 else 0x17256) | 1)
        elif address == 0x17406:
            destination = cpu.reg_read(UC_ARM_REG_R0)
            source = cpu.reg_read(UC_ARM_REG_R1)
            length = cpu.reg_read(UC_ARM_REG_R2)
            assert source == destination
            assert length in (0x1000, 0x10000)
            assert destination + length <= SIZE
            programmed.append([destination, source, length])
            cpu.reg_write(UC_ARM_REG_PC, cpu.reg_read(UC_ARM_REG_LR))
        elif not (0x17054 <= address <= 0x172ea or 0x140a5a <= address <= 0x140b9c):
            raise AssertionError(f"unexpected program path {address:x}")

    cpu.hook_add(UC_HOOK_CODE, step)
    cpu.emu_start(0x140a5b, 0x200000, count=100000)
    assert stopped and wrapper_bound, "instruction budget exhausted or wrapper not bound"
    assert erased == [[destination, length] for destination, _, length in programmed]
    spans = []
    for destination, _, length in programmed:
        if spans and spans[-1][1] == destination:
            spans[-1][1] += length
        else:
            spans.append([destination, destination + length])
    assert spans == [[start, 0x1d0000], [0x1ec000, 0x1f0000]]
    assert get(cpu, 0x02000c6c) == 0
    return {"start": start, "spans": spans, "writes": len(programmed),
            "instructions": instructions, "hardware_io": "summarized_not_executed",
            "wrapper_bound": wrapper_bound, "summaries": sorted(summaries)}


def main():
    current = firmware("c3a18eed17251d1508964647e833ffdfe01b13c28dff9a717dfac6336e7c70e6")
    target = firmware("97b287072e20c9527de6f34f6d564c8edcc6afb3ecf5675c11b8262c11663061")
    encrypted = subprocess.run(
        ["openssl", "enc", "-aes-128-ecb", "-K", KEY, "-nopad"],
        input=target, capture_output=True, check=True,
    ).stdout
    assert hashlib.sha256(encrypted).hexdigest() == "5567d28100b951757a5be4950cd1cb89a3d2fdb34d27abc2b68416d8d3c98bfa"
    mixed = bytearray(target)
    mixed[0x3000:0x3010] = encrypted[0x3000:0x3010]
    body_only = bytearray(encrypted)
    body_only[0x3000:0x3010] = target[0x3000:0x3010]
    header_results = []
    for name, wire, expected in [
        ("plaintext", target, False), ("whole_ciphertext", encrypted, True),
        ("header_ciphertext_body_plaintext", bytes(mixed), True),
        ("header_plaintext_body_ciphertext", bytes(body_only), False),
    ]:
        for flags in (0x0b, 0x0a):
            result = header_path(current, wire, flags)
            assert result["accepted_header"] == expected
            assert result["final_flags"] == flags
            result["wire"] = name
            header_results.append(result)
    current_inputs = signature_path(current, current, 0x0a, True)
    target_inputs = signature_path(current, bytes(mixed), 0x0a, True)
    assert current_inputs["secure_inputs"] == target_inputs["secure_inputs"]
    acceptance = []
    for name, wire in [("whole_ciphertext", encrypted), ("mixed", bytes(mixed))]:
        for flags in (0x0b, 0x0a):
            for secure_result in (0, 1):
                result = acceptance_path(current, wire, flags, secure_result)
                should_program = name == "mixed" and flags == 0x0a and secure_result == 1
                assert (result["result"] == "program_call") == should_program, result
                if should_program:
                    assert (result["destination"], result["source"], result["length"]) == (0x10000, 0x10000, 0x1f0000)
                result["wire"] = name
                acceptance.append(result)
    results = []
    for name, wire in [("whole_ciphertext", encrypted), ("header_ciphertext_body_plaintext", bytes(mixed))]:
        for flags in (0x0b, 0x0a):
            result = signature_path(current, wire, flags)
            assert result["result"] == ("signature_mismatch" if name == "whole_ciphertext" else "opaque_verifier_reached")
            result["wire"] = name
            results.append(result)
    # Independently execute altered skip thresholds. Each must violate the
    # expected write spans rather than silently preserving a plausible plan.
    mutations_rejected = []
    for address in (0x1707a, 0x1709c):
        changed = bytearray(current)
        changed[address] ^= 1
        try:
            program_path(bytes(changed), bytes(mixed), 0x10000)
        except AssertionError:
            mutations_rejected.append(hex(address))
        else:
            raise AssertionError(f"reserved threshold mutation accepted: {address:x}")
    wrapper_mutations_rejected = []
    for address in (0x140a5c, 0x140a5e, 0x140a60, 0x140b82, 0x140b86, 0x140b8a):
        changed = bytearray(current)
        changed[address] ^= 1
        try:
            program_path(bytes(changed), bytes(mixed), 0x10000)
        except AssertionError:
            wrapper_mutations_rejected.append(hex(address))
        else:
            raise AssertionError(f"wrapper argument mutation accepted: {address:x}")
    print(json.dumps({"header_paths": header_results, "signature_paths": results,
                      "conditional_acceptance_paths": acceptance,
                      "secure_input_equivalence": {"installed": current_inputs, "candidate": target_inputs},
                      "program_paths": [program_path(current, bytes(mixed), start) for start in (0, 0x10000)],
                      "reserved_threshold_mutations_rejected": mutations_rejected,
                      "wrapper_argument_mutations_rejected": wrapper_mutations_rejected,
                      "complete_receiver_emulation": False}, indent=2))


if __name__ == "__main__":
    main()
