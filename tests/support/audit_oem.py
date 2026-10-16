#!/usr/bin/env python3
"""Build factual expectations from raw hoard bytes and OpenSSL, never this crate.
Usage: audit_oem.py HOARD OUTPUT_JSON
Requires OpenSSL with CMAC support. Does not write to the hoard.
"""
import hashlib, json, pathlib, struct, subprocess, sys
root = pathlib.Path(sys.argv[1])
rows = []
for chip in ('MT1939', 'MT1959'):
    for meta_path in sorted((root / 'images/mediatek' / chip).rglob('*.bin.json')):
        meta = json.loads(meta_path.read_text())
        flags = meta.get('mediatek', {})
        if meta.get('bytes') != 0x200000 or flags.get('patched') or flags.get('fragment'):
            continue
        path = meta_path.with_suffix('')
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        assert digest == meta['sha256'] == path.stem
        banner = data[0x3000:0x3010]
        entries = []
        for index in range(16):
            at = 0x10400 + index * 28
            enabled, start, end, stored = struct.unpack_from('<III16s', data, at)
            if enabled != 1:
                continue
            if not start <= end < len(data):
                entries.append(dict(index=index, start=start, end=end, stored=stored.hex(), invalid_range=True, matches=False))
                continue
            span = data[start:end+1]
            reversed_blocks = b''.join(span[i:i+16][::-1] for i in range(0, len(span), 16))
            result = subprocess.run(['openssl', 'mac', '-macopt', 'cipher:AES-128-CBC',
                '-macopt', 'hexkey:BD209408E35E526A36235234434FE8AB', 'CMAC'],
                input=reversed_blocks, capture_output=True, check=True)
            computed = bytes.fromhex(result.stdout.decode().strip())[::-1]
            entries.append(dict(index=index, start=start, end=end, stored=stored.hex(),
                                openssl=computed.hex(), matches=stored == computed))
        assert entries, path
        extra = dict(mirrored_boot=data[:0x400] == data[0x10000:0x10400])
        if all(e['matches'] for e in entries):
            changed = bytearray(data)
            # Mutate an authenticated data range, then independently re-sign the
            # data tags before the tag covering the integrity table.
            at = next(e['end'] for e in entries if not e['start'] <= 0x10400 <= e['end'])
            changed[at] ^= 1
            for e in sorted(entries, key=lambda e: e['start'] <= 0x10400 <= e['end']):
                span = changed[e['start']:e['end']+1]
                reversed_blocks = b''.join(span[i:i+16][::-1] for i in range(0,len(span),16))
                result = subprocess.run(['openssl','mac','-macopt','cipher:AES-128-CBC',
                    '-macopt','hexkey:BD209408E35E526A36235234434FE8AB','CMAC'],
                    input=reversed_blocks,capture_output=True,check=True)
                tag_at = 0x10400 + e['index'] * 28 + 12
                changed[tag_at:tag_at+16] = bytes.fromhex(result.stdout.decode().strip())[::-1]
            extra.update(resign_mutation=at, resigned_sha256=hashlib.sha256(changed).hexdigest())
        encrypted = subprocess.run(['openssl','enc','-aes-128-ecb','-K',
            '5e9e4f0094ef20ab52e35e736acb2324','-nopad'],input=data,capture_output=True,check=True).stdout
        extra['encrypted_sha256'] = hashlib.sha256(encrypted).hexdigest()
        rows.append(dict(**extra, path=str(path.relative_to(root)), sha256=digest,
            installer_sources=[s for s in meta['sources'] if '.exe' in s['candidate'].lower()],
            sources=meta['sources'], banner_hex=banner.hex(),
            descriptor_hex=data[0x1ec000:0x1ec060].hex(), entries=entries))
pathlib.Path(sys.argv[2]).write_text(json.dumps(rows, indent=2)+'\n')
print(f'{len(rows)} images; {sum(bool(r["installer_sources"]) for r in rows)} with installer provenance; '
      f'{sum(all(e["matches"] for e in r["entries"]) for r in rows)} all tags valid; '
      f'{sum(len(r["entries"]) for r in rows)} active tags')
cases = pathlib.Path(sys.argv[2]).with_name('oem_cases.rs.inc')
cases.write_text(''.join(f'case!(oem_{r["sha256"][:16]}, {i});\n' for i,r in enumerate(rows)))
# Small OEM table records only; these make the independent known-answer test
# runnable in CI without redistributing executable firmware bodies.
vectors = {}
for row in rows:
    if not row['installer_sources']:
        continue
    data = (root / row['path']).read_bytes()
    for e in row['entries']:
        if e['matches'] and e['end'] - e['start'] + 1 <= 432:
            record = data[e['start']:e['end']+1].hex()
            vectors.setdefault(record, dict(data=record, tag=e['stored'],
                source_sha256=row['sha256'],start=e['start'],end=e['end'],index=e['index']))
pathlib.Path(sys.argv[2]).with_name('oem_cmac_vectors.json').write_text(
    json.dumps(list(vectors.values()),indent=2)+'\n')
