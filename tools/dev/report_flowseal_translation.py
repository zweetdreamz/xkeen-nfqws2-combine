#!/usr/bin/env python3
"""Deterministic old/v2 change-set from the immutable extracted corpus. No I/O network."""
import collections
import json
from pathlib import Path
from unittest import mock

from capture_flowseal_corpus import TUNER


def changes(path):
    data = json.loads(Path(path).read_bytes())
    rows = []
    sources = []
    profiles = {}
    for source in data['files']:
        origin = TUNER.SourceFile(source['name'], '', source['sha'], source['url'])
        sources.append(origin)
        profiles[origin.name] = [TUNER.Profile(origin, item['number'], tuple(tuple(pair) for pair in item['options']))
                                 for item in source['profiles']]
        for item in source['profiles']:
            profile = TUNER.Profile(origin, item['number'], tuple(tuple(pair) for pair in item['options']))
            for service in sorted(set(item['roles']) & {'youtube', 'discord-tcp'}):
                old = TUNER.translate_tls_profile(profile, service)
                result = TUNER.translate_tls_v2(profile, service)
                new = result.candidate

                def final(candidate, service=service, origin=origin):
                    if candidate is None or service != 'youtube':
                        return candidate
                    return TUNER.make_candidate(
                        service=service, source=origin, family=candidate.family,
                        args=(*candidate.args, '--new', *TUNER.NATIVE_QUIC),
                        notes=candidate.notes, rank=candidate.rank)

                old_final, new_final = final(old), final(new)
                rows.append(dict(
                    source=origin.name, profile=profile.number, service=service,
                    status=('rejected' if new is None else 'unchanged' if old and old.args == new.args else 'changed'),
                    reasons=list(result.reasons),
                    old_id=old.candidate_id if old else None,
                    new_id=new.candidate_id if new else None,
                    old_final_id=old_final.candidate_id if old_final else None,
                    new_final_id=new_final.candidate_id if new_final else None,
                    old_args=list(old.args) if old else None,
                    new_args=list(new.args) if new else None,
                ))
    search = {}
    with mock.patch.object(TUNER, 'parse_profiles', side_effect=lambda source: profiles[source.name]):
        for service in ('youtube', 'discord-tcp'):
            for level in ('off', 'safe', 'extended'):
                new = TUNER.build_candidates(service, sources, level)
                with mock.patch.object(TUNER, 'translate_tls_v2', side_effect=lambda p, s: TUNER.TranslationResult(
                        TUNER.translate_tls_profile(p, s))):
                    old = TUNER.build_candidates(service, sources, level)
                old_ids = {candidate.candidate_id for candidate in old}
                new_ids = {candidate.candidate_id for candidate in new}
                search[service + '/' + level] = dict(
                    old=len(old_ids), new=len(new_ids), unchanged=len(old_ids & new_ids),
                    added=sorted(new_ids - old_ids), removed=sorted(old_ids - new_ids))
    return dict(commit=data['commit'], quic='NATIVE_QUIC (fixed comparison suffix)',
                counts=dict(sorted(collections.Counter(row['status'] for row in rows).items())),
                reasons=dict(sorted(collections.Counter(reason for row in rows for reason in row['reasons']).items())),
                rows=rows, search=search)


if __name__ == '__main__':
    root = Path(__file__).resolve().parents[2]
    print(json.dumps(changes(root / 'tests/fixtures/flowseal/phase9-176f56dc3f11.json'),
                     ensure_ascii=False, indent=2))
