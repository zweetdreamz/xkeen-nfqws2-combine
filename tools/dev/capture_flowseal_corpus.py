"""Capture immutable upstream strategy data for phase9; never execute BAT.

Outputs raw source cache under .cache and extracted JSON fixtures for tests.
Usage: python capture_flowseal_corpus.py COMMIT CACHE_JSON FIXTURE_JSON
"""
import dataclasses
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import urllib.parse
import urllib.request


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('phase9_baseline_tuner', ROOT / 'tools/windows/zapret_tuner.py')
TUNER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = TUNER
SPEC.loader.exec_module(TUNER)


def read(url, maximum):
    request = urllib.request.Request(url, headers={'User-Agent': 'kdn-phase9-corpus', 'Accept': 'application/vnd.github+json'})
    with urllib.request.urlopen(request, timeout=30) as response:
        raw = response.read(maximum + 1)
    if len(raw) > maximum:
        raise ValueError('upstream corpus response exceeds budget')
    return raw


def capture(commit):
    if not TUNER.GIT_SHA_RE.fullmatch(commit):
        raise ValueError('immutable commit SHA required')
    repo = TUNER.DEFAULT_REPOSITORY
    listing = json.loads(read(f'https://api.github.com/repos/{repo}/contents?ref={commit}', 1024 * 1024))
    if not isinstance(listing, list):
        raise ValueError('unexpected repository listing')
    sources, fixtures = [], []
    for item in sorted(listing, key=lambda row: row['name'].lower()):
        name = item['name']
        if item.get('type') != 'file' or not TUNER.SOURCE_NAME_RE.fullmatch(name):
            continue
        if len(sources) >= 64:
            raise ValueError('too many strategy files')
        url = f'https://raw.githubusercontent.com/{repo}/{commit}/' + urllib.parse.quote(name, safe='')
        raw = read(url, 262144)
        git_sha = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
        if git_sha != item['sha']:
            raise ValueError('upstream Git blob mismatch')
        text = raw.decode('utf-8-sig')
        source = TUNER.SourceFile(name, text, git_sha, url)
        sources.append(dict(name=name, text=text, sha=git_sha, url=url, raw_sha256=hashlib.sha256(raw).hexdigest()))
        profiles = []
        for profile in TUNER.parse_profiles(source):
            roles = sorted(TUNER.profile_roles(profile))
            baseline = []
            for service in roles:
                candidate = (TUNER.translate_tls_profile(profile, service) if service in ('youtube', 'discord-tcp')
                             else TUNER.translate_voice_profile(profile) if service == 'discord-voice' else None)
                if candidate is not None:
                    baseline.append(dataclasses.asdict(candidate))
            profiles.append(dict(number=profile.number, options=profile.options, roles=roles, baseline=baseline))
        fixtures.append(dict(name=name, sha=git_sha, url=url, raw_sha256=hashlib.sha256(raw).hexdigest(), profiles=profiles))
    if not sources:
        raise ValueError('empty corpus')
    common = dict(format=1, repository=repo, commit=commit)
    return dict(common, sources=sources), dict(common, files=fixtures)


def main(argv):
    if len(argv) != 3:
        raise ValueError('expected COMMIT CACHE_JSON FIXTURE_JSON')
    commit, cache_name, fixture_name = argv
    cache, fixture = capture(commit)
    for name, value in ((cache_name, cache), (fixture_name, fixture)):
        path = Path(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            raise ValueError('capture refuses to overwrite an existing corpus')
        path.write_bytes((json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode('utf-8'))
    print(json.dumps({'commit': commit, 'files': len(fixture['files']),
                      'profiles': sum(len(row['profiles']) for row in fixture['files'])}))


if __name__ == '__main__':
    main(sys.argv[1:])
