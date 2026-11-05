"""Native routing contract: append-only outbounds, DSCP and user policy preservation."""
from copy import deepcopy
from itertools import product
import json
from pathlib import Path
import unittest
from unittest import mock

from kdn.common import jsonc, lock
from kdn.engine import apply_dependencies, apply_files, confvalues, snapshot_store, transaction, xray_patch
from test_engine_apply_files import ApplyFilesFixture


OLD_NAMES = tuple('04_' + service + '_nfqws2_outbound.json'
                  for service in ('discord', 'youtube', 'telegram'))
TAIL_NAMES = tuple(name.replace('.json', '_tail.json') for name in OLD_NAMES)


def prospective(plan):
    result = {name: json.loads(jsonc.strip_json_comments(raw.decode())) for name, raw, _mode in plan.corpus}
    for change in plan.changes:
        if not change.logical.startswith('/opt/etc/xray/configs/'):
            continue
        name = Path(change.logical).name
        if change.after is None:
            result.pop(name, None)
        else:
            result[name] = json.loads(change.after)
    return result


def merged_outbounds(documents):
    """Xray26.10.31 Config.Override: existing tags update, tail appends, else prepend."""
    rows = []
    for number, (name, doc) in enumerate(sorted(documents.items())):
        if number == 0:
            rows = list(doc.get('outbounds', []))
            continue
        prepend = []
        for row in doc.get('outbounds', []):
            index = next((i for i, old in enumerate(rows) if old['tag'] == row['tag']), None)
            if index is not None:
                rows[index] = row
            elif 'tail' in name.lower():
                rows.append(row)
            else:
                prepend.append(row)
        rows = prepend + rows
    return rows


class NativeRoutingContractTests(ApplyFilesFixture, unittest.TestCase):
    def test_late_tail_only_default_change_is_refused_before_rescue_or_writes(self):
        (self.routing.parent / '04_outbounds.json').unlink()
        late = self.put('99_custom_tail.json', {'outbounds': [{'tag': 'vpn', 'protocol': 'vless'}]})
        self.put(OLD_NAMES[0], xray_patch.direct_outbound('discord-direct'))
        before = {path.name: (path.read_bytes(), path.stat().st_mode)
                  for path in self.routing.parent.iterdir()}
        with self.assertRaisesRegex(ValueError, 'unmanaged Xray default'):
            self.plan()
        self.assertEqual({path.name: (path.read_bytes(), path.stat().st_mode)
                          for path in self.routing.parent.iterdir()}, before)
        self.assertTrue(late.exists())
        self.assertFalse(Path(self.paths.snapshot_root).exists())

    def test_late_non_tail_prepend_preserves_default_and_tag_override_position(self):
        (self.routing.parent / '04_outbounds.json').unlink()
        self.put('99_custom_tail.json', {'outbounds': [{'tag': 'vpn', 'protocol': 'vless'}]})
        early = {'tag': 'manual', 'protocol': 'freedom', 'settings': {'domainStrategy': 'UseIPv4'}}
        late = {'tag': 'manual', 'protocol': 'freedom', 'settings': {'domainStrategy': 'UseIPv6'}}
        self.put('02_custom_tail.json', {'outbounds': [early]})
        self.put('98_override.json', {'outbounds': [late]})
        plan = self.plan()
        self.assertEqual(merged_outbounds(prospective(plan))[0], late)
        self.put('97_new_default.json', {'outbounds': [{'tag': 'later-new', 'protocol': 'freedom'}]})
        plan = self.plan()
        self.assertEqual(merged_outbounds(prospective(plan))[0]['tag'], 'later-new')

    def test_new_outbounds_append_without_changing_unmanaged_default(self):
        self.put('04_outbounds.json', {'outbounds': [
            {'tag': 'vpn', 'protocol': 'vless'}, {'tag': 'direct', 'protocol': 'freedom'},
            {'tag': 'block', 'protocol': 'blackhole'}]})
        self.put('03_user_outbound.json', {'outbounds': [{'tag': 'custom', 'protocol': 'freedom'}]})
        plan = self.plan()
        baseline = {name: json.loads(raw) for name, raw, _mode in plan.corpus}
        before = merged_outbounds(baseline)
        after = merged_outbounds(prospective(plan))
        self.assertEqual(after[:len(before)], before)
        self.assertEqual(after[0]['tag'], 'vpn')
        self.assertTrue(all('tail' in name for name in apply_files.OWNED_OUTBOUNDS))
        self.assertEqual(set(apply_files.OWNED_OUTBOUNDS), set(TAIL_NAMES))

    def test_old_owned_migration_staging_and_restore_bytes_modes_absence(self):
        old = self.put(OLD_NAMES[0], xray_patch.direct_outbound('discord-direct', 255))
        old.write_bytes(b'// legacy owned\n' + old.read_bytes())
        original = old.read_bytes()
        plan, rescue = self.plan(), self.capture()
        self.assertIsNone(next(c.after for c in plan.changes if c.logical.endswith(OLD_NAMES[0])))
        self.assertIn(TAIL_NAMES[0], prospective(plan))
        def inspect(argv, _env, **_kwargs):
            from types import SimpleNamespace
            stage = Path(argv[argv.index('-confdir') + 1])
            self.assertFalse((stage / OLD_NAMES[0]).exists())
            self.assertTrue((stage / TAIL_NAMES[0]).exists())
            self.assertTrue(old.exists())
            return SimpleNamespace(returncode=0, timed_out=False, output_limited=False)
        stack, runner = self.checker(inspect)
        with stack, lock.ProjectLock(self.paths.lock_dir):
            tx = transaction.Transaction(self.ctx)
            tx.arm(lambda: apply_files.restore_files(self.ctx, plan, rescue))
            apply_files.publish(tx, plan, rescue)
            self.assertFalse(old.exists())
            self.assertTrue((old.parent / TAIL_NAMES[0]).exists())
            tx.rollback()
        self.assertEqual(runner.call_count, 1)
        self.assertEqual(old.read_bytes(), original)
        self.assertEqual(old.stat().st_mode & 0o777, 0o640)
        self.assertFalse((old.parent / TAIL_NAMES[0]).exists())

    def test_reserved_foreign_fields_and_ambiguous_collision_are_guarded(self):
        for name in (OLD_NAMES[0], TAIL_NAMES[0]):
            for extra in ({'sendThrough': '192.0.2.1'}, {'settings': {'domainStrategy': 'UseIP'}},
                          {'streamSettings': {'sockopt': {'mark': 255, 'interface': 'custom'}}}):
                doc = xray_patch.direct_outbound('discord-direct')
                doc['outbounds'][0].update(extra)
                target = self.put(name, doc)
                with self.subTest(name=name, extra=extra), self.assertRaisesRegex(ValueError, 'not project-owned'):
                    self.plan()
                target.unlink()
        self.put(OLD_NAMES[0], xray_patch.direct_outbound('discord-direct', 255))
        self.put(TAIL_NAMES[0], xray_patch.direct_outbound('discord-direct', 256))
        with self.assertRaisesRegex(ValueError, 'collision'):
            self.plan()

    def test_reserved_ownership_accepts_only_exact_direct_and_relay_shapes(self):
        valid = xray_patch.direct_outbound('telegram-direct', 0)
        relay = xray_patch.direct_outbound('telegram-ws', 0)['outbounds'][0]
        relay['settings'] = {'redirect': '127.0.0.1:18443'}
        valid['outbounds'].append(relay)
        target = self.put(TAIL_NAMES[2], valid)
        self.routes['telegram'] = 'ws'
        self.plan()
        invalid = []
        for value in (None, {}, {'mark': 1}, {'sockopt': None}, {'sockopt': {'mark': True}},
                      {'sockopt': {'mark': -1}}, {'sockopt': {'mark': 2147483648}}):
            doc = deepcopy(valid)
            doc['outbounds'][0]['streamSettings'] = value
            invalid.append(doc)
        for settings in ({}, {'redirect': '192.0.2.1:18443'}, {'redirect': '127.0.0.1:0'},
                         {'redirect': '127.0.0.1:65536'}, {'redirect': '127.0.0.1:invalid'},
                         {'redirect': '127.0.0.1:18443', 'extra': True}):
            doc = deepcopy(valid)
            doc['outbounds'][1]['settings'] = settings
            invalid.append(doc)
        invalid += [{'outbounds': []}, {'outbounds': valid['outbounds'] * 2},
                    {'outbounds': valid['outbounds'], 'user': True}]
        for doc in invalid:
            target.write_text(json.dumps(doc))
            with self.subTest(doc=doc), self.assertRaisesRegex(ValueError, 'not project-owned'):
                self.plan()

    def test_equal_collision_migrates_and_failed_candidate_never_deletes_old(self):
        old = self.put(OLD_NAMES[0], xray_patch.direct_outbound('discord-direct'))
        new = self.put(TAIL_NAMES[0], xray_patch.direct_outbound('discord-direct'))
        before = (old.read_bytes(), new.read_bytes())
        plan, rescue = self.plan(), self.capture()
        stack, runner = self.checker()
        runner.return_value.returncode = 1
        with stack, lock.ProjectLock(self.paths.lock_dir):
            tx = transaction.Transaction(self.ctx)
            tx.arm(lambda: apply_files.restore_files(self.ctx, plan, rescue))
            with self.assertRaises(RuntimeError):
                apply_files.publish(tx, plan, rescue)
        self.assertEqual((old.read_bytes(), new.read_bytes()), before)
        self.assertIsNone(next(c.after for c in plan.changes if c.logical.endswith(OLD_NAMES[0])))

    def test_full_snapshot_restores_migrated_names_and_keeps_current_vpn_file(self):
        old = self.put(OLD_NAMES[0], xray_patch.direct_outbound('discord-direct'))
        original = old.read_bytes()
        plan, rescue = self.plan(), self.capture()
        stack, _runner = self.checker()
        with stack, lock.ProjectLock(self.paths.lock_dir):
            tx = transaction.Transaction(self.ctx)
            tx.arm(lambda: None)
            apply_files.publish(tx, plan, rescue)
            protected = self.put('04_outbounds.json', {'outbounds': [{'tag': 'new-vpn', 'protocol': 'vless'}]})
            protected_bytes = protected.read_bytes()
            snapshot_store.restore_files(self.paths, rescue, current_xkeen_version='2.1.1')
        self.assertEqual(old.read_bytes(), original)
        self.assertEqual(old.stat().st_mode & 0o777, 0o640)
        self.assertFalse(any((old.parent / name).exists() for name in TAIL_NAMES))
        self.assertEqual(protected.read_bytes(), protected_bytes)

    def test_configured_dscp_force_tags_keep_sniffing_and_vpn_path(self):
        for base in ('force-proxy', 'custom-force'):
            init = Path(self.paths.xkeen_init)
            init.parent.mkdir(parents=True, exist_ok=True)
            init.write_text(f'dscp_force_proxy_tag="{base}"\n')
            special = [{'tag': base + suffix, 'port': 2399 + i,
                        'settings': {'followRedirect': True, 'network': 'tcp,udp'},
                        'sniffing': {'enabled': False, 'metadataOnly': True}}
                       for i, suffix in enumerate(('', '-redirect', '-tproxy'))]
            ordinary = {'tag': 'redirect', 'port': 1191,
                        'settings': {'followRedirect': True, 'network': 'tcp'}}
            self.put('01_inbounds.json', {'inbounds': [ordinary, *special]})
            force_rule = {'inboundTag': [row['tag'] for row in special], 'outboundTag': 'vpn'}
            self.put('05_routing.json', {'routing': {'rules': [force_rule, {'outboundTag': 'direct'}]}})
            result = prospective(self.plan())
            with self.subTest(base=base):
                self.assertEqual(result['01_inbounds.json']['inbounds'][1:], special)
                rows = result['05_routing.json']['routing']['rules']
                self.assertEqual(rows[-2:], [force_rule, {'outboundTag': 'direct'}])
                self.assertTrue(all(row['inboundTag'] == ['redirect'] for row in rows[:-2]))

    def test_special_service_selectors_and_foreign_owned_tags_are_preserved(self):
        special = [{'inboundTag': [tag], 'outboundTag': 'vpn',
                    'domain': ['ext:geosite_v2fly.dat:youtube']}
                   for tag in ('force-proxy', 'dns-main-xkeen', 'tor-socks-in')]
        self.put('05_routing.json', {'routing': {'rules': special + [{'outboundTag': 'direct'}]}})
        rows = prospective(self.plan())['05_routing.json']['routing']['rules']
        self.assertEqual(rows[-4:], special + [{'outboundTag': 'direct'}])
        foreign = self.put('02_custom.json', {'outbounds': [{'tag': 'discord-direct',
                                                           'protocol': 'freedom', 'sendThrough': '192.0.2.1'}]})
        original = foreign.read_bytes()
        with self.assertRaisesRegex(ValueError, 'tag.*outside'):
            self.plan()
        self.assertEqual(foreign.read_bytes(), original)

    def test_special_scalar_and_comma_scope_preserves_raw_rules(self):
        init = Path(self.paths.xkeen_init)
        init.parent.mkdir(parents=True, exist_ok=True)
        init.write_text('dscp_force_proxy_tag="custom-force"\n')
        tags = ('force-proxy', 'custom-force', 'custom-force-redirect', 'custom-force-tproxy',
                'dns-main-xkeen', 'tor-socks-in')
        for encoded in (lambda tag: tag, lambda tag: 'transparent-custom,' + tag,
                        lambda tag: ['transparent-custom', tag]):
            special = [{'inboundTag': encoded(tag), 'outboundTag': 'vpn',
                        'domain': ['ext:custom.dat:youtube-special']}
                       for tag in tags]
            terminal = {'outboundTag': 'direct'}
            self.put('05_routing.json', {'routing': {'rules': [*special, terminal]}})
            with self.subTest(encoded=special[0]['inboundTag']):
                rows = prospective(self.plan())['05_routing.json']['routing']['rules']
                self.assertEqual(rows[-len(special)-1:], [*special, terminal])
                self.assertTrue(all('ext:custom.dat:youtube-special' not in row.get('domain', [])
                                    for row in rows[:-len(special)-1]))

    def test_ordinary_scalar_and_comma_scope_still_replaces_service_rules(self):
        for scope in ('transparent-custom', 'transparent-custom,redirect,tproxy'):
            original = {'routing': {'rules': [{'inboundTag': scope, 'outboundTag': 'vpn',
                         'domain': ['ext:custom.dat:youtube-ordinary']},
                         {'inboundTag': scope, 'outboundTag': 'vpn', 'network': 'udp',
                          'port': '3478-3481,5349,19294-19344,50000-50100'}, {'outboundTag': 'direct'}]}}
            kwargs = dict(inbound_tags=['transparent-custom'], routes=self.routes, proxy_outbound='vpn')
            result = xray_patch.patch_routing(original, **kwargs)
            with self.subTest(scope=scope):
                self.assertEqual(len(result['routing']['rules']), 4)
                self.assertIn('ext:custom.dat:youtube-ordinary', result['routing']['rules'][2]['domain'])
                self.assertEqual(result['routing']['rules'][2]['outboundTag'], 'youtube-direct')
                self.assertEqual(result['routing']['rules'][-1], {'outboundTag': 'direct'})

    def test_scope_stringlist_does_not_trim_or_split_array_elements(self):
        for scope in (['redirect,tproxy'], 'transparent-custom, tproxy'):
            row = {'inboundTag': scope, 'outboundTag': 'vpn', 'domain': ['ext:custom.dat:youtube-scoped']}
            kwargs = dict(inbound_tags=['transparent-custom'], routes=self.routes, proxy_outbound='vpn')
            result = xray_patch.patch_routing({'routing': {'rules': [row]}}, **kwargs)
            with self.subTest(scope=scope):
                self.assertEqual(result['routing']['rules'][-1], row)
                self.assertNotIn('ext:custom.dat:youtube-scoped', result['routing']['rules'][2]['domain'])

    def test_named_manual_rules_preserve_selectors_without_expanding_managed_domains(self):
        manual = [
            {'ruleTag': 'user-direct-youtube', 'outboundTag': 'direct',
             'domain': ['ext:custom.dat:youtube-manual'], 'ip': ['192.0.2.0/24']},
            {'ruleTag': 'user-vpn-discord', 'outboundTag': 'vpn',
             'domain': ['ext:custom.dat:discord-manual'], 'ip': ['ext:custom.dat:discord-private']},
            {'ruleTag': 'user-block', 'outboundTag': 'block',
             'domain': ['ext:custom.dat:youtube@ads']},
            {'network': 'tcp,udp', 'outboundTag': 'direct'}]
        owned = [{'ruleTag': 'kdn-telegram-old', 'outboundTag': 'obsolete', 'domain': ['old.example']},
                 {'ruleTag': 'kdn-discord-voice-vless', 'outboundTag': 'obsolete'}]
        source = {'routing': {'rules': [manual[0], owned[0], manual[1], owned[1], *manual[2:]]}}
        kwargs = dict(inbound_tags=['transparent-custom'], routes=self.routes, proxy_outbound='vpn',
                      block_tags=['block'])
        result = xray_patch.patch_routing(source, **kwargs)
        rows = result['routing']['rules']
        front_blocks, remaining = [manual[2]], [manual[0], manual[1], manual[3]]
        self.assertEqual(rows[:len(front_blocks)], front_blocks)
        self.assertEqual(rows[-len(remaining):], remaining)
        managed = rows[len(front_blocks):-len(remaining)]
        self.assertTrue(all(not value.startswith('ext:custom.dat:')
                            for row in managed for value in row.get('domain', [])))
        self.assertFalse(any(row.get('outboundTag') == 'obsolete' for row in result['routing']['rules']))
        self.assertEqual(xray_patch.patch_routing(result, **kwargs), result)

    def test_named_ad_block_precedes_overlapping_youtube_without_promoting_other_named_rules(self):
        block = {'ruleTag': 'manual-youtube-ads', 'type': 'field', 'outboundTag': 'block',
                 'domain': ['ext:geosite_v2fly.dat:youtube@ads', 'ext:custom.dat:youtube-block-only'],
                 'inboundTag': ['transparent-custom']}
        remaining = [
            {'ruleTag': 'manual-direct-ads', 'outboundTag': 'direct',
             'domain': ['ext:custom.dat:youtube@ads']},
            {'ruleTag': 'manual-vpn-ads', 'outboundTag': 'vpn',
             'domain': ['ext:custom.dat:discord@ads']},
            {'ruleTag': 'manual-block-plain', 'outboundTag': 'block',
             'domain': ['ext:custom.dat:youtube-plain']},
            {'outboundTag': 'direct'}]
        source = {'routing': {'rules': [remaining[0], block, *remaining[1:]]}}
        kwargs = dict(inbound_tags=['transparent-custom'], routes=self.routes,
                      proxy_outbound='vpn', block_tags=['block'])
        patched = xray_patch.patch_routing(source, **kwargs)
        rows = patched['routing']['rules']
        self.assertEqual(rows[0], block, 'the attributed subset must win before its managed YouTube superset')
        youtube = next(i for i, row in enumerate(rows) if row.get('outboundTag') == 'youtube-direct')
        self.assertLess(rows.index(block), youtube)
        self.assertIn('ext:geosite_v2fly.dat:youtube', rows[youtube]['domain'])
        self.assertNotIn('ext:custom.dat:youtube-block-only', rows[youtube]['domain'])
        self.assertEqual(rows[-len(remaining):], remaining)
        self.assertEqual(xray_patch.patch_routing(patched, **kwargs), patched)
        self.assertEqual(source['routing']['rules'], [remaining[0], block, *remaining[1:]])

    def test_init_change_invalidates_prepared_plan(self):
        init = Path(self.paths.xkeen_init)
        init.parent.mkdir(parents=True, exist_ok=True)
        init.write_bytes(b'dscp_force_proxy_tag="custom"\n')
        plan = self.plan()
        init.write_bytes(b'dscp_force_proxy_tag="changed"\n')
        with self.assertRaisesRegex(ValueError, 'dependency changed'):
            apply_files._validate_plan(self.ctx, plan)

    def test_migrate_each_old_file_and_remove_unused_owned_outbounds(self):
        for old_name, service in zip(OLD_NAMES, ('discord', 'youtube', 'telegram'), strict=True):
            self.put(old_name, xray_patch.direct_outbound(service + '-direct'))
        self.routes = dict(discord_tcp='vless', discord_voice='vless', youtube='vless', telegram='vless')
        plan = self.plan()
        result = prospective(plan)
        self.assertFalse(set(OLD_NAMES + TAIL_NAMES) & set(result))
        self.assertEqual({Path(c.logical).name for c in plan.changes if c.after is None}, set(OLD_NAMES))

    def test_migration_at_corpus_budget_allows_bounded_port_and_feed_changes(self):
        for old_name, service in zip(OLD_NAMES, ('discord', 'youtube', 'telegram'), strict=True):
            self.put(old_name, xray_patch.direct_outbound(service + '-direct'))
        self.routes['telegram'] = 'direct'
        ports = Path(self.paths.xkeen_port_proxying)
        ports.parent.mkdir(parents=True, exist_ok=True)
        ports.write_bytes(b'443\n')
        with mock.patch.object(apply_files, 'MAX_FILES', 6):
            plan, _warnings = apply_dependencies.prepare_files(self.ctx, self.plan(), telegram='direct')
            self.assertEqual(len(plan.corpus), 6)
            self.assertEqual(len(prospective(plan)), 6)
            apply_files._validate_plan(self.ctx, plan)

    def test_terminal_direct_dns_socks_and_remaining_policy_for_all_routes(self):
        self.put('01_inbounds.json', {'inbounds': [
            {'tag': 'redirect', 'settings': {'followRedirect': True, 'network': 'tcp'}},
            {'tag': 'tproxy', 'settings': {'followRedirect': True, 'network': 'udp'}},
            {'tag': 'dns-main-xkeen', 'protocol': 'dokodemo-door', 'settings': {'network': 'tcp,udp'}},
            {'tag': 'tor-socks-in', 'protocol': 'socks'}]})
        remaining = [
            {'inboundTag': ['dns-main-xkeen'], 'outboundTag': 'vpn'},
            {'domain': ['domain:forced.example'], 'outboundTag': 'vpn'},
            {'inboundTag': ['tor-socks-in'], 'outboundTag': 'vpn'},
            {'ip': ['geoip:private', 'geoip:ru'], 'outboundTag': 'direct'},
            {'domain': ['domain:manual.example'], 'outboundTag': 'direct'},
            {'domain': ['domain:blocked.example'], 'outboundTag': 'block'},
            {'domain': ['domain:youtube.com', 'geosite:cloudflare', 'geosite:google'], 'outboundTag': 'vpn'},
            {'ip': ['geoip:cloudflare', 'geoip:google'], 'outboundTag': 'vpn'},
            {'protocol': ['bittorrent'], 'outboundTag': 'direct'},
            {'network': 'tcp,udp', 'outboundTag': 'direct'}]
        source = {'routing': {'rules': deepcopy(remaining)}}
        source['routing']['rules'][1:1] = [
            {'outboundTag': 'discord-direct', 'domain': ['ext:geosite_v2fly.dat:discord']},
            {'outboundTag': 'youtube-direct', 'domain': ['ext:zkeen.dat:youtube']},
            {'ruleTag': 'kdn-telegram-domain', 'outboundTag': 'telegram-direct',
             'domain': ['ext:geosite_v2fly.dat:telegram']}]
        self.put('05_routing.json', source)
        before = self.routing.read_bytes()
        protected = (self.routing.parent / '04_outbounds.json').read_bytes()
        for tcp, voice, youtube, telegram in product(*([('direct', 'zapret', 'vless')] * 3),
                                                    ('direct', 'vless', 'ws', 'unmanaged')):
            self.routes = dict(discord_tcp=tcp, discord_voice=voice, youtube=youtube, telegram=telegram)
            plan = self.plan()
            rows = prospective(plan)['05_routing.json']['routing']['rules']
            with self.subTest(routes=self.routes):
                self.assertEqual(rows[-len(remaining):], remaining)
                self.assertTrue(all(row['inboundTag'] == ['redirect', 'tproxy']
                                    for row in rows[:-len(remaining)]))
                self.assertEqual(rows[0]['outboundTag'], 'vpn' if tcp == 'vless' else 'discord-direct')
                self.assertEqual(rows[1]['outboundTag'], 'vpn' if voice == 'vless' else 'discord-direct')
                self.assertEqual(rows[2]['outboundTag'], 'vpn' if youtube == 'vless' else 'youtube-direct')
                self.assertFalse(any(c.logical.endswith('/04_outbounds.json') for c in plan.changes))
        self.assertEqual(self.routing.read_bytes(), before)
        self.assertEqual((self.routing.parent / '04_outbounds.json').read_bytes(), protected)


class EffectivePortsContractTests(unittest.TestCase):
    def test_inline_comma_ranges_bounds_and_normalization(self):
        self.assertEqual(confvalues.active_ports('443 # HTTPS\n80, 5222\n65535-50000\n0,65536,bad\n'),
                         '443,80,5222,50000:65535')
        self.assertEqual(confvalues.active_ports(' 0 0 8 0, 90 : 80\n'), '80,80:90')
        self.assertEqual(confvalues.active_ports('# unrestricted\n\n'), '')

    def test_restricted_inline_and_comma_receive_managed_ports_without_editing_user_bytes(self):
        for raw in (b'443 # HTTPS\r\n', b'80,443\n', b'443 # HTTPS'):
            rendered, warnings = apply_dependencies.render_ports(raw, b'590-600, 1400 # calls\n', telegram='vless')
            with self.subTest(raw=raw):
                self.assertTrue(rendered.startswith(raw))
                self.assertIn(b'50000:50100\n', rendered)
                self.assertIn(b'5222\n', rendered)
                self.assertNotIn(b'1400\n', rendered)
                self.assertNotIn(b'590:600\n', rendered)
                self.assertEqual(len(warnings), 2)
                self.assertEqual(apply_dependencies.render_ports(rendered, b'590-600,1400 # calls\n',
                                                               telegram='vless')[0], rendered)

    def test_user_trailing_blank_bytes_survive_port_render(self):
        original = b'# user\r\n443 # HTTPS\r\n\r\n\r\n'
        rendered, _warnings = apply_dependencies.render_ports(original, telegram='direct')
        self.assertTrue(rendered.startswith(original))
        self.assertEqual(apply_dependencies.render_ports(rendered, telegram='direct')[0], rendered)
