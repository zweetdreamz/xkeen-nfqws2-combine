-- Trusted test harness, never loaded on the router. Only the lowest C sender
-- is replaced: real pinned Lua segmentation, fooling and ip_id remain intact.
local sent = {}
rawsend_dissect = function(dis, opts)
    for i=1,tonumber(opts.repeats or 1) do
        sent[#sent+1] = deepcopy(dis)
    end
    return true
end
direction_cutoff_opposite = function() end -- C flow cutoff is not under test.
replay_drop_set = function() end
local function packet(ipv6)
    return {
        arg={}, outgoing=true, l7payload='tls_client_hello', tcp_mss=1460,
        dis={ip=not ipv6 and {ip_id=321} or nil,
             ip6=ipv6 and {exthdr={}} or nil,
             tcp={th_seq=100, th_ack=0, th_flags=TH_ACK, th_urp=0, options={}},
             payload='abcdef'}
    }
end
local d = packet(false)
d.arg={blob='0x4141', repeats='2', ip_id='zero'}
fake({}, d)
d.arg={blob='0x4242', repeats='3', ip_id='zero'}
fake({}, d)
assert(#sent==5)
for i=1,5 do
    assert(sent[i].payload==(i<=2 and 'AA' or 'BB'))
    assert(sent[i].ip.ip_id==0)
end
assert(d.dis.ip.ip_id==321, 'fake must not change original packet')
sent={}
d.arg={blob='0x41414141', repeats='2', tcp_seq='10000', ip_id='zero'}
fake({}, d)
d.arg={blob='0x42424242', repeats='3', tcp_seq='10004', ip_id='zero'}
fake({}, d)
assert(#sent==5)
for i=1,5 do
    assert(sent[i].tcp.th_seq==(i<=2 and 10100 or 10104))
    assert(sent[i].payload==(i<=2 and 'AAAA' or 'BBBB'))
end
assert(d.dis.tcp.th_seq==100, 'fooling must not change original sequence')
sent={}
d.reasm_data=fake_default_tls
d.arg={blob='fake_default_tls', repeats='2', tls_mod='sni=one.example', ip_id='zero'}
fake({}, d)
d.arg={blob='fake_default_tls', repeats='1', tls_mod='sni=two.example', ip_id='zero'}
fake({}, d)
assert(#sent==3)
assert(string.find(sent[1].payload, 'one.example', 1, true))
assert(sent[1].payload==sent[2].payload)
assert(string.find(sent[3].payload, 'two.example', 1, true))
assert(not string.find(sent[3].payload, 'one.example', 1, true))
d.reasm_data=nil
sent={}
d.arg={pos='2', ip_id='zero'}
multisplit({}, d)
assert(#sent==2)
assert(sent[1].payload=='ab' and sent[2].payload=='cdef')
assert(sent[1].tcp.th_seq==100 and sent[2].tcp.th_seq==102)
assert(sent[1].ip.ip_id==0 and sent[2].ip.ip_id==0)
assert(d.dis.ip.ip_id==321)
sent={}
d=packet(true)
d.arg={blob='0x4343', ip_id='zero'}
fake({}, d)
assert(#sent==1 and sent[1].ip==nil and sent[1].ip6~=nil)
print('PACKET_EMISSION_V2_OK')
print('DEFAULTHEX='..string2hex(fake_default_tls))
