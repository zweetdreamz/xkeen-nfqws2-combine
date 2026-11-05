-- Only the rawsend boundary is replaced. Stock Lua does all marker resolution,
-- reassembly range normalization, segmentation, repeat handling and fooling.
local sent = {}
rawsend_dissect = function(dis, opts)
    for _=1,tonumber(opts.repeats or 1) do
        sent[#sent+1] = deepcopy(dis)
    end
    return true
end
local name = string.match(RECIPE, '^([^:]+)')
local args = {}
for param in string.gmatch(RECIPE, ':([^:]+)') do
    local k,v = string.match(param, '^([^=]+)=(.*)$')
    args[k or param] = v or ''
end
local data = fake_default_tls
if CASE=='reasm' then
    -- Grow the TLS extension block with RFC 7685 padding, rather than move SNI
    -- or invent a marker offset. Keep the stock 680B ClientHello's SNI intact.
    local function u16(pos) return string.byte(data,pos)*256+string.byte(data,pos+1) end
    local function be16(n) return string.char(math.floor(n/256),n%256) end
    local function put(pos, n, size)
        local value = size==2 and be16(n) or string.char(math.floor(n/65536),math.floor(n/256)%256,n%256)
        data=string.sub(data,1,pos-1)..value..string.sub(data,pos+size)
    end
    local sidlen=string.byte(data,44)
    local cipherpos=45+sidlen
    local compressionpos=cipherpos+2+u16(cipherpos)
    local extpos=compressionpos+1+string.byte(data,compressionpos)
    local extra=2000-#data
    local cursor, padding=extpos+2, nil
    while cursor<#data do
        if u16(cursor)==21 then
            assert(not padding, 'duplicate stock TLS padding extension')
            padding=cursor
        end
        cursor=cursor+4+u16(cursor+2)
    end
    assert(cursor==#data+1, 'stock TLS extension block length')
    put(extpos,u16(extpos)+extra,2)
    put(4,2000-5,2)
    put(7,2000-9,3)
    if padding then
        local padlen=u16(padding+2)
        local endpad=padding+4+padlen
        put(padding+2,padlen+extra,2)
        data=string.sub(data,1,endpad-1)..string.rep('\0',extra)..string.sub(data,endpad)
    else
        data=data..be16(21)..be16(extra-4)..string.rep('\0',extra-4)
    end
    assert(#data==2000)
end
local track={lua_state={}}
local function emit(offset, length, piece)
    local d={arg=args, outgoing=true, l7payload='tls_client_hello', tcp_mss=1460,
        func_instance='test', track=track, reasm_data=data, reasm_offset=offset,
        replay=CASE=='reasm', replay_piece=piece, replay_piece_last=piece==2,
        dis={ip={ip_id=321}, tcp={th_seq=100+offset, th_ack=0,
            th_flags=TH_ACK, th_urp=0, options={}},
            payload=string.sub(data,offset+1,offset+length)}}
    assert(_G[name](nil,d)==VERDICT_DROP, 'expected stock Lua DROP')
end
if CASE=='reasm' then
    -- Two actual replay pieces, 1000B each; MSS 1460 exceeds each piece.
    emit(0,1000,1)
    emit(1000,1000,2)
else
    emit(0,#data,1)
end
for _,dis in ipairs(sent) do print('PACKET='..dis.tcp.th_seq..','..#dis.payload) end
print('FLOWSEAL_EMISSION_OK')
