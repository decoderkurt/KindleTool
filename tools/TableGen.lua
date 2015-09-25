#!/usr/bin/env luajit
--[[
    Table generator for Amazon byte mangle, de-mangle algorithm.
    Output is to stdout, the result is the body of kindle_tool.h

    Each bit-wise operator used was tested in the commented examples.
    In lua the only data-type is double and the bitop package uses
    the 53 bit integer field of double as a 32 bit array.
--]]

local bit = require("bit")
local band, bor, bxor = bit.band, bit.bor, bit.bxor
local lshift, rshift, tohex = bit.lshift, bit.rshift, bit.tohex

function printx (x)
  print("0x"..tohex(x))
end

function print2x (x) return "0x"..tohex(x, 2) end

function col4 (w, x, y, z)
  return string.format('%s\t%s\t\t%s\t%s\n',
         print2x(w), print2x(x), print2x(y), print2x(z)) end

-- printx(bit.band(0x12345678, 0x0f))        --> 0x00000008
-- printx(bit.band(0x12345678, 0xf0))        --> 0x00000070

-- printx(lshift(band(0x12345678, 0x0f), 4))    --> 0x00000080
-- printx(rshift(band(0x12345678, 0xf0), 4))    --> 0x00000007

-- printx(bor(rshift(band(0x12345678, 0xf0), 4), lshift(band(0x12345678, 0x0f), 4)))
--> 0x00000087

-- printx(bxor(bor(rshift(band(0x12345678, 0xf0), 4), lshift(band(0x12345678, 0x0f), 4)), 0x7A))
--> 0x000000fd

-- swap nibbles in a byte
function swap_nibbles (x)
  return bor(rshift(band(x, 0xF0), 4), lshift(band(x, 0x0F), 4)) end

-- obscure nibbles in a byte
function obsc_nibbles (x, y) return bxor(swap_nibbles(x), y) end

-- Input plain byte, return obscure byte
function md_nibbles (x) return obsc_nibbles(x, 0x7A) end

-- Input obscure byte, return plain byte
function dm_nibbles (x) return obsc_nibbles(x, 0xA7) end

md_tbl = { 0, 0, 0, 0, 0, 0, 0, 0 }  -- start with eight elements, let double to 256
dm_tbl = { 0, 0, 0, 0, 0, 0, 0, 0 }  -- table only has to be re-allocated 5 times.

for i = 0, 255, 1 do
   local md = md_nibbles(i)
   md_tbl[i] = md
   dm_tbl[md] = i -- a.k.a: dm_nibbles(md_nibbles(i))
end

local hdl = io.output() -- stdout

--[[
print('plain', 'obfuscated', 'dm-tbl', 'dm-func')
for i = 0, 255, 1 do
  local md = md_tbl[i]
  hdl:write(col4(i, md, dm_tbl[md], dm_nibbles(md)))
end
]]

-- Header, plain to garbled
hd_ptog = '/*  index by plain, result garbled */\nstatic const uint8_t ptog[] = {\n'
-- Header, garbled to plain
hd_gtop = '\n/*  index by garbled, result plain */\nstatic const uint8_t gtop[] = {\n'

-- lines ('C' doesn't like trailing commas)
lns = '\t%4s, %4s, %4s, %4s, %4s, %4s, %4s, %4s,\n'
lnl = '\t%4s, %4s, %4s, %4s, %4s, %4s, %4s, %4s\n};\n'

hdl:write(hd_ptog)
for i = 0, 247, 8 do
    hdl:write(string.format(lns,
        print2x(md_tbl[ i ]), print2x(md_tbl[i+1]), print2x(md_tbl[i+2]), print2x(md_tbl[i+3]),
        print2x(md_tbl[i+4]), print2x(md_tbl[i+5]), print2x(md_tbl[i+6]), print2x(md_tbl[i+7])
    ))
end
hdl:write(string.format(lnl,
    print2x(md_tbl[248]), print2x(md_tbl[249]), print2x(md_tbl[250]), print2x(md_tbl[251]),
    print2x(md_tbl[252]), print2x(md_tbl[253]), print2x(md_tbl[254]), print2x(md_tbl[255])
))

hdl:write(hd_gtop)
for i = 0, 247, 8 do
    hdl:write(string.format(lns,
        print2x(dm_tbl[ i ]), print2x(dm_tbl[i+1]), print2x(dm_tbl[i+2]), print2x(dm_tbl[i+3]),
        print2x(dm_tbl[i+4]), print2x(dm_tbl[i+5]), print2x(dm_tbl[i+6]), print2x(dm_tbl[i+7])
    ))
end
hdl:write(string.format(lnl,
    print2x(dm_tbl[248]), print2x(dm_tbl[249]), print2x(dm_tbl[250]), print2x(dm_tbl[251]),
    print2x(dm_tbl[252]), print2x(dm_tbl[253]), print2x(dm_tbl[254]), print2x(dm_tbl[255])
))

hdl:flush()
hdl:close()
