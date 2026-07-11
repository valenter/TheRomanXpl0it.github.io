---
title: DEF CON CTF Qualifier 2026 - Birdhouse
date: 2026-06-02
lastmod: 2026-06-02T18:13:30+02:00
aliases: ["/posts/2026/06/defconquals-2026-birdhouse/"]
categories:
  - writeup
  - defconquals26
tags:
  - reverse
  - gdb
  - ida
  - hard
authors:
  - Valenter
  - ice cream
---
# Birdhouse

## Initial Analysis

Loading the ROM into an emulator (ares) showed a fairly standard N64 game (like Minecraft). We first tried attaching to the integrated gdb server for debugging purposes, but that didn't work too well, so we turned to inspecting the ROM structure directly.

![screenshot](/defconquals2026/birdhouse/screenshot.png)

Examining the binary revealed the presence of a DragonFS filesystem, identified by the `TOC0` signature. DragonFS is commonly used by libdragon projects to package assets and executable components into the ROM image.

Within the filesystem entries was a file named `code`, which contained an ELF executable.

![TOC0](/defconquals2026/birdhouse/TOC0.png)
## Extracting the Embedded ELF

Initially, we tried to extract it with the help of the libdragon toolchain, but it did not work, so we resorted to manually carving out the ELF inside the `code` entry from DragonFS with `dd` .

This landed us with a big-endian MIPS ELF which contained a compressed `PT_LOAD` segment marked with the libdragon-specific compression flag (`0x1000`). Static analysis of the loading process indicated that the segment would be decompressed at runtime before execution, which led us to run the game in ares again and dump the decompressed memory from the runtime address range directly through GDB.

From `readelf`:

```
Program Headers:
  Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align
  LOOS+0x4e36341 0x000094 0x00000000 0x00000000 0x001c0 0x00000 R E 0x8
  LOAD           0x000258 0x800001a0 0x80000000 0x00014 0x00188 R E 0x1000
  LOAD           0x000270 0x80026ca0 0x80000400 0x42847 0x7f218 RWE 0x1000
```

So we knew there was compressed data starting at offset 0x000270.

Physical memory in MIPS can be mapped onto 2 virtual memory segments, `KSEG0` (cached) and `KSEG1` (uncached), we used the latter to extract the decompressed binary and then loaded the file back into IDA.
## Solving

Given that the challenge presents itself as a voxel game, and asks us to place blocks in a certain way in order to retrieve the flag, we realized the coordinates of the blocks and their IDs had to be checked somewhere in the binary, so we went scouring for a hidden table.

After a lot of blind static searching, we decided to compare dumped memory bins before and after placing blocks, and noticed, with some AI-assisted pattern matching, that several bytes in the region at address `0x695d8` in RDRAM were changing consistently with the types of blocks that were being placed.

![house](/defconquals2026/birdhouse/house.png)

This led us to find the function at `0x80061CE4`, which is the actual checker for the solve.

The function reads from a big table of 16-bit pairs, where the first value is a target and the second value is a reference.
The target is used as 3D coordinates inside the game, and the reference is a voxel-grid offset that points to an in-game palette whose contents are block IDs.

- grass: 0x3656
- dirt: 0x2852
- stone: 0x2c49
- wood: 0x32c7
- leaves: 0x398d
- sand: 0x2a53
- brick: 0x386c

Given these pairs, the code makes a check that resembles the graph coloring problem, where the block to insert inside the target must be inside the references, must be unique, and must be in the correct slot (the slot is determined by the target offset in the above list).
So we can easily bruteforce all 8 candidates for each target group.

Finally we can compute the key to decrypt the flag by copying the code directly from IDA inside python and making the necessary adjustments to make it work

### Script
```python
import struct

def xor(a, b):
	return [x ^ y for x, y in zip(a, b)]

enc_flag = [
	0xFD, 0x36, 0x4D, 0x4A, 0x68, 0x54, 0x33, 0xAC, 0xB6, 0xB5, 
	0x51, 0x84, 0x39, 0x27, 0x40, 0xDB, 0x84, 0xC9, 0xC5, 0x44, 
	0xD4, 0x3F, 0x7E, 0x56, 0xBA, 0x58, 0x35, 0x7D, 0x4F, 0xA4, 
	0xC1, 0x1F,
]

with open('table_entries.bin' , 'rb') as f: # IDA dumped pair entries (starting from addr `0x80057CA8` with a length of 0x1D28 pairs)
	data = f.read()



hidden_table = struct.unpack(f'>{(len(data) // 2)}H', data)

pairs = [hidden_table[i:i+2] for i in range(0, len(hidden_table), 2)]
groups = {}
for target, ref in pairs:
	if target not in groups:
		groups[target] = []
	groups[target].append(ref)


blocks = {
	'grass': 0x3656,
	'dirt': 0x2852,
	'stone': 0x2c49,
	'wood': 0x32c7,
	'leaves': 0x398d,
	'sand': 0x2a53,
	'brick': 0x386c
}
palette = {v: k for k, v in blocks.items()}

palette_idx = {
	0: 'grass',
	1: 'dirt',
	2: 'stone',
	3: 'wood',
	4: 'leaves',
	5: 'sand',
	6: 'brick',
}
palette_idx_inv = {v: k for k, v in palette_idx.items()}



final_candidates = []
for group_target, group_refs in groups.items():
	candidate = None

	for c in range(1, 8): # brute grid target
		
		for slot in range(0, 8):
			ref = group_refs[slot]
			r = palette[ref]
			if slot == c:
				continue
			# if r == 0:
			# 	break
			if palette_idx_inv[r]+1 == c:
				break

		else:
			if candidate is not None:
				print(f"multiple candidates {candidate} and {c}")
				exit(1)
			candidate = c
			# break

	if candidate is None:
		print('no candidate found')
		exit(1)
	
	# print(f"candidate {candidate} {palette_idx[candidate-1]}")
	final_candidates.append(candidate)



state = 0x6d2b79f5
for i in range(len(final_candidates)):
    c = final_candidates[i]
    state ^= (158 * i + c) & 0xffffffff
    state ^= (state << 13) & 0xffffffff
    state ^= (state >> 17) & 0xffffffff
    state ^= (state << 5) & 0xffffffff


key = [None] * 32
for j in range(32):
    state = (state + 0x9e3779b9) & 0xffffffff
    state ^= (state << 13) & 0xffffffff
    state ^= (state >> 17) & 0xffffffff
    state ^= (state << 5) & 0xffffffff
    key[j] = (state >> 8) & 0xff


print(bytes(xor(enc_flag, key)))
```

### Flag
`bbb{r5p_gr4ph_c0l0r_0n_n64}`
