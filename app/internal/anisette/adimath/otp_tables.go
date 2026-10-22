// Recovered arithmetic retained as source; synthetic regression vectors cover this implementation.
// Native artifact SHA2569d5b557cf3faf88c34c394ab2cd7fc1a3b4acf3aed51f28cd0bc093858107c22.
package adimath

// OTPTableParams is the independently varied input boundary of the selected
// native constructor. Permute controls four byte-index permutations. OutputXOR
// supplies its eight word masks. Their full derivation from ADI state remains
// outside this recovered arithmetic primitive.
type OTPTableParams struct {
	Permute   [4]byte
	OutputXOR [8]uint32
}

// OTPTables contains the eight256-word lookup tables built by this native path.
type OTPTables [8][256]uint32

// BuildOTPTables reproduces the selected constructor with pure integer math and
// fixed numeric lookup material. It does not implement the cipher rounds or OTP.
func BuildOTPTables(params OTPTableParams) (out OTPTables) {
	for i := 0; i < 256; i++ {
		u := uint32(0x62dd5900) | uint32(i)
		v0 := u ^ uint32(0x62dd59ab)
		v1 := otpLookupMaterial[0][i]
		v2 := uint32(0x00009c21)
		v3 := (v2 & uint32(0x0000ffff)) | uint32(0x86f70000)
		v4 := uint32(0x000045c2)
		v5 := v0*v0 + v1
		v6 := (v4 & uint32(0x0000ffff)) | uint32(0xb0840000)
		v7 := uint32(0x62dd590c) + uint32(0x000000a1)
		v8 := v5 ^ v3
		v9 := uint32(0x000022e1)
		v10 := u ^ v7
		v11 := v6 & (v8 << 1)
		v12 := (v9 & uint32(0x0000ffff)) | uint32(0x58420000)
		v13 := v8 - v11
		v14 := v13 + v12
		v15 := params.OutputXOR[0]
		v18 := v14 ^ (v14 >> 2)
		v19 := v15 ^ v14
		v20 := v19 ^ (v18 >> 4)
		v21 := otpLookupMaterial[1][i]
		v22 := uint32(0x62dd590c) + uint32(0x00000006)
		v23 := uint32(0x000020f2)
		v24 := u ^ v22
		v25 := v10*v10 + v21
		v26 := (v23 & uint32(0x0000ffff)) | uint32(0x31ec0000)
		v27 := v24 ^ v25
		v28 := uint32(0x00001079)
		v29 := v26 & (v27 << 1)
		v30 := (v28 & uint32(0x0000ffff)) | uint32(0x18f60000)
		v31 := v27 - v29
		v33 := v31 + v30
		v34 := params.OutputXOR[1]
		v35 := uint32(0x62dd590c) + uint32(0x000000ed)
		v37 := u ^ v35
		v38 := v34 ^ v33
		v39 := otpLookupMaterial[2][i]
		v40 := params.OutputXOR[2]
		v41 := uint32(0x00006726)
		v42 := (v41 & uint32(0x0000ffff)) | uint32(0x462d0000)
		v43 := v37*v37 + v39
		v44 := v40 ^ v43
		v45 := uint32(0x0000b393)
		v47 := v42 & (v44 << 1)
		v48 := (v45 & uint32(0x0000ffff)) | uint32(0x23160000)
		v49 := v44 - v47
		v50 := uint32(0x0000acc5)
		v51 := v49 + v48
		v52 := (v50 & uint32(0x0000ffff)) | uint32(0x635e0000)
		v53 := uint32(0x62dd590c) + uint32(0x000000ab)
		v55 := u ^ v51
		v56 := u ^ v53
		v57 := v55 ^ v52
		v58 := otpLookupMaterial[3][i]
		v59 := params.OutputXOR[3]
		v60 := uint32(0x00007a0c)
		v61 := (v60 & uint32(0x0000ffff)) | uint32(0xb5e90000)
		v62 := v56*v56 + v58
		v63 := v59 ^ v62
		v64 := uint32(0x0000bd06)
		v66 := v61 & (v63 << 1)
		v67 := (v64 & uint32(0x0000ffff)) | uint32(0x5af40000)
		v68 := uint32(0x000073e2)
		v69 := v63 - v66
		v70 := (v68 & uint32(0x0000ffff)) | uint32(0x10840000)
		v71 := v69 + v67
		v72 := v71 ^ v70
		v74 := u ^ uint32(0x62dd590c)
		v75 := otpLookupMaterial[4][i]
		v76 := uint32(0x00005d3d)
		v77 := (v76 & uint32(0x0000ffff)) | uint32(0x28860000)
		v78 := uint32(0x0000bf6e)
		v79 := v74*v74 + v75
		v80 := (v78 & uint32(0x0000ffff)) | uint32(0x02ed0000)
		v81 := v79 ^ v77
		v82 := v80 & (v81 << 1)
		v83 := v81 + uint32(0x0176dfb7)
		v84 := uint32(0x00008de0)
		v85 := v83 - v82
		v86 := (v84 & uint32(0x0000ffff)) | uint32(0xd5860000)
		v87 := uint32(0x0000c740)
		v88 := v85 ^ uint32(0x0176dfb7)
		v89 := (v87 & uint32(0x0000ffff)) | uint32(0x14eb0000)
		v90 := v88 * v86
		v91 := v90 & v89
		v92 := uint32(0x000046f0)
		v93 := (v92 & uint32(0x0000ffff)) | uint32(0x6ac30000)
		v94 := uint32(0) - v91
		v95 := v88*v93 + v94
		v96 := uint32(0x0000e3a7)
		v97 := (v96 & uint32(0x0000ffff)) | uint32(0x0a750000)
		v98 := v95 + v97
		v99 := params.OutputXOR[4]
		v100 := v99 ^ v85
		v101 := v100 ^ v98
		v103 := uint32(0x62dd590c) + uint32(0x0000007f)
		v104 := u ^ v103
		v105 := otpLookupMaterial[5][i]
		v106 := uint32(0x00001ffe)
		v107 := (v106 & uint32(0x0000ffff)) | uint32(0xc50f0000)
		v108 := params.OutputXOR[5]
		v109 := v104*v104 + v105
		v110 := uint32(0x0000331a)
		v111 := (v110 & uint32(0x0000ffff)) | uint32(0xd8e40000)
		v112 := v107 + (v109 << 1)
		v113 := v112 & v111
		v114 := uint32(0x0000a98c)
		v115 := (v114 & uint32(0x0000ffff)) | uint32(0xcef90000)
		v116 := v109 - v113
		v117 := v116 + v115
		v119 := uint32(0x62dd590c) + uint32(0x000000c4)
		v120 := v108 ^ v117
		v121 := u ^ v119
		v122 := otpLookupMaterial[6][i]
		v123 := uint32(0x00003e06)
		v124 := uint32(0x000041ca)
		v125 := v121*v121 + v122
		v126 := v123 + (v125 << 1)
		v127 := v126 & v124
		v128 := uint32(0xffffbfe8)
		v129 := v125 - v127
		v130 := uint32(0x00007909)
		v131 := v129 + v128
		v132 := uint32(0x00004800)
		v133 := v130 & (v131 >> 1)
		v134 := uint32(0x0000a002)
		v135 := v133 ^ v132
		v136 := v134 & (v135 << 1)
		v137 := uint32(0x000056b7)
		v138 := v135 - v136
		v139 := v138 + v137
		v140 := uint32(0x00002e52)
		v141 := uint32(0x0000f6de)
		v142 := v131 ^ v139
		v143 := (v141 & uint32(0x0000ffff)) | uint32(0x00010000)
		v144 := v142 ^ v140
		v145 := v143 + uint32(0x0000036c)
		v146 := v144 & uint32(0x0000ffff)
		v147 := uint32(0x0000fd25)
		v148 := v145 & (v146 << 1)
		v149 := (v147 & uint32(0x0000ffff)) | uint32(0x73800000)
		v150 := v146 - v148
		v151 := v150 + v149
		v152 := params.OutputXOR[6] ^ v151
		v160 := uint32(0x62dd590c) + uint32(0x000000a0)
		v166 := u ^ v160
		v171 := otpLookupMaterial[7][i]
		v176 := v166*v166 + v171
		v177 := u ^ v176
		v178 := uint32(0x00000012)
		v179 := v177 ^ v178
		v180 := uint32(0x00000064)
		v181 := v180 & (v179 << 1)
		v182 := v179 - v181
		v183 := v182 + uint32(0x00000032)
		v184 := uint32(0x00000032)
		v185 := v183 ^ v184
		v186 := v185 & uint32(0x000000ff)
		v187 := uint32(0x00000144)
		v188 := v187 & (v186 << 1)
		v189 := v186 - v188
		v190 := uint32(0x0000b1a2)
		v191 := (v190 & uint32(0x0000ffff)) | uint32(0x0ad30000)
		v192 := v189 + v191
		v193 := params.OutputXOR[7]
		v197 := v193 ^ v192
		out[0][byte(i)^params.Permute[0]] = v20
		out[1][byte(i)^params.Permute[1]] = v38
		out[2][byte(i)^params.Permute[2]] = v57
		out[3][byte(i)^params.Permute[3]] = v72
		out[4][byte(i)^params.Permute[0]] = v101
		out[5][byte(i)^params.Permute[1]] = v120
		out[6][byte(i)^params.Permute[2]] = v152
		out[7][byte(i)^params.Permute[3]] = v197
	}
	return out
}
