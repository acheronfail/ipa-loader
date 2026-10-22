// Recovered arithmetic retained as source; synthetic regression vectors cover this implementation.
package adimath

// OTPPrekeyState contains the six observed accumulator words.
type OTPPrekeyState [6]uint32

func otpPrekeyStep(state OTPPrekeyState, input byte, position uint32) OTPPrekeyState {
	v0 := uint32(input) & uint32(0xff)
	v1 := v0 ^ uint32(0xfffffefe)
	v2 := v0 << uint32(0x1)
	v3 := v2 & uint32(0x1fc)
	v4 := v3 + v1
	v5 := v4 * uint32(0x3b868e46)
	v6 := v5 + uint32(0x3d9b628c)
	v7 := v6 & uint32(0x37f085ec)
	v9 := uint32(0x0) - v7
	v10 := v4 * uint32(0x1dc34723)
	v11 := v10 + v9
	v12 := v11 + uint32(0x1ac5f43c)
	v13 := state[1] ^ v12
	v14 := v13 ^ uint32(0x43976e8f)
	v15 := (uint32(0x780fe43a) + position) + uint32(0x87f01bc6)
	v16 := v14 + v15
	v17 := v16 ^ uint32(0x6baddc5f)
	v18 := v16 << uint32(0x1)
	v19 := uint32(0xd75bb8be) & v18
	v20 := v19 + v17
	v21 := v20 + uint32(0x945223a1)
	v22 := v21 >> uint32(0x10)
	v23 := v22 ^ uint32(0x6dd9f67a)
	v24 := v22 << uint32(0x1)
	v25 := uint32(0x1ecf4) & v24
	v26 := v23 + v20
	v27 := v26 + v25
	v28 := v27 + uint32(0x26782d27)
	v29 := v28 >> uint32(0x8)
	v30 := v29 ^ uint32(0xe57edbdb)
	v31 := v27 - v30
	v32 := v31 + uint32(0xc78af7e)
	v33 := v29 << uint32(0x1)
	v34 := uint32(0xfdb7b6) & v33
	v35 := v32 - v34
	v36 := state[5] ^ uint32(0x5ffaed24)
	v37 := v35 + uint32(0xff7e5984)
	v38 := v36 ^ v37
	v39 := v35 << uint32(0x1)
	v40 := v39 + uint32(0xbd7511f2)
	v41 := v39 + uint32(0x3bed70dc)
	v42 := v39 + uint32(0x3a65cfc6)
	v43 := v39 + uint32(0xf8de2eb0)
	v44 := v40 & uint32(0xd9d2cb68)
	v45 := v42 & uint32(0x7b18943e)
	v46 := v43 & uint32(0xe6846c10)
	v47 := v38 << uint32(0x1)
	v48 := uint32(0xedec098c) & v47
	v49 := v38 + uint32(0x76f604c6)
	v50 := v49 - v48
	v51 := v41 & uint32(0x29cb36be)
	v52 := v35 - v44
	v53 := v35 - v51
	v54 := v35 - v45
	v55 := v35 - v46
	v56 := v52 + uint32(0xcba3eead)
	v57 := v53 + uint32(0xd2dc53cd)
	v58 := v54 + uint32(0x5abf3202)
	v59 := v55 + uint32(0xefb14d60)
	v60 := v12 ^ v59
	v61 := v60 ^ uint32(0x68ba74fe)
	v62 := v61 + v15
	v63 := state[0] ^ v59
	v64 := v62 ^ uint32(0xf67edfef)
	v65 := v62 << uint32(0x1)
	v66 := uint32(0xecfdbfde) & v65
	v67 := v66 + v64
	v68 := v67 + uint32(0x9812011)
	v69 := v68 >> uint32(0x10)
	v70 := uint32(0x73bf3c7d) ^ v69
	v71 := v68 >> uint32(0xf)
	v72 := uint32(0x78fa) & v71
	v73 := v70 + v67
	v74 := v73 + v72
	v75 := v74 + uint32(0x95c1e394)
	v76 := v75 >> uint32(0x8)
	v77 := uint32(0xf5e036ff) ^ v76
	v78 := v74 - v77
	v79 := v75 >> uint32(0x7)
	v80 := uint32(0x1c06dfe) & v79
	v81 := v78 + uint32(0xb31a03f6)
	v82 := v81 - v80
	v83 := v82 + uint32(0xd8880a0c)
	v84 := v50 ^ uint32(0x76f604c6)
	v85 := v83 + uint32(0xc91)
	v86 := v84 ^ v85
	v87 := v82 << uint32(0x1)
	v88 := v87 + uint32(0x2f888c24)
	v89 := v88 & uint32(0x32627c86)
	v90 := v87 + uint32(0x2e00eb0e)
	v91 := v90 & uint32(0xce5dc776)
	v92 := state[2] ^ v56
	v93 := v87 + uint32(0x6c7949f8)
	v94 := v93 & uint32(0x736aa7b4)
	v95 := v87 + uint32(0xaaf1a8e2)
	v96 := v95 & uint32(0xb0de58f2)
	v97 := v82 - v89
	v98 := v82 - v91
	v99 := v82 - v94
	v100 := v82 - v96
	v101 := v86 << uint32(0x1)
	v102 := uint32(0xbff5da48) & v101
	v103 := v86 + uint32(0x5ffaed24)
	v104 := v103 - v102
	v105 := v97 + uint32(0x50f58455)
	v106 := v98 + uint32(0xfe2f5942)
	v107 := state[4] ^ v57
	v108 := v100 + uint32(0xade800ea)
	v109 := v92 ^ v105
	v110 := v107 ^ v106
	v111 := v109 ^ uint32(0x75d85bf7)
	v112 := state[3] ^ v58
	v113 := v99 + uint32(0x2ff1f8d6)
	v114 := v110 ^ uint32(0x73cb78e4)
	v115 := v112 ^ v113
	v116 := v115 ^ uint32(0x43919c5)
	v117 := v63 ^ v108
	v119 := v117 ^ uint32(0x2b2d1a71)
	return OTPPrekeyState{v119, v108, v111, v116, v114, v104}
}

// HashOTPPrekey32 reproduces the observed32-byte accumulator loop on normalized
// bytes, after native pointer-dependent decoding. The interpretation and
// construction of these bytes from persistent state remain separate.
func HashOTPPrekey32(input [32]byte) OTPPrekeyState {
	state := OTPPrekeyState{0xc0c8d760, 0x3c47af8a, 0xde9598de, 0x9b590996, 0xa48eeec3, 0x84435731}
	for i, b := range input {
		state = otpPrekeyStep(state, b, uint32(i))
	}
	return state
}
