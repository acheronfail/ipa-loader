package adimath

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"testing"
)

type fixture struct {
	Seed struct {
		SeedHex string `json:"seed_hex"`
		Words   string `json:"encoded_words_le_hex"`
	} `json:"seed"`
	Transitions []struct {
		Name      string `json:"name"`
		Before    string `json:"before_le_hex"`
		After     string `json:"after_le_hex"`
		Index     uint32 `json:"index"`
		NextIndex uint32 `json:"next_index"`
		OutputHex string `json:"output_hex"`
	} `json:"transitions"`
}

func nativeFixture(t *testing.T) fixture {
	t.Helper()
	b, err := os.ReadFile("testdata/native_mt_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var out fixture
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func word(t *testing.T, s string) uint32 {
	t.Helper()
	n, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		t.Fatal(err)
	}
	return uint32(n)
}

func words(t *testing.T, s string) (out [MTWords]uint32) {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != MTWords*4 {
		t.Fatalf("state has %d bytes", len(b))
	}
	for i := range out {
		out[i] = binary.LittleEndian.Uint32(b[4*i:])
	}
	return out
}

func assertState(t *testing.T, got, want [MTWords]uint32) {
	t.Helper()
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("encoded state[%d]=%08x, native=%08x", i, got[i], want[i])
		}
	}
}

func TestNativeSeedInitialization(t *testing.T) {
	v := nativeFixture(t).Seed
	got := SeedEncodedMT(word(t, v.SeedHex), 624)
	assertState(t, got.Words, words(t, v.Words))
	if got.Index != 624 {
		t.Fatal("constructor lost supplied index")
	}
}

func TestNativeFullStateTransitions(t *testing.T) {
	v := nativeFixture(t)
	for _, tc := range v.Transitions {
		t.Run(tc.Name, func(t *testing.T) {
			got := EncodedMT{Words: words(t, tc.Before), Index: tc.Index}
			output := got.Next()
			assertState(t, got.Words, words(t, tc.After))
			if output != word(t, tc.OutputHex) || got.Index != tc.NextIndex {
				t.Fatalf("output=%08x index=%d, native output=%s index=%d", output, got.Index, tc.OutputHex, tc.NextIndex)
			}
		})
	}
}

func TestNativeConsecutiveSequence(t *testing.T) {
	v := nativeFixture(t)
	state := EncodedMT{Words: words(t, v.Transitions[0].Before), Index: v.Transitions[0].Index}
	for _, tc := range v.Transitions[:4] {
		assertState(t, state.Words, words(t, tc.Before))
		if state.Index != tc.Index {
			t.Fatalf("before %s: index=%d native=%d", tc.Name, state.Index, tc.Index)
		}
		if output := state.Next(); output != word(t, tc.OutputHex) {
			t.Fatalf("%s output=%08x native=%s", tc.Name, output, tc.OutputHex)
		}
		assertState(t, state.Words, words(t, tc.After))
	}
}
