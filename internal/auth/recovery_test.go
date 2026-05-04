package auth

import (
	"strings"
	"testing"
)

func TestGenerateRecoveryCodesShape(t *testing.T) {
	t.Parallel()

	codes, err := GenerateRecoveryCodes(8)
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != 8 {
		t.Fatalf("got %d codes, want 8", len(codes))
	}
	for _, c := range codes {
		if len(c) != recoveryCodeLen {
			t.Errorf("code %q has length %d", c, len(c))
		}
		for _, r := range c {
			if !strings.ContainsRune(RecoveryCodeAlphabet, r) {
				t.Errorf("code %q contains rune outside alphabet: %q", c, r)
			}
		}
	}
}

func TestRecoveryCodesAreUnique(t *testing.T) {
	t.Parallel()

	codes, err := GenerateRecoveryCodes(50)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, c := range codes {
		if seen[c] {
			t.Fatalf("duplicate code %q (alphabet/length too small or rng broken)", c)
		}
		seen[c] = true
	}
}

func TestConsumeRecoveryCode(t *testing.T) {
	t.Parallel()

	codes := []string{"AAA", "BBB", "CCC"}
	left, ok := ConsumeRecoveryCode(codes, "BBB")
	if !ok {
		t.Fatal("expected BBB to consume")
	}
	if len(left) != 2 || left[0] != "AAA" || left[1] != "CCC" {
		t.Fatalf("got %v", left)
	}
}

func TestConsumeRecoveryCodeMissing(t *testing.T) {
	t.Parallel()

	codes := []string{"AAA"}
	_, ok := ConsumeRecoveryCode(codes, "BBB")
	if ok {
		t.Fatal("BBB should not consume")
	}
}

func TestRecoveryCodeJSONRoundTrip(t *testing.T) {
	t.Parallel()

	codes := []string{"X1", "Y2"}
	b, err := MarshalRecoveryCodes(codes)
	if err != nil {
		t.Fatal(err)
	}
	back, err := UnmarshalRecoveryCodes(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(back) != 2 || back[0] != "X1" || back[1] != "Y2" {
		t.Fatalf("got %v", back)
	}
}
