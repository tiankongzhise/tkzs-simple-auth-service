package m2m

import "testing"

func TestSignSortsParamsAndUsesLowerHexHMAC(t *testing.T) {
	params := map[string]string{"z": "last", "a": "first"}

	sign := Sign("secret", "1710000000", params)

	if sign != "af39dc862c22b12a716b8b587c62adac9bf26159c8ed1879ba150a95e42f670f" {
		t.Fatalf("sign = %q", sign)
	}
	if !EqualSign(sign, sign) {
		t.Fatal("EqualSign() = false")
	}
}
