package auth_test

import (
	"slices"
	"testing"

	"github.com/ubgo/auth"
)

func TestEffects_HeaderRecordsNameAndValue(t *testing.T) {
	var e auth.Effects
	e.Header("Set-Auth-JWT", "tok")
	list := e.List()
	if len(list) != 1 || list[0].Kind != auth.EffectHeader || list[0].Name != "Set-Auth-JWT" || list[0].Value != "tok" {
		t.Fatalf("effects = %+v", list)
	}
	if !slices.Contains(auth.EffectKindValues, auth.EffectHeader) {
		t.Fatal("EffectKindValues must list EffectHeader, so transports learn it")
	}
}
