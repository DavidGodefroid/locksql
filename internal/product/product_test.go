package product

import "testing"

// The names locksql had before lockkit: changing one would orphan
// keychain items, sockets, config files and the console account.
func TestNamesUnchanged(t *testing.T) {
	if err := P.Validate(); err != nil {
		t.Fatal(err)
	}
	if P.Name != "locksql" || P.Account != "locksql" || P.ClientsGroup != "locksql-clients" ||
		P.KeychainService != "locksql" || P.EnvPrefix != "LOCKSQL_" ||
		P.Tagline != "Your AI writes the query. You hold the key." {
		t.Fatalf("%+v", P)
	}
	if SysconfPath() != "/etc/locksql/system.toml" || Keychain.Service != "locksql" {
		t.Fatal(SysconfPath(), Keychain.Service)
	}
}
