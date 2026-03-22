package models

import (
	"encoding/json"
	"testing"
)

func TestAuditDetails_Value_Nil(t *testing.T) {
	var a AuditDetails
	val, err := a.Value()
	if err != nil {
		t.Fatalf("AuditDetails.Value() unexpected error: %v", err)
	}
	if val != nil {
		t.Errorf("AuditDetails.Value() = %v, want nil", val)
	}
}

func TestAuditDetails_Value_NonNil(t *testing.T) {
	a := AuditDetails{"key": "value", "count": float64(42)}
	val, err := a.Value()
	if err != nil {
		t.Fatalf("AuditDetails.Value() unexpected error: %v", err)
	}
	bytes, ok := val.([]byte)
	if !ok {
		t.Fatalf("AuditDetails.Value() returned non-[]byte type: %T", val)
	}

	var roundTrip map[string]any
	if err := json.Unmarshal(bytes, &roundTrip); err != nil {
		t.Fatalf("AuditDetails.Value() returned invalid JSON: %v", err)
	}
	if roundTrip["key"] != "value" {
		t.Errorf("round-trip key = %v, want \"value\"", roundTrip["key"])
	}
	if roundTrip["count"] != float64(42) {
		t.Errorf("round-trip count = %v, want 42", roundTrip["count"])
	}
}

func TestAuditDetails_Scan_Nil(t *testing.T) {
	a := AuditDetails{"existing": "data"}
	if err := a.Scan(nil); err != nil {
		t.Fatalf("AuditDetails.Scan(nil) unexpected error: %v", err)
	}
	if a != nil {
		t.Errorf("AuditDetails.Scan(nil) = %v, want nil", a)
	}
}

func TestAuditDetails_Scan_ValidJSON(t *testing.T) {
	var a AuditDetails
	err := a.Scan([]byte(`{"username":"admin","ip":"127.0.0.1"}`))
	if err != nil {
		t.Fatalf("AuditDetails.Scan() unexpected error: %v", err)
	}
	if a["username"] != "admin" {
		t.Errorf("AuditDetails[\"username\"] = %v, want \"admin\"", a["username"])
	}
	if a["ip"] != "127.0.0.1" {
		t.Errorf("AuditDetails[\"ip\"] = %v, want \"127.0.0.1\"", a["ip"])
	}
}

func TestAuditDetails_Scan_InvalidJSON(t *testing.T) {
	var a AuditDetails
	err := a.Scan([]byte(`{invalid json}`))
	if err == nil {
		t.Error("AuditDetails.Scan(invalid JSON) expected error, got nil")
	}
}

func TestAuditDetails_Scan_InvalidType(t *testing.T) {
	var a AuditDetails
	err := a.Scan("not a byte slice")
	if err == nil {
		t.Error("AuditDetails.Scan(string) expected error, got nil")
	}
}

func TestAuditLog_TableName(t *testing.T) {
	a := AuditLog{}
	if got := a.TableName(); got != "audit_logs" {
		t.Errorf("AuditLog.TableName() = %v, want %v", got, "audit_logs")
	}
}
