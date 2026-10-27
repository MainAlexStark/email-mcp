package tools

import (
	"errors"
	"strings"
	"testing"
)

func TestDefaultSafetyIsReadOnly(t *testing.T) {
	s := DefaultSafety()
	for _, a := range []Access{AccessDrafts, AccessWrite, AccessSend} {
		var denied ErrAccessDenied
		if err := s.Check("x", a); !errors.As(err, &denied) {
			t.Errorf("право %s открыто по умолчанию", a)
		}
	}
	if err := s.Check("x", AccessRead); err != nil {
		t.Errorf("чтение должно быть открыто: %v", err)
	}
	if s.Mode() != "чтение" {
		t.Errorf("режим по умолчанию: %q", s.Mode())
	}
}

func TestRecipientsThreshold(t *testing.T) {
	s := DefaultSafety()
	s.MaxRecipients = 3
	if err := s.CheckRecipients(3, false); err != nil {
		t.Error("ровно порог должен проходить")
	}
	if err := s.CheckRecipients(4, false); err == nil || !strings.Contains(err.Error(), "confirm_many_recipients") {
		t.Errorf("сверх порога без подтверждения: %v", err)
	}
	if err := s.CheckRecipients(40, true); err != nil {
		t.Error("с подтверждением порог не действует")
	}
}

func TestBatchSize(t *testing.T) {
	s := DefaultSafety()
	s.MaxItemsPerWrite = 5
	if s.CheckBatchSize(5) != nil || s.CheckBatchSize(6) == nil {
		t.Error("порог пакета считается неверно")
	}
}
