package seccomp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"testing"
)

func exportPFCBytes(t *testing.T, filter *ScmpFilter) []byte {
	t.Helper()

	file, err := os.Create(t.TempDir() + "/pfc")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	if err := filter.ExportPFC(file); err != nil {
		t.Fatalf("ExportPFC: %v", err)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(file)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func foreignArchForTest(t *testing.T) ScmpArch {
	t.Helper()

	nativeArch, err := GetNativeArch()
	if err != nil {
		t.Fatalf("GetNativeArch: %v", err)
	}
	if nativeArch != ArchARM64 {
		return ArchARM64
	}
	return ArchAMD64
}

func TestFilterExportImportRoundTrip(t *testing.T) {
	nativeArch, err := GetNativeArch()
	if err != nil {
		t.Fatalf("GetNativeArch: %v", err)
	}
	foreignArch := foreignArchForTest(t)

	filter, err := NewFilter(ActErrno.SetReturnCode(1))
	if err != nil {
		t.Fatalf("NewFilter: %v", err)
	}
	defer filter.Release()

	if err := filter.AddArch(foreignArch); err != nil {
		t.Fatalf("AddArch(%s): %v", foreignArch, err)
	}
	if err := filter.RemoveArch(nativeArch); err != nil {
		t.Fatalf("RemoveArch(%s): %v", nativeArch, err)
	}

	// A rule added to a filter containing only the foreign ABI belongs to
	// that ABI and must not be restored on the native ABI after import.
	call, err := GetSyscallFromName("getpid")
	if err != nil {
		t.Fatalf("GetSyscallFromName: %v", err)
	}
	if err := filter.AddRuleConditional(call, ActAllow, []ScmpCondition{{
		Argument: 0,
		Op:       CompareEqual,
		Operand1: 123,
	}}); err != nil {
		t.Fatalf("AddRuleConditional: %v", err)
	}

	wantPFC := exportPFCBytes(t, filter)
	exported, err := filter.Export()
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if bytes.Equal(exported, wantPFC) {
		t.Fatal("self-describing export must not be plain PFC")
	}
	if !bytes.HasPrefix(exported, filterExportMagic[:]) {
		t.Fatalf("export does not start with the format magic: %x", exported[:len(filterExportMagic)])
	}

	exportPath := t.TempDir() + "/filter.export"
	if err := os.WriteFile(exportPath, exported, 0o600); err != nil {
		t.Fatal(err)
	}
	persisted, err := os.ReadFile(exportPath)
	if err != nil {
		t.Fatal(err)
	}

	imported, err := ImportFilter(persisted)
	if err != nil {
		t.Fatalf("ImportFilter: %v", err)
	}
	defer imported.Release()

	present, err := imported.IsArchPresent(nativeArch)
	if err != nil {
		t.Fatalf("IsArchPresent(%s): %v", nativeArch, err)
	}
	if present {
		t.Errorf("native architecture %s was restored", nativeArch)
	}
	present, err = imported.IsArchPresent(foreignArch)
	if err != nil {
		t.Fatalf("IsArchPresent(%s): %v", foreignArch, err)
	}
	if !present {
		t.Errorf("foreign architecture %s was not restored", foreignArch)
	}

	gotPFC := exportPFCBytes(t, imported)
	if !bytes.Equal(gotPFC, wantPFC) {
		t.Errorf("imported filter differs from the original:\n--- want ---\n%s\n--- got ---\n%s", wantPFC, gotPFC)
	}

	roundTrip, err := imported.Export()
	if err != nil {
		t.Fatalf("Export after import: %v", err)
	}
	if !bytes.Equal(roundTrip, exported) {
		t.Errorf("export after import is not stable")
	}
}

func TestFilterExportImportMultiArch(t *testing.T) {
	nativeArch, err := GetNativeArch()
	if err != nil {
		t.Fatalf("GetNativeArch: %v", err)
	}
	foreignArch := foreignArchForTest(t)

	filter, err := NewFilter(ActKillThread)
	if err != nil {
		t.Fatalf("NewFilter: %v", err)
	}
	defer filter.Release()

	if err := filter.AddArch(foreignArch); err != nil {
		t.Fatalf("AddArch(%s): %v", foreignArch, err)
	}

	nativeCall, err := GetSyscallFromNameByArch("getpid", nativeArch)
	if err != nil {
		t.Fatalf("GetSyscallFromNameByArch(%s): %v", nativeArch, err)
	}
	foreignCall, err := GetSyscallFromNameByArch("getpid", foreignArch)
	if err != nil {
		t.Fatalf("GetSyscallFromNameByArch(%s): %v", foreignArch, err)
	}
	if nativeCall == foreignCall {
		t.Skipf("getpid has the same number on %s and %s", nativeArch, foreignArch)
	}

	if err := filter.AddRule(nativeCall, ActAllow); err != nil {
		t.Fatalf("AddRule(%s): %v", nativeArch, err)
	}
	if err := filter.AddRule(foreignCall, ActErrno.SetReturnCode(42)); err != nil {
		t.Fatalf("AddRule(%s): %v", foreignArch, err)
	}

	wantPFC := exportPFCBytes(t, filter)
	exported, err := filter.Export()
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	imported, err := ImportFilter(exported)
	if err != nil {
		t.Fatalf("ImportFilter: %v", err)
	}
	defer imported.Release()

	if present, err := imported.IsArchPresent(nativeArch); err != nil {
		t.Fatalf("IsArchPresent(%s): %v", nativeArch, err)
	} else if !present {
		t.Errorf("native architecture %s was not restored", nativeArch)
	}
	if present, err := imported.IsArchPresent(foreignArch); err != nil {
		t.Fatalf("IsArchPresent(%s): %v", foreignArch, err)
	} else if !present {
		t.Errorf("foreign architecture %s was not restored", foreignArch)
	}

	gotPFC := exportPFCBytes(t, imported)
	if !bytes.Equal(gotPFC, wantPFC) {
		t.Errorf("imported filter differs from the original:\n--- want ---\n%s\n--- got ---\n%s", wantPFC, gotPFC)
	}
}

func TestFilterExportImportAttributes(t *testing.T) {
	defaultAction := ActErrno.SetReturnCode(7)
	badArchAction := ActTrap

	filter, err := NewFilter(defaultAction)
	if err != nil {
		t.Fatalf("NewFilter: %v", err)
	}
	defer filter.Release()

	if err := filter.SetBadArchAction(badArchAction); err != nil {
		t.Fatalf("SetBadArchAction: %v", err)
	}
	if err := filter.SetNoNewPrivsBit(false); err != nil {
		t.Fatalf("SetNoNewPrivsBit: %v", err)
	}

	exported, err := filter.Export()
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	imported, err := ImportFilter(exported)
	if err != nil {
		t.Fatalf("ImportFilter: %v", err)
	}
	defer imported.Release()

	if action, err := imported.GetDefaultAction(); err != nil {
		t.Errorf("GetDefaultAction: %v", err)
	} else if action != defaultAction {
		t.Errorf("default action = %v, want %v", action, defaultAction)
	}
	if action, err := imported.GetBadArchAction(); err != nil {
		t.Errorf("GetBadArchAction: %v", err)
	} else if action != badArchAction {
		t.Errorf("bad architecture action = %v, want %v", action, badArchAction)
	}
	if nnp, err := imported.GetNoNewPrivsBit(); err != nil {
		t.Errorf("GetNoNewPrivsBit: %v", err)
	} else if nnp {
		t.Error("no-new-privs bit = true, want false")
	}
}

func TestImportRejectsLegacyRawBPF(t *testing.T) {
	if err := checkVersion("ExportBPFMem", 2, 6, 0); err != nil {
		t.Skip(err)
	}

	filter, err := NewFilter(ActAllow)
	if err != nil {
		t.Fatalf("NewFilter: %v", err)
	}
	defer filter.Release()

	call, err := GetSyscallFromName("getpid")
	if err != nil {
		t.Fatalf("GetSyscallFromName: %v", err)
	}
	if err := filter.AddRule(call, ActErrno.SetReturnCode(42)); err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	rawBPF, err := filter.ExportBPFMem()
	if err != nil {
		t.Fatalf("ExportBPFMem: %v", err)
	}
	if _, err := ImportFilter(rawBPF); !errors.Is(err, ErrLegacyFilterExport) {
		t.Fatalf("ImportFilter(raw BPF) error = %v, want %v", err, ErrLegacyFilterExport)
	}
}

func TestImportRejectsRuleForArchitectureNotInManifest(t *testing.T) {
	nativeArch, err := GetNativeArch()
	if err != nil {
		t.Fatalf("GetNativeArch: %v", err)
	}
	foreignArch := foreignArchForTest(t)

	filter, err := NewFilter(ActAllow)
	if err != nil {
		t.Fatalf("NewFilter: %v", err)
	}
	defer filter.Release()

	if err := filter.AddArch(foreignArch); err != nil {
		t.Fatalf("AddArch(%s): %v", foreignArch, err)
	}
	if err := filter.RemoveArch(nativeArch); err != nil {
		t.Fatalf("RemoveArch(%s): %v", nativeArch, err)
	}
	call, err := GetSyscallFromName("getpid")
	if err != nil {
		t.Fatalf("GetSyscallFromName: %v", err)
	}
	if err := filter.AddRule(call, ActErrno.SetReturnCode(42)); err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	exported, err := filter.Export()
	if err != nil {
		t.Fatalf("Export: %v", err)
	}

	// Corrupt the architecture tag of the first rule so that it points to
	// an architecture which is valid but absent from the manifest.
	const archEntrySize = 8
	ruleOffset := filterExportHeaderSize + archEntrySize
	unlistedArch := ArchX86
	if foreignArch == ArchX86 {
		unlistedArch = ArchAMD64
	}
	binary.LittleEndian.PutUint32(exported[ruleOffset:], unlistedArch.exportID())

	if _, err := ImportFilter(exported); !errors.Is(err, ErrFilterExportFormat) {
		t.Fatalf("ImportFilter() error = %v, want %v", err, ErrFilterExportFormat)
	}
}

func TestImportRejectsTruncatedExport(t *testing.T) {
	filter, err := NewFilter(ActAllow)
	if err != nil {
		t.Fatalf("NewFilter: %v", err)
	}
	defer filter.Release()

	exported, err := filter.Export()
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if _, err := ImportFilter(exported[:len(exported)-1]); !errors.Is(err, ErrFilterExportFormat) {
		t.Fatalf("ImportFilter(truncated) error = %v, want %v", err, ErrFilterExportFormat)
	}
}
