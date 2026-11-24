package seccomp

import (
	"errors"
	"fmt"
)

// This file implements a self-describing representation of a filter. Unlike
// the BPF exports, which are just a sequence of kernel instructions, this
// format records the architectures and the rules that belong to each
// architecture, so an imported filter cannot silently attach a rule to the
// wrong ABI.

const (
	filterExportVersion    = 1
	filterExportHeaderSize = 64

	filterExportFlagExact uint32 = 1 << 0

	filterExportAttrNNP uint32 = 1 << iota
	filterExportAttrLog
	filterExportAttrSSB
	filterExportAttrRawRC
	filterExportAttrWaitKill
	filterExportAttrOptimize
)

var (
	// ErrFilterExportFormat reports that data passed to Import is not a
	// supported filter export.
	ErrFilterExportFormat = errors.New("invalid seccomp filter export")
	// ErrLegacyFilterExport reports that data passed to Import is a legacy
	// raw BPF export. Such exports contain no architecture metadata and can
	// not be imported safely.
	ErrLegacyFilterExport = fmt.Errorf("%w: legacy raw BPF export has no architecture metadata", ErrFilterExportFormat)
	// ErrUnsupportedFilterExport reports that the export uses a format
	// version this package does not understand.
	ErrUnsupportedFilterExport = fmt.Errorf("%w: unsupported format version", ErrFilterExportFormat)
)

var filterExportMagic = [8]byte{0x89, 'S', 'C', 'M', 'P', 'F', 'I', 'L'}

type filterRule struct {
	call   ScmpSyscall
	action ScmpAction
	exact  bool
	conds  []ScmpCondition
}

type filterExportAttrs struct {
	defaultAction ScmpAction
	badArchAction ScmpAction
	attrMask      uint32
	attrValueMask uint32
	optimize      int32
}

type filterExportRule struct {
	arch ScmpArch
	rule filterRule
}

type filterExport struct {
	attrs  filterExportAttrs
	arches []ScmpArch
	rules  []filterExportRule
}

func cloneConditions(conds []ScmpCondition) []ScmpCondition {
	if len(conds) == 0 {
		return nil
	}
	cloned := make([]ScmpCondition, len(conds))
	copy(cloned, conds)
	return cloned
}

func cloneFilterRules(rules []filterRule) []filterRule {
	if len(rules) == 0 {
		return nil
	}
	cloned := make([]filterRule, len(rules))
	for i, rule := range rules {
		rule.conds = cloneConditions(rule.conds)
		cloned[i] = rule
	}
	return cloned
}

func cloneRuleMap(rules map[ScmpArch][]filterRule) map[ScmpArch][]filterRule {
	if rules == nil {
		return nil
	}
	cloned := make(map[ScmpArch][]filterRule, len(rules))
	for arch, archRules := range rules {
		cloned[arch] = cloneFilterRules(archRules)
	}
	return cloned
}

// DOES NOT LOCK OR CHECK VALIDITY
// Assumes caller has already done this.
func (f *ScmpFilter) ensureRuleArch(arch ScmpArch) {
	if f.rules == nil {
		return
	}
	if _, ok := f.rules[arch]; !ok {
		f.rules[arch] = nil
	}
}

// DOES NOT LOCK OR CHECK VALIDITY
// Assumes caller has already done this.
func (f *ScmpFilter) mergeRules(src *ScmpFilter) {
	if src.rules == nil {
		return
	}
	if f.rules == nil {
		f.rules = make(map[ScmpArch][]filterRule, len(src.rules))
	}
	for arch, rules := range src.rules {
		f.rules[arch] = append(f.rules[arch], cloneFilterRules(rules)...)
	}
}

// recordRule records a successfully added rule for every architecture it
// applies to. libseccomp interprets plain syscall numbers against the native
// architecture, so the number stored for each architecture is the equivalent
// number on that architecture.
//
// DOES NOT LOCK OR CHECK VALIDITY
// Assumes caller has already done this.
func (f *ScmpFilter) recordRule(call ScmpSyscall, action ScmpAction, exact bool, conds []ScmpCondition) {
	arches, err := f.getArchesLocked()
	if err != nil || len(arches) == 0 {
		return
	}

	var syscallName string
	nativeArch, err := GetNativeArch()
	if err != nil {
		return
	}
	syscallName, err = call.GetNameByArch(nativeArch)
	if err != nil && call >= 0 {
		return
	}

	if f.rules == nil {
		f.rules = make(map[ScmpArch][]filterRule, len(arches))
	}
	for _, arch := range arches {
		if _, ok := f.rules[arch]; !ok {
			f.rules[arch] = nil
		}
	}

	for _, arch := range arches {
		archCall := call
		if syscallName != "" {
			archCall, err = GetSyscallFromNameByArch(syscallName, arch)
			if err != nil {
				// The syscall does not exist for this ABI; libseccomp
				// does not add the rule there either.
				continue
			}
		}
		f.rules[arch] = append(f.rules[arch], filterRule{
			call:   archCall,
			action: action,
			exact:  exact,
			conds:  cloneConditions(conds),
		})
	}
}

// Export serializes a filter into a self-describing byte slice. The result
// records the filter attributes, the complete architecture list, and every
// rule together with the architecture it belongs to. It can be restored with
// [Import] or [ImportFilter].
//
// This is different from [ScmpFilter.ExportBPF] and
// [ScmpFilter.ExportBPFMem], which produce raw kernel BPF without any
// architecture metadata. Raw BPF is intentionally rejected by Import.
func (f *ScmpFilter) Export() ([]byte, error) {
	f.lock.Lock()
	defer f.lock.Unlock()

	if !f.valid {
		return nil, errBadFilter
	}

	attrs, err := f.snapshotExportAttrsLocked()
	if err != nil {
		return nil, fmt.Errorf("could not read filter attributes: %w", err)
	}

	arches, err := f.getArchesLocked()
	if err != nil {
		return nil, err
	}
	if len(arches) == 0 {
		return nil, errors.New("filter has no architectures")
	}

	rules := make([]filterExportRule, 0)
	ruleCounts := make(map[ScmpArch]uint32, len(arches))
	for _, arch := range arches {
		for _, rule := range f.rules[arch] {
			rules = append(rules, filterExportRule{arch: arch, rule: rule})
			ruleCounts[arch]++
		}
	}

	return marshalFilterExport(attrs, arches, ruleCounts, rules), nil
}

// MarshalBinary implements [encoding.BinaryMarshaler].
func (f *ScmpFilter) MarshalBinary() ([]byte, error) {
	return f.Export()
}

// ExportFilter is an alias for [ScmpFilter.Export].
func (f *ScmpFilter) ExportFilter() ([]byte, error) {
	return f.Export()
}

// ExportFilterMem is an alias for [ScmpFilter.Export].
func (f *ScmpFilter) ExportFilterMem() ([]byte, error) {
	return f.Export()
}

// ImportFilter restores a filter exported by [ScmpFilter.Export].
//
// Every rule is checked against the exported architecture list and is
// restored for the architecture it was exported for. A raw BPF export (the
// output of [ScmpFilter.ExportBPF] or [ScmpFilter.ExportBPFMem]) is rejected
// with [ErrLegacyFilterExport], because it has no architecture metadata.
func ImportFilter(data []byte) (*ScmpFilter, error) {
	exported, err := unmarshalFilterExport(data)
	if err != nil {
		return nil, err
	}
	return exported.build()
}

// Import is an alias for [ImportFilter].
func Import(data []byte) (*ScmpFilter, error) {
	return ImportFilter(data)
}

// ImportBPFMem is an alias for [ImportFilter]. It accepts only the
// self-describing format produced by [ScmpFilter.Export]; raw BPF is rejected
// with [ErrLegacyFilterExport].
func ImportBPFMem(data []byte) (*ScmpFilter, error) {
	return ImportFilter(data)
}

// Import replaces the state of f with the filter restored from data. On
// error, f is left unchanged.
//
// See [ImportFilter] for the format and legacy-format behavior.
func (f *ScmpFilter) Import(data []byte) error {
	imported, err := ImportFilter(data)
	if err != nil {
		return err
	}
	if err := f.replaceFilterCtx(imported); err != nil {
		imported.Release()
		return err
	}
	return nil
}

// UnmarshalBinary implements [encoding.BinaryUnmarshaler].
func (f *ScmpFilter) UnmarshalBinary(data []byte) error {
	return f.Import(data)
}

func marshalFilterExport(attrs filterExportAttrs, arches []ScmpArch, ruleCounts map[ScmpArch]uint32, rules []filterExportRule) []byte {
	size := filterExportHeaderSize + len(arches)*8
	for _, rule := range rules {
		size += 20 + len(rule.rule.conds)*24
	}

	data := make([]byte, 0, size)
	data = append(data, filterExportMagic[:]...)
	data = appendUint16(data, filterExportVersion)
	data = appendUint16(data, filterExportHeaderSize)
	data = appendUint32(data, 0) // reserved flags
	data = appendUint32(data, uint32(size))
	data = appendUint32(data, uint32(attrs.defaultAction))
	data = appendUint32(data, uint32(attrs.badArchAction))
	data = appendUint32(data, attrs.attrMask)
	data = appendUint32(data, attrs.attrValueMask)
	data = appendUint32(data, uint32(attrs.optimize))
	data = appendUint32(data, uint32(len(arches)))
	data = appendUint32(data, uint32(len(rules)))
	for len(data) < filterExportHeaderSize {
		data = append(data, 0)
	}

	for _, arch := range arches {
		data = appendUint32(data, arch.exportID())
		data = appendUint32(data, ruleCounts[arch])
	}
	for _, exportedRule := range rules {
		rule := exportedRule.rule
		flags := uint32(0)
		if rule.exact {
			flags |= filterExportFlagExact
		}
		data = appendUint32(data, exportedRule.arch.exportID())
		data = appendUint32(data, uint32(rule.call))
		data = appendUint32(data, uint32(rule.action))
		data = appendUint32(data, flags)
		data = appendUint32(data, uint32(len(rule.conds)))
		for _, cond := range rule.conds {
			data = appendUint32(data, uint32(cond.Argument))
			data = appendUint32(data, uint32(cond.Op))
			data = appendUint64(data, cond.Operand1)
			data = appendUint64(data, cond.Operand2)
		}
	}

	return data
}

func appendUint16(data []byte, value uint16) []byte {
	return append(data, byte(value), byte(value>>8))
}

func appendUint32(data []byte, value uint32) []byte {
	return append(data, byte(value), byte(value>>8), byte(value>>16), byte(value>>24))
}

func appendUint64(data []byte, value uint64) []byte {
	return append(data,
		byte(value), byte(value>>8), byte(value>>16), byte(value>>24),
		byte(value>>32), byte(value>>40), byte(value>>48), byte(value>>56))
}

type filterExportReader struct {
	data []byte
	off  int
	err  error
}

func (r *filterExportReader) remaining() int {
	return len(r.data) - r.off
}

func (r *filterExportReader) uint16() uint16 {
	if r.err != nil {
		return 0
	}
	if r.remaining() < 2 {
		r.err = errors.New("truncated export")
		return 0
	}
	value := uint16(r.data[r.off]) | uint16(r.data[r.off+1])<<8
	r.off += 2
	return value
}

func (r *filterExportReader) uint32() uint32 {
	if r.err != nil {
		return 0
	}
	if r.remaining() < 4 {
		r.err = errors.New("truncated export")
		return 0
	}
	value := uint32(r.data[r.off]) |
		uint32(r.data[r.off+1])<<8 |
		uint32(r.data[r.off+2])<<16 |
		uint32(r.data[r.off+3])<<24
	r.off += 4
	return value
}

func (r *filterExportReader) uint64() uint64 {
	if r.err != nil {
		return 0
	}
	if r.remaining() < 8 {
		r.err = errors.New("truncated export")
		return 0
	}
	value := uint64(r.uint32())
	value |= uint64(r.uint32()) << 32
	return value
}

func (r *filterExportReader) skip(length int) {
	if r.err != nil {
		return
	}
	if length < 0 || r.remaining() < length {
		r.err = errors.New("truncated export")
		return
	}
	r.off += length
}

func unmarshalFilterExport(data []byte) (*filterExport, error) {
	if len(data) < len(filterExportMagic) || !bytesEqual(data[:len(filterExportMagic)], filterExportMagic[:]) {
		if looksLikeRawBPF(data) {
			return nil, ErrLegacyFilterExport
		}
		return nil, fmt.Errorf("%w: missing format header", ErrFilterExportFormat)
	}

	reader := &filterExportReader{data: data, off: len(filterExportMagic)}
	version := reader.uint16()
	headerSize := reader.uint16()
	_ = reader.uint32() // reserved flags
	totalSize := reader.uint32()
	defaultAction := ScmpAction(reader.uint32())
	badArchAction := ScmpAction(reader.uint32())
	attrMask := reader.uint32()
	attrValueMask := reader.uint32()
	optimize := int32(reader.uint32())
	archCount := reader.uint32()
	ruleCount := reader.uint32()

	if reader.err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFilterExportFormat, reader.err)
	}
	if version != filterExportVersion {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrUnsupportedFilterExport, version, filterExportVersion)
	}
	if headerSize != filterExportHeaderSize || int(totalSize) != len(data) {
		return nil, fmt.Errorf("%w: invalid header or total size", ErrFilterExportFormat)
	}
	reader.skip(int(headerSize) - reader.off)
	if err := sanitizeAction(defaultAction); err != nil {
		return nil, fmt.Errorf("%w: invalid default action: %v", ErrFilterExportFormat, err)
	}
	if err := sanitizeAction(badArchAction); err != nil {
		return nil, fmt.Errorf("%w: invalid bad-architecture action: %v", ErrFilterExportFormat, err)
	}
	const knownAttrs = filterExportAttrNNP |
		filterExportAttrLog |
		filterExportAttrSSB |
		filterExportAttrRawRC |
		filterExportAttrWaitKill |
		filterExportAttrOptimize
	if attrMask&^knownAttrs != 0 || attrValueMask&^knownAttrs != 0 {
		return nil, fmt.Errorf("%w: unknown filter attributes %#x", ErrFilterExportFormat, attrMask|attrValueMask)
	}
	if attrValueMask&^attrMask != 0 {
		return nil, fmt.Errorf("%w: filter attribute value without presence bit", ErrFilterExportFormat)
	}
	if archCount == 0 {
		return nil, fmt.Errorf("%w: empty architecture list", ErrFilterExportFormat)
	}
	if uint64(archCount) > uint64(reader.remaining()/8) {
		return nil, fmt.Errorf("%w: architecture table is truncated", ErrFilterExportFormat)
	}

	exported := &filterExport{
		attrs: filterExportAttrs{
			defaultAction: defaultAction,
			badArchAction: badArchAction,
			attrMask:      attrMask,
			attrValueMask: attrValueMask,
			optimize:      optimize,
		},
		arches: make([]ScmpArch, 0, archCount),
	}

	declaredRuleCounts := make(map[ScmpArch]uint32, archCount)
	seenArches := make(map[ScmpArch]struct{}, archCount)
	for i := uint32(0); i < archCount; i++ {
		archID := reader.uint32()
		archRuleCount := reader.uint32()
		if reader.err != nil {
			return nil, fmt.Errorf("%w: %v", ErrFilterExportFormat, reader.err)
		}
		arch, err := archFromExportID(archID)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrFilterExportFormat, err)
		}
		if arch == ArchNative {
			return nil, fmt.Errorf("%w: native architecture placeholder in manifest", ErrFilterExportFormat)
		}
		if err := sanitizeArch(arch); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrFilterExportFormat, err)
		}
		if _, ok := seenArches[arch]; ok {
			return nil, fmt.Errorf("%w: duplicate architecture %s", ErrFilterExportFormat, arch)
		}
		seenArches[arch] = struct{}{}
		declaredRuleCounts[arch] = archRuleCount
		exported.arches = append(exported.arches, arch)
	}

	if uint64(ruleCount) > uint64(reader.remaining()/20) {
		return nil, fmt.Errorf("%w: rule table is truncated", ErrFilterExportFormat)
	}

	actualRuleCounts := make(map[ScmpArch]uint32, len(exported.arches))
	exported.rules = make([]filterExportRule, 0, ruleCount)
	for i := uint32(0); i < ruleCount; i++ {
		archID := reader.uint32()
		call := ScmpSyscall(int32(reader.uint32()))
		action := ScmpAction(reader.uint32())
		flags := reader.uint32()
		condCount := reader.uint32()
		if reader.err != nil {
			return nil, fmt.Errorf("%w: %v", ErrFilterExportFormat, reader.err)
		}
		arch, err := archFromExportID(archID)
		if err != nil {
			return nil, fmt.Errorf("%w: rule has invalid architecture: %v", ErrFilterExportFormat, err)
		}
		if _, ok := seenArches[arch]; !ok {
			return nil, fmt.Errorf("%w: rule references architecture %s which is not in the architecture list", ErrFilterExportFormat, arch)
		}
		if flags&^filterExportFlagExact != 0 {
			return nil, fmt.Errorf("%w: unknown rule flags %#x", ErrFilterExportFormat, flags)
		}
		if err := sanitizeAction(action); err != nil {
			return nil, fmt.Errorf("%w: invalid rule action: %v", ErrFilterExportFormat, err)
		}
		if condCount > 6 {
			return nil, fmt.Errorf("%w: rule has too many conditions", ErrFilterExportFormat)
		}
		if uint64(condCount) > uint64(reader.remaining()/24) {
			return nil, fmt.Errorf("%w: rule conditions are truncated", ErrFilterExportFormat)
		}
		rule := filterRule{
			call:   call,
			action: action,
			exact:  flags&filterExportFlagExact != 0,
			conds:  make([]ScmpCondition, 0, condCount),
		}
		for j := uint32(0); j < condCount; j++ {
			argument := reader.uint32()
			op := ScmpCompareOp(reader.uint32())
			operand1 := reader.uint64()
			operand2 := reader.uint64()
			if reader.err != nil {
				return nil, fmt.Errorf("%w: %v", ErrFilterExportFormat, reader.err)
			}
			if argument > 5 {
				return nil, fmt.Errorf("%w: invalid rule argument %d", ErrFilterExportFormat, argument)
			}
			if err := sanitizeCompareOp(op); err != nil {
				return nil, fmt.Errorf("%w: invalid comparison operator: %v", ErrFilterExportFormat, err)
			}
			rule.conds = append(rule.conds, ScmpCondition{
				Argument: uint(argument),
				Op:       op,
				Operand1: operand1,
				Operand2: operand2,
			})
		}
		actualRuleCounts[arch]++
		exported.rules = append(exported.rules, filterExportRule{arch: arch, rule: rule})
	}

	if reader.err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFilterExportFormat, reader.err)
	}
	if reader.remaining() != 0 {
		return nil, fmt.Errorf("%w: %d trailing bytes", ErrFilterExportFormat, reader.remaining())
	}
	for _, arch := range exported.arches {
		if actualRuleCounts[arch] != declaredRuleCounts[arch] {
			return nil, fmt.Errorf("%w: rule count mismatch for architecture %s", ErrFilterExportFormat, arch)
		}
	}

	return exported, nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// looksLikeRawBPF reports whether data could be the output of
// seccomp_export_bpf. A BPF program is an array of 8-byte sock_filter
// structures.
func looksLikeRawBPF(data []byte) bool {
	return len(data) > 0 && len(data)%8 == 0
}

func (exported *filterExport) build() (*ScmpFilter, error) {
	nativeArch, err := GetNativeArch()
	if err != nil {
		return nil, err
	}

	subFilters := make([]*ScmpFilter, 0, len(exported.arches))
	success := false
	defer func() {
		if success {
			return
		}
		for _, filter := range subFilters {
			filter.Release()
		}
	}()

	for _, arch := range exported.arches {
		filter, err := NewFilter(exported.attrs.defaultAction)
		if err != nil {
			return nil, err
		}
		subFilters = append(subFilters, filter)

		if err := applyExportAttrs(filter, exported.attrs); err != nil {
			return nil, err
		}
		if arch != nativeArch {
			if err := filter.AddArch(arch); err != nil {
				return nil, err
			}
			if err := filter.RemoveArch(nativeArch); err != nil {
				return nil, err
			}
		}

		for _, exportedRule := range exported.rules {
			if exportedRule.arch != arch {
				continue
			}
			call, err := importRuleCall(exportedRule.rule.call, arch)
			if err != nil {
				return nil, fmt.Errorf("could not restore rule for architecture %s: %w", arch, err)
			}
			rule := exportedRule.rule
			switch {
			case rule.exact && len(rule.conds) == 0:
				err = filter.AddRuleExact(call, rule.action)
			case rule.exact:
				err = filter.AddRuleConditionalExact(call, rule.action, rule.conds)
			case len(rule.conds) == 0:
				err = filter.AddRule(call, rule.action)
			default:
				err = filter.AddRuleConditional(call, rule.action, rule.conds)
			}
			if err != nil {
				return nil, fmt.Errorf("could not restore rule for architecture %s: %w", arch, err)
			}
		}
	}

	if len(subFilters) == 0 {
		return nil, fmt.Errorf("%w: empty architecture list", ErrFilterExportFormat)
	}

	base := subFilters[0]
	for _, filter := range subFilters[1:] {
		if err := base.Merge(filter); err != nil {
			return nil, err
		}
	}

	success = true
	return base, nil
}

func applyExportAttrs(filter *ScmpFilter, attrs filterExportAttrs) error {
	if attrs.attrMask&filterExportAttrNNP != 0 {
		if err := filter.SetNoNewPrivsBit(attrs.attrValueMask&filterExportAttrNNP != 0); err != nil {
			return err
		}
	}
	if attrs.attrMask&filterExportAttrLog != 0 {
		if err := filter.SetLogBit(attrs.attrValueMask&filterExportAttrLog != 0); err != nil {
			return err
		}
	}
	if attrs.attrMask&filterExportAttrSSB != 0 {
		if err := filter.SetSSB(attrs.attrValueMask&filterExportAttrSSB != 0); err != nil {
			return err
		}
	}
	if attrs.attrMask&filterExportAttrRawRC != 0 {
		if err := filter.SetRawRC(attrs.attrValueMask&filterExportAttrRawRC != 0); err != nil {
			return err
		}
	}
	if attrs.attrMask&filterExportAttrWaitKill != 0 {
		if err := filter.SetWaitKill(attrs.attrValueMask&filterExportAttrWaitKill != 0); err != nil {
			return err
		}
	}
	if attrs.attrMask&filterExportAttrOptimize != 0 {
		if err := filter.SetOptimize(int(attrs.optimize)); err != nil {
			return err
		}
	}
	if err := filter.SetBadArchAction(attrs.badArchAction); err != nil {
		return err
	}
	return nil
}

// importRuleCall converts the syscall number stored for arch into the
// equivalent native number. libseccomp interprets the number passed to
// seccomp_rule_add() against the native architecture and maps it to every
// architecture present in the filter.
func importRuleCall(call ScmpSyscall, arch ScmpArch) (ScmpSyscall, error) {
	name, err := call.GetNameByArch(arch)
	if err != nil {
		if call < 0 {
			return call, nil
		}
		return 0, fmt.Errorf("unknown syscall %#x on architecture %s", int32(call), arch)
	}
	nativeArch, err := GetNativeArch()
	if err != nil {
		return 0, err
	}
	nativeCall, err := GetSyscallFromNameByArch(name, nativeArch)
	if err != nil {
		return 0, err
	}
	return nativeCall, nil
}
