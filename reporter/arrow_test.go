package reporter

import (
	"testing"

	"github.com/apache/arrow/go/v16/arrow/memory"
)

func TestArrow(t *testing.T) {
	mem := memory.NewCheckedAllocator(memory.NewGoAllocator())
	defer mem.AssertSize(t, 0)

	w := NewV1Writer(mem, []string{"test1", "test2"})
	defer w.Release()

	w.LabelBuildersMap["test1"].AppendString("test")
	w.LabelBuildersMap["test2"].AppendString("test")
	w.Producer.AppendString("cpu")
	w.SampleType.AppendString("cpu")
	w.SampleUnit.AppendString("samples")
	w.PeriodType.AppendString("cpu")
	w.PeriodUnit.AppendString("nanoseconds")
	w.Temporality.AppendString("delta")
	w.Period.Append(1000)
	w.Duration.Append(1000)
	w.Timestamp.Append(1000)
	w.Value.Append(1)
	w.Address.Append(0x4000)
	w.FrameType.AppendString("native")
	w.MappingStart.Append(0x1000)
	w.MappingLimit.Append(0x6000)
	w.MappingOffset.Append(0x1000)
	w.MappingFile.AppendString("mybinary")
	w.MappingBuildID.AppendString("1234567890abcdef")
	w.LocationsList.Append(true)
	w.Locations.Append(true)
	w.Lines.Append(true)
	w.Line.Append(true)
	w.LineNumber.Append(123)
	w.FunctionName.AppendString("main")
	w.FunctionSystemName.AppendString("main")
	w.FunctionFilename.AppendString("main.c")
	w.FunctionStartLine.Append(120)

	r := w.NewRecord()
	defer r.Release()
}
