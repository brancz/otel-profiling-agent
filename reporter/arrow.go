package reporter

import (
	"bytes"
	"unsafe"

	"github.com/apache/arrow/go/v16/arrow"
	"github.com/apache/arrow/go/v16/arrow/array"
	"github.com/apache/arrow/go/v16/arrow/memory"
)

func binaryDictionaryRunEndBuilder(arr array.Builder) *BinaryDictionaryRunEndBuilder {
	ree := arr.(*array.RunEndEncodedBuilder)
	return &BinaryDictionaryRunEndBuilder{
		ree: ree,
		bd:  ree.ValueBuilder().(*array.BinaryDictionaryBuilder),
	}
}

type BinaryDictionaryRunEndBuilder struct {
	ree *array.RunEndEncodedBuilder
	bd  *array.BinaryDictionaryBuilder
}

func (b *BinaryDictionaryRunEndBuilder) Append(v []byte) {
	if b.bd.Len() > 0 && bytes.Equal(v, b.bd.Value(b.bd.Len()-1)) {
		b.ree.ContinueRun(1)
		return
	}
	b.ree.Append(1)
	b.bd.Append(v)
}

func (b *BinaryDictionaryRunEndBuilder) AppendString(v string) {
	b.Append(unsafeStringToBytes(v))
}

func unsafeStringToBytes(s string) []byte {
	return unsafe.Slice(unsafe.StringData(s), len(s))
}

func uint64RunEndBuilder(arr array.Builder) *Uint64RunEndBuilder {
	ree := arr.(*array.RunEndEncodedBuilder)
	return &Uint64RunEndBuilder{
		ree: ree,
		ub:  ree.ValueBuilder().(*array.Uint64Builder),
	}
}

type Uint64RunEndBuilder struct {
	ree *array.RunEndEncodedBuilder
	ub  *array.Uint64Builder
}

func (b *Uint64RunEndBuilder) Append(v uint64) {
	if b.ub.Len() > 0 && v == b.ub.Value(b.ub.Len()-1) {
		b.ree.ContinueRun(1)
		return
	}
	b.ree.Append(1)
	b.ub.Append(v)
}

type Int64RunEndBuilder struct {
	ree *array.RunEndEncodedBuilder
	ib  *array.Int64Builder
}

func int64RunEndBuilder(arr array.Builder) *Int64RunEndBuilder {
	ree := arr.(*array.RunEndEncodedBuilder)
	return &Int64RunEndBuilder{
		ree: ree,
		ib:  ree.ValueBuilder().(*array.Int64Builder),
	}
}

func (b *Int64RunEndBuilder) Append(v int64) {
	if b.ib.Len() > 0 && v == b.ib.Value(b.ib.Len()-1) {
		b.ree.ContinueRun(1)
		return
	}
	b.ree.Append(1)
	b.ib.Append(v)
}

type Writer struct {
	recordBuilder *array.RecordBuilder

	LabelBuildersMap   map[string]*BinaryDictionaryRunEndBuilder
	LabelBuilders      []*BinaryDictionaryRunEndBuilder
	LocationsList      *array.ListBuilder
	Locations          *array.StructBuilder
	Address            *array.Uint64Builder
	FrameType          *BinaryDictionaryRunEndBuilder
	MappingStart       *Uint64RunEndBuilder
	MappingLimit       *Uint64RunEndBuilder
	MappingOffset      *Uint64RunEndBuilder
	MappingFile        *BinaryDictionaryRunEndBuilder
	MappingBuildID     *BinaryDictionaryRunEndBuilder
	Lines              *array.ListBuilder
	Line               *array.StructBuilder
	LineNumber         *array.Int64Builder
	FunctionName       *array.BinaryDictionaryBuilder
	FunctionSystemName *array.BinaryDictionaryBuilder
	FunctionFilename   *BinaryDictionaryRunEndBuilder
	FunctionStartLine  *array.Int64Builder
	Value              *array.Int64Builder
	Producer           *BinaryDictionaryRunEndBuilder
	SampleType         *BinaryDictionaryRunEndBuilder
	SampleUnit         *BinaryDictionaryRunEndBuilder
	PeriodType         *BinaryDictionaryRunEndBuilder
	PeriodUnit         *BinaryDictionaryRunEndBuilder
	Temporality        *BinaryDictionaryRunEndBuilder
	Period             *Int64RunEndBuilder
	Duration           *Int64RunEndBuilder
	Timestamp          *Int64RunEndBuilder
}

func (w *Writer) NewRecord() arrow.Record {
	r := w.recordBuilder.NewRecord()

	for _, c := range r.Columns() {
		if dict, ok := c.(*array.Dictionary); ok {
			// Dictionaries are lazily initialized, so we need to force
			// initialization here.
			dict.Dictionary()
		}
	}

	return r
}

func (w *Writer) Release() {
	w.recordBuilder.Release()
}

var LocationsField = arrow.Field{
	Name: "locations",
	Type: arrow.ListOf(arrow.StructOf([]arrow.Field{{
		Name: "address",
		Type: arrow.PrimitiveTypes.Uint64,
	}, {
		Name: "frame_type",
		Type: arrow.RunEndEncodedOf(
			arrow.PrimitiveTypes.Int32,
			&arrow.DictionaryType{IndexType: arrow.PrimitiveTypes.Uint32, ValueType: arrow.BinaryTypes.Binary},
		),
	}, {
		Name: "mapping_start",
		Type: arrow.RunEndEncodedOf(arrow.PrimitiveTypes.Int32, arrow.PrimitiveTypes.Uint64),
	}, {
		Name: "mapping_limit",
		Type: arrow.RunEndEncodedOf(arrow.PrimitiveTypes.Int32, arrow.PrimitiveTypes.Uint64),
	}, {
		Name: "mapping_offset",
		Type: arrow.RunEndEncodedOf(arrow.PrimitiveTypes.Int32, arrow.PrimitiveTypes.Uint64),
	}, {
		Name: "mapping_file",
		Type: arrow.RunEndEncodedOf(
			arrow.PrimitiveTypes.Int32,
			&arrow.DictionaryType{IndexType: arrow.PrimitiveTypes.Uint32, ValueType: arrow.BinaryTypes.Binary},
		),
	}, {
		Name: "mapping_build_id",
		Type: arrow.RunEndEncodedOf(
			arrow.PrimitiveTypes.Int32,
			&arrow.DictionaryType{IndexType: arrow.PrimitiveTypes.Uint32, ValueType: arrow.BinaryTypes.Binary},
		),
	}, {
		Name: "lines",
		Type: arrow.ListOf(arrow.StructOf([]arrow.Field{{
			Name: "line",
			Type: arrow.PrimitiveTypes.Int64,
		}, {
			Name: "function_name",
			Type: &arrow.DictionaryType{IndexType: arrow.PrimitiveTypes.Uint32, ValueType: arrow.BinaryTypes.Binary},
		}, {
			Name: "function_system_name",
			Type: &arrow.DictionaryType{IndexType: arrow.PrimitiveTypes.Uint32, ValueType: arrow.BinaryTypes.Binary},
		}, {
			Name: "function_filename",
			Type: arrow.RunEndEncodedOf(
				arrow.PrimitiveTypes.Int32,
				&arrow.DictionaryType{IndexType: arrow.PrimitiveTypes.Uint32, ValueType: arrow.BinaryTypes.Binary},
			),
		}, {
			Name: "function_start_line",
			Type: arrow.PrimitiveTypes.Int64,
		}}...)),
	}}...)),
}

func ArrowSamplesField(profileLabelFields []arrow.Field) []arrow.Field {
	numFields := len(profileLabelFields) + 11 // +11 for stacktraces, value, producer, sample_type, sample_unit, period_type, period_unit, temporality, period, duration, timestamp
	fields := make([]arrow.Field, numFields)
	copy(fields, profileLabelFields)
	fields[numFields-11] = LocationsField
	fields[numFields-10] = arrow.Field{
		Name: "value",
		Type: arrow.PrimitiveTypes.Int64,
	}
	fields[numFields-9] = arrow.Field{
		Name: "producer",
		Type: arrow.RunEndEncodedOf(
			arrow.PrimitiveTypes.Int32,
			&arrow.DictionaryType{IndexType: arrow.PrimitiveTypes.Uint32, ValueType: arrow.BinaryTypes.Binary},
		),
	}
	fields[numFields-8] = arrow.Field{
		Name: "sample_type",
		Type: arrow.RunEndEncodedOf(
			arrow.PrimitiveTypes.Int32,
			&arrow.DictionaryType{IndexType: arrow.PrimitiveTypes.Uint32, ValueType: arrow.BinaryTypes.Binary},
		),
	}
	fields[numFields-7] = arrow.Field{
		Name: "sample_unit",
		Type: arrow.RunEndEncodedOf(
			arrow.PrimitiveTypes.Int32,
			&arrow.DictionaryType{IndexType: arrow.PrimitiveTypes.Uint32, ValueType: arrow.BinaryTypes.Binary},
		),
	}
	fields[numFields-6] = arrow.Field{
		Name: "period_type",
		Type: arrow.RunEndEncodedOf(
			arrow.PrimitiveTypes.Int32,
			&arrow.DictionaryType{IndexType: arrow.PrimitiveTypes.Uint32, ValueType: arrow.BinaryTypes.Binary},
		),
	}
	fields[numFields-5] = arrow.Field{
		Name: "period_unit",
		Type: arrow.RunEndEncodedOf(
			arrow.PrimitiveTypes.Int32,
			&arrow.DictionaryType{IndexType: arrow.PrimitiveTypes.Uint32, ValueType: arrow.BinaryTypes.Binary},
		),
	}
	fields[numFields-4] = arrow.Field{
		Name: "temporality",
		Type: arrow.RunEndEncodedOf(
			arrow.PrimitiveTypes.Int32,
			&arrow.DictionaryType{IndexType: arrow.PrimitiveTypes.Uint32, ValueType: arrow.BinaryTypes.Binary},
		),
	}
	fields[numFields-3] = arrow.Field{
		Name: "period",
		Type: arrow.RunEndEncodedOf(arrow.PrimitiveTypes.Int32, arrow.PrimitiveTypes.Int64),
	}
	fields[numFields-2] = arrow.Field{
		Name: "duration",
		Type: arrow.RunEndEncodedOf(arrow.PrimitiveTypes.Int32, arrow.PrimitiveTypes.Int64),
	}
	fields[numFields-1] = arrow.Field{
		Name: "timestamp",
		Type: arrow.RunEndEncodedOf(arrow.PrimitiveTypes.Int32, arrow.PrimitiveTypes.Int64),
	}

	return fields
}

const (
	MetadataSchemaVersion = "parca_write_schema_version"
)

const (
	MetadataSchemaVersionV1 = "v1"
)

func ArrowSchemaV1(profileLabelFields []arrow.Field) *arrow.Schema {
	m := arrow.NewMetadata([]string{MetadataSchemaVersion}, []string{MetadataSchemaVersionV1})
	return arrow.NewSchema(ArrowSamplesField(profileLabelFields), &m)
}

const ColumnLabelsPrefix = "labels."

func NewV1Writer(pool memory.Allocator, labelNames []string) Writer {
	labelFields := make([]arrow.Field, len(labelNames))
	for i, name := range labelNames {
		labelFields[i] = arrow.Field{
			Name: ColumnLabelsPrefix + name,
			Type: arrow.RunEndEncodedOf(
				arrow.PrimitiveTypes.Int32,
				&arrow.DictionaryType{IndexType: arrow.PrimitiveTypes.Uint32, ValueType: arrow.BinaryTypes.Binary},
			),
			Nullable: true,
		}
	}

	b := array.NewRecordBuilder(pool, ArrowSchemaV1(labelFields))

	labelNum := len(labelFields)
	labelBuilders := make([]*BinaryDictionaryRunEndBuilder, labelNum)
	labelBuildersMap := make(map[string]*BinaryDictionaryRunEndBuilder, labelNum)
	for i := 0; i < labelNum; i++ {
		labelBuilders[i] = binaryDictionaryRunEndBuilder(b.Field(i))
		labelBuildersMap[labelNames[i]] = labelBuilders[i]
	}

	locationsList := b.Field(labelNum).(*array.ListBuilder)
	locations := locationsList.ValueBuilder().(*array.StructBuilder)

	addresses := locations.FieldBuilder(0).(*array.Uint64Builder)
	frameType := binaryDictionaryRunEndBuilder(locations.FieldBuilder(1))

	mappingStart := uint64RunEndBuilder(locations.FieldBuilder(2))
	mappingLimit := uint64RunEndBuilder(locations.FieldBuilder(3))
	mappingOffset := uint64RunEndBuilder(locations.FieldBuilder(4))
	mappingFile := binaryDictionaryRunEndBuilder(locations.FieldBuilder(5))
	mappingBuildID := binaryDictionaryRunEndBuilder(locations.FieldBuilder(6))

	lines := locations.FieldBuilder(7).(*array.ListBuilder)
	line := lines.ValueBuilder().(*array.StructBuilder)
	lineNumber := line.FieldBuilder(0).(*array.Int64Builder)
	functionName := line.FieldBuilder(1).(*array.BinaryDictionaryBuilder)
	functionSystemName := line.FieldBuilder(2).(*array.BinaryDictionaryBuilder)
	functionFilename := binaryDictionaryRunEndBuilder(line.FieldBuilder(3))
	functionStartLine := line.FieldBuilder(4).(*array.Int64Builder)

	value := b.Field(labelNum + 1).(*array.Int64Builder)
	producer := binaryDictionaryRunEndBuilder(b.Field(labelNum + 2))
	sampleType := binaryDictionaryRunEndBuilder(b.Field(labelNum + 3))
	sampleUnit := binaryDictionaryRunEndBuilder(b.Field(labelNum + 4))
	periodType := binaryDictionaryRunEndBuilder(b.Field(labelNum + 5))
	periodUnit := binaryDictionaryRunEndBuilder(b.Field(labelNum + 6))
	temporality := binaryDictionaryRunEndBuilder(b.Field(labelNum + 7))
	period := int64RunEndBuilder(b.Field(labelNum + 8))
	duration := int64RunEndBuilder(b.Field(labelNum + 9))
	timestamp := int64RunEndBuilder(b.Field(labelNum + 10))

	return Writer{
		recordBuilder:      b,
		LabelBuildersMap:   labelBuildersMap,
		LabelBuilders:      labelBuilders,
		LocationsList:      locationsList,
		Locations:          locations,
		Address:            addresses,
		FrameType:          frameType,
		MappingStart:       mappingStart,
		MappingLimit:       mappingLimit,
		MappingOffset:      mappingOffset,
		MappingFile:        mappingFile,
		MappingBuildID:     mappingBuildID,
		Lines:              lines,
		Line:               line,
		LineNumber:         lineNumber,
		FunctionName:       functionName,
		FunctionSystemName: functionSystemName,
		FunctionFilename:   functionFilename,
		FunctionStartLine:  functionStartLine,
		Value:              value,
		Producer:           producer,
		SampleType:         sampleType,
		SampleUnit:         sampleUnit,
		PeriodType:         periodType,
		PeriodUnit:         periodUnit,
		Temporality:        temporality,
		Period:             period,
		Duration:           duration,
		Timestamp:          timestamp,
	}
}
