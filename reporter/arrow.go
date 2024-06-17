package reporter

import (
	"github.com/apache/arrow/go/v16/arrow"
	"github.com/apache/arrow/go/v16/arrow/array"
	"github.com/apache/arrow/go/v16/arrow/memory"
)

type Writer struct {
	recordBuilder *array.RecordBuilder

	LabelBuildersMap   map[string]*array.BinaryDictionaryBuilder
	LabelBuilders      []*array.BinaryDictionaryBuilder
	LocationsList      *array.ListBuilder
	Locations          *array.StructBuilder
	Address            *array.Uint64Builder
	FrameType          *array.BinaryDictionaryBuilder
	MappingStart       *array.Uint64Builder
	MappingLimit       *array.Uint64Builder
	MappingOffset      *array.Uint64Builder
	MappingFile        *array.BinaryDictionaryBuilder
	MappingBuildID     *array.BinaryDictionaryBuilder
	Lines              *array.ListBuilder
	Line               *array.StructBuilder
	LineNumber         *array.Int64Builder
	FunctionName       *array.BinaryDictionaryBuilder
	FunctionSystemName *array.BinaryDictionaryBuilder
	FunctionFilename   *array.BinaryDictionaryBuilder
	FunctionStartLine  *array.Int64Builder
	Value              *array.Int64Builder
	Producer           *array.BinaryDictionaryBuilder
	SampleType         *array.BinaryDictionaryBuilder
	SampleUnit         *array.BinaryDictionaryBuilder
	PeriodType         *array.BinaryDictionaryBuilder
	PeriodUnit         *array.BinaryDictionaryBuilder
	Temporality        *array.BinaryDictionaryBuilder
	Period             *array.Int64Builder
	Duration           *array.Int64Builder
	Timestamp          *array.Int64Builder
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
		Type: &arrow.DictionaryType{IndexType: arrow.PrimitiveTypes.Uint32, ValueType: arrow.BinaryTypes.Binary},
	}, {
		Name: "mapping_start",
		Type: arrow.PrimitiveTypes.Uint64,
	}, {
		Name: "mapping_limit",
		Type: arrow.PrimitiveTypes.Uint64,
	}, {
		Name: "mapping_offset",
		Type: arrow.PrimitiveTypes.Uint64,
	}, {
		Name: "mapping_file",
		Type: &arrow.DictionaryType{IndexType: arrow.PrimitiveTypes.Uint32, ValueType: arrow.BinaryTypes.Binary},
	}, {
		Name: "mapping_build_id",
		Type: &arrow.DictionaryType{IndexType: arrow.PrimitiveTypes.Uint32, ValueType: arrow.BinaryTypes.Binary},
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
			Type: &arrow.DictionaryType{IndexType: arrow.PrimitiveTypes.Uint32, ValueType: arrow.BinaryTypes.Binary},
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
		Type: &arrow.DictionaryType{IndexType: arrow.PrimitiveTypes.Uint32, ValueType: arrow.BinaryTypes.Binary},
	}
	fields[numFields-8] = arrow.Field{
		Name: "sample_type",
		Type: &arrow.DictionaryType{IndexType: arrow.PrimitiveTypes.Uint32, ValueType: arrow.BinaryTypes.Binary},
	}
	fields[numFields-7] = arrow.Field{
		Name: "sample_unit",
		Type: &arrow.DictionaryType{IndexType: arrow.PrimitiveTypes.Uint32, ValueType: arrow.BinaryTypes.Binary},
	}
	fields[numFields-6] = arrow.Field{
		Name: "period_type",
		Type: &arrow.DictionaryType{IndexType: arrow.PrimitiveTypes.Uint32, ValueType: arrow.BinaryTypes.Binary},
	}
	fields[numFields-5] = arrow.Field{
		Name: "period_unit",
		Type: &arrow.DictionaryType{IndexType: arrow.PrimitiveTypes.Uint32, ValueType: arrow.BinaryTypes.Binary},
	}
	fields[numFields-4] = arrow.Field{
		Name: "temporality",
		Type: &arrow.DictionaryType{IndexType: arrow.PrimitiveTypes.Uint32, ValueType: arrow.BinaryTypes.Binary},
	}
	fields[numFields-3] = arrow.Field{
		Name: "period",
		Type: arrow.PrimitiveTypes.Int64,
	}
	fields[numFields-2] = arrow.Field{
		Name: "duration",
		Type: arrow.PrimitiveTypes.Int64,
	}
	fields[numFields-1] = arrow.Field{
		Name: "timestamp",
		Type: arrow.PrimitiveTypes.Int64,
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
			Name:     ColumnLabelsPrefix + name,
			Type:     &arrow.DictionaryType{IndexType: arrow.PrimitiveTypes.Uint32, ValueType: arrow.BinaryTypes.Binary},
			Nullable: true,
		}
	}

	b := array.NewRecordBuilder(pool, ArrowSchemaV1(labelFields))

	labelNum := len(labelFields)
	labelBuilders := make([]*array.BinaryDictionaryBuilder, labelNum)
	labelBuildersMap := make(map[string]*array.BinaryDictionaryBuilder, labelNum)
	for i := 0; i < labelNum; i++ {
		labelBuilders[i] = b.Field(i).(*array.BinaryDictionaryBuilder)
		labelBuildersMap[labelNames[i]] = labelBuilders[i]
	}

	locationsList := b.Field(labelNum).(*array.ListBuilder)
	locations := locationsList.ValueBuilder().(*array.StructBuilder)

	addresses := locations.FieldBuilder(0).(*array.Uint64Builder)
	frameType := locations.FieldBuilder(1).(*array.BinaryDictionaryBuilder)

	mappingStart := locations.FieldBuilder(2).(*array.Uint64Builder)
	mappingLimit := locations.FieldBuilder(3).(*array.Uint64Builder)
	mappingOffset := locations.FieldBuilder(4).(*array.Uint64Builder)
	mappingFile := locations.FieldBuilder(5).(*array.BinaryDictionaryBuilder)
	mappingBuildID := locations.FieldBuilder(6).(*array.BinaryDictionaryBuilder)

	lines := locations.FieldBuilder(7).(*array.ListBuilder)
	line := lines.ValueBuilder().(*array.StructBuilder)
	lineNumber := line.FieldBuilder(0).(*array.Int64Builder)
	functionName := line.FieldBuilder(1).(*array.BinaryDictionaryBuilder)
	functionSystemName := line.FieldBuilder(2).(*array.BinaryDictionaryBuilder)
	functionFilename := line.FieldBuilder(3).(*array.BinaryDictionaryBuilder)
	functionStartLine := line.FieldBuilder(4).(*array.Int64Builder)

	value := b.Field(labelNum + 1).(*array.Int64Builder)
	producer := b.Field(labelNum + 2).(*array.BinaryDictionaryBuilder)
	sampleType := b.Field(labelNum + 3).(*array.BinaryDictionaryBuilder)
	sampleUnit := b.Field(labelNum + 4).(*array.BinaryDictionaryBuilder)
	periodType := b.Field(labelNum + 5).(*array.BinaryDictionaryBuilder)
	periodUnit := b.Field(labelNum + 6).(*array.BinaryDictionaryBuilder)
	temporality := b.Field(labelNum + 7).(*array.BinaryDictionaryBuilder)
	period := b.Field(labelNum + 8).(*array.Int64Builder)
	duration := b.Field(labelNum + 9).(*array.Int64Builder)
	timestamp := b.Field(labelNum + 10).(*array.Int64Builder)

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
