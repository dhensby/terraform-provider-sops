package sops

import (
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

type summaryError struct {
	Summary string
	Err     error
}

func (e summaryError) Error() string {
	return fmt.Sprintf("%s: %s", e.Summary, e.Err.Error())
}

func newSummaryError(summary string, err error) summaryError {
	return summaryError{
		Summary: summary,
		Err:     err,
	}
}

func getFileData(sourceFile types.String, inputType types.String) (sopsData, error) {
	sourceFileValue := sourceFile.ValueString()
	content, err := os.ReadFile(sourceFileValue)
	if err != nil {
		return sopsData{}, newSummaryError("Error reading file", err)
	}

	var format string
	if !inputType.IsNull() {
		format = inputType.ValueString()
	} else {
		switch ext := path.Ext(sourceFileValue); ext {
		case ".json":
			format = "json"
		case ".yaml", ".yml":
			format = "yaml"
		case ".env":
			format = "dotenv"
		case ".ini":
			format = "ini"
		default:
			return sopsData{}, newSummaryError("Unknown file type", fmt.Errorf("Don't know how to decode file with extension %s, set input_type as appropriate", ext))
		}
	}

	if err := validateInputType(format); err != nil {
		return sopsData{}, newSummaryError("Invalid input type", err)
	}

	result, err := readData(content, format)
	if err != nil {
		return sopsData{}, newSummaryError("Error reading data", err)
	}
	return result, nil
}

func getExternalData(source types.String, inputType types.String) (sopsData, error) {
	content, err := io.ReadAll(strings.NewReader(source.ValueString()))
	if err != nil {
		return sopsData{}, newSummaryError("Error reading source", err)
	}

	format := inputType.ValueString()
	if err := validateInputType(format); err != nil {
		return sopsData{}, newSummaryError("Invalid input type", err)
	}

	result, err := readData(content, format)
	if err != nil {
		return sopsData{}, newSummaryError("Error reading data", err)
	}

	return result, nil
}
