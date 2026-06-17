package sops

import (
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"time"

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

// resolveFileFormat reads a file from disk and determines the sops format to use,
// either from an explicit input_type or by inferring it from the file extension.
func resolveFileFormat(sourceFile types.String, inputType types.String) (content []byte, format string, err error) {
	sourceFileValue := sourceFile.ValueString()
	content, err = os.ReadFile(sourceFileValue)
	if err != nil {
		return nil, "", newSummaryError("Error reading file", err)
	}

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
			return nil, "", newSummaryError("Unknown file type", fmt.Errorf("Don't know how to decode file with extension %s, set input_type as appropriate", ext))
		}
	}

	if err := validateInputType(format); err != nil {
		return nil, "", newSummaryError("Invalid input type", err)
	}
	return content, format, nil
}

// resolveExternalFormat reads encrypted content from a string and validates the
// explicitly-provided input_type.
func resolveExternalFormat(source types.String, inputType types.String) (content []byte, format string, err error) {
	content, err = io.ReadAll(strings.NewReader(source.ValueString()))
	if err != nil {
		return nil, "", newSummaryError("Error reading source", err)
	}

	format = inputType.ValueString()
	if err := validateInputType(format); err != nil {
		return nil, "", newSummaryError("Invalid input type", err)
	}
	return content, format, nil
}

func getFileData(sourceFile types.String, inputType types.String) (sopsData, error) {
	content, format, err := resolveFileFormat(sourceFile, inputType)
	if err != nil {
		return sopsData{}, err
	}

	result, err := readData(content, format)
	if err != nil {
		return sopsData{}, newSummaryError("Error reading data", err)
	}
	return result, nil
}

func getExternalData(source types.String, inputType types.String) (sopsData, error) {
	content, format, err := resolveExternalFormat(source, inputType)
	if err != nil {
		return sopsData{}, err
	}

	result, err := readData(content, format)
	if err != nil {
		return sopsData{}, newSummaryError("Error reading data", err)
	}
	return result, nil
}

// getFileMetadata reads only the sops metadata of a file without decrypting it.
func getFileMetadata(sourceFile types.String, inputType types.String) (time.Time, error) {
	content, format, err := resolveFileFormat(sourceFile, inputType)
	if err != nil {
		return time.Time{}, err
	}

	lastModified, err := readMetadata(content, format)
	if err != nil {
		return time.Time{}, err
	}
	return lastModified, nil
}

// getExternalMetadata reads only the sops metadata of a string without decrypting it.
func getExternalMetadata(source types.String, inputType types.String) (time.Time, error) {
	content, format, err := resolveExternalFormat(source, inputType)
	if err != nil {
		return time.Time{}, err
	}

	lastModified, err := readMetadata(content, format)
	if err != nil {
		return time.Time{}, err
	}
	return lastModified, nil
}
