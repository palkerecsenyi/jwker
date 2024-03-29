package util

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
)

func base64Encode(bytes []byte, encoding *base64.Encoding) string {
	b64Bytes := make([]byte, base64.StdEncoding.EncodedLen(len(bytes)))
	encoding.Encode(b64Bytes, bytes)
	return string(b64Bytes)
}

func OutputJsonBytes(jsonBytes []byte, format string) (string, error) {
	switch format {
	case "json":
		return string(jsonBytes), nil
	case "base64":
		return base64Encode(jsonBytes, base64.StdEncoding), nil
	case "base64url":
		return base64Encode(jsonBytes, base64.URLEncoding), nil
	}

	return "", fmt.Errorf("unrecognised format: %s", format)
}

func OutputJsonBytesToFile(jsonBytes []byte, format string, file string) error {
	finalString, err := OutputJsonBytes(jsonBytes, format)
	if err != nil {
		return fmt.Errorf("convert to desired output: %s", err)
	}

	fileToWrite := os.Stdout
	if file != "" {
		_, err := os.Stat(file)
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("refusing to write to existing file")
		}

		fileToWrite, err = os.OpenFile(file, os.O_RDWR|os.O_CREATE, 0600)
		if err != nil {
			return fmt.Errorf("open file: %s", err)
		}
	}

	_, err = fileToWrite.WriteString(finalString)
	if err != nil {
		return fmt.Errorf("write to file: %s", err)
	}

	if fileToWrite == os.Stdout {
		_, err = fileToWrite.WriteString("\n")
		if err != nil {
			return fmt.Errorf("write newline to stdout: %s", err)
		}
	}

	return nil
}
