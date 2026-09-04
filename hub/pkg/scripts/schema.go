package scripts

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

const (
	MaxParamSchemaBytes      = 8192  // 8 KiB max schema JSON
	MaxParamTotalValuesBytes = 16384 // 16 KiB max total parameter values
)

var (
	ErrInvalidSchema    = errors.New("invalid parameter schema")
	ErrInvalidParameter = errors.New("invalid parameter value")
	ErrUnknownParameter = errors.New("parameter not defined in schema")
	ErrMissingParameter = errors.New("missing required parameter")

	paramNameRe = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)
)

// ParameterDef defines a strongly-typed parameter in a script version schema.
type ParameterDef struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"` // "string", "number", "boolean", "enum"
	Description string   `json:"description,omitempty"`
	Required    bool     `json:"required,omitempty"`
	Default     string   `json:"default,omitempty"`
	EnumValues  []string `json:"enum_values,omitempty"`
	Enum        []string `json:"enum,omitempty"`
	Pattern     string   `json:"pattern,omitempty"`
}

// ParameterSchema wraps a list of parameter definitions.
type ParameterSchema struct {
	Parameters []ParameterDef `json:"parameters"`
}

// ValidateSchema parses and validates a raw JSON parameter schema.
func ValidateSchema(rawJSON string) (*ParameterSchema, error) {
	trimmed := strings.TrimSpace(rawJSON)
	if trimmed == "" {
		return nil, nil
	}

	if len(trimmed) > MaxParamSchemaBytes {
		return nil, fmt.Errorf("%w: schema exceeds %d bytes", ErrInvalidSchema, MaxParamSchemaBytes)
	}

	var schema ParameterSchema
	if err := json.Unmarshal([]byte(trimmed), &schema); err != nil {
		return nil, fmt.Errorf("%w: json parse error: %v", ErrInvalidSchema, err)
	}

	seenNames := make(map[string]bool)
	for i, p := range schema.Parameters {
		if !paramNameRe.MatchString(p.Name) {
			return nil, fmt.Errorf("%w: parameter[%d] invalid name %q (must match ^[a-zA-Z0-9_-]{1,64}$)", ErrInvalidSchema, i, p.Name)
		}
		if seenNames[p.Name] {
			return nil, fmt.Errorf("%w: duplicate parameter name %q", ErrInvalidSchema, p.Name)
		}
		seenNames[p.Name] = true

		switch p.Type {
		case "string":
			if p.Pattern != "" {
				if _, err := regexp.Compile(p.Pattern); err != nil {
					return nil, fmt.Errorf("%w: parameter %q invalid regex pattern %q: %v", ErrInvalidSchema, p.Name, p.Pattern, err)
				}
			}
		case "number":
			if p.Default != "" {
				if _, err := strconv.ParseFloat(p.Default, 64); err != nil {
					return nil, fmt.Errorf("%w: parameter %q default %q is not a valid number", ErrInvalidSchema, p.Name, p.Default)
				}
			}
		case "boolean":
			if p.Default != "" {
				d := strings.ToLower(p.Default)
				if d != "true" && d != "false" && d != "1" && d != "0" {
					return nil, fmt.Errorf("%w: parameter %q default %q is not a valid boolean", ErrInvalidSchema, p.Name, p.Default)
				}
			}
		case "enum":
			if len(p.EnumValues) == 0 && len(p.Enum) > 0 {
				p.EnumValues = p.Enum
				schema.Parameters[i].EnumValues = p.Enum
			}
			if len(p.EnumValues) == 0 {
				return nil, fmt.Errorf("%w: parameter %q enum requires at least one enum_value", ErrInvalidSchema, p.Name)
			}
			enumMap := make(map[string]bool)
			for _, ev := range p.EnumValues {
				if ev == "" {
					return nil, fmt.Errorf("%w: parameter %q enum contains empty value", ErrInvalidSchema, p.Name)
				}
				enumMap[ev] = true
			}
			if p.Default != "" && !enumMap[p.Default] {
				return nil, fmt.Errorf("%w: parameter %q default %q is not in enum_values", ErrInvalidSchema, p.Name, p.Default)
			}
		default:
			return nil, fmt.Errorf("%w: parameter %q unsupported type %q (allowed: string, number, boolean, enum)", ErrInvalidSchema, p.Name, p.Type)
		}
	}

	return &schema, nil
}

// ValidateParameters checks caller-supplied parameter values against a declared schema.
func ValidateParameters(schema *ParameterSchema, values map[string]string) error {
	totalBytes := 0
	for k, v := range values {
		totalBytes += len(k) + len(v)
		if strings.ContainsRune(k, '\x00') || strings.ContainsRune(v, '\x00') {
			return fmt.Errorf("%w: parameter %q contains null byte", ErrInvalidParameter, k)
		}
	}
	if totalBytes > MaxParamTotalValuesBytes {
		return fmt.Errorf("%w: total parameter values size %d exceeds limit of %d bytes", ErrInvalidParameter, totalBytes, MaxParamTotalValuesBytes)
	}

	if schema == nil || len(schema.Parameters) == 0 {
		if len(values) > 0 {
			return fmt.Errorf("%w: script does not declare any parameters", ErrUnknownParameter)
		}
		return nil
	}

	declared := make(map[string]ParameterDef)
	for _, p := range schema.Parameters {
		declared[p.Name] = p
	}

	// Reject unknown parameter names (strictly fail-closed allowlist)
	for k := range values {
		if _, ok := declared[k]; !ok {
			return fmt.Errorf("%w: unknown parameter %q", ErrUnknownParameter, k)
		}
	}

	// Validate declared parameters
	for _, p := range schema.Parameters {
		val, exists := values[p.Name]
		if !exists || val == "" {
			if p.Required && p.Default == "" {
				return fmt.Errorf("%w: parameter %q is required", ErrMissingParameter, p.Name)
			}
			continue
		}

		switch p.Type {
		case "number":
			if _, err := strconv.ParseFloat(val, 64); err != nil {
				return fmt.Errorf("%w: parameter %q value %q is not a valid number", ErrInvalidParameter, p.Name, val)
			}
		case "boolean":
			low := strings.ToLower(val)
			if low != "true" && low != "false" && low != "1" && low != "0" {
				return fmt.Errorf("%w: parameter %q value %q is not a valid boolean (expected true/false)", ErrInvalidParameter, p.Name, val)
			}
		case "enum":
			matched := false
			for _, ev := range p.EnumValues {
				if ev == val {
					matched = true
					break
				}
			}
			if !matched {
				return fmt.Errorf("%w: parameter %q value %q is not one of %v", ErrInvalidParameter, p.Name, val, p.EnumValues)
			}
		case "string":
			if p.Pattern != "" {
				matched, err := regexp.MatchString(p.Pattern, val)
				if err != nil || !matched {
					return fmt.Errorf("%w: parameter %q value does not match pattern %q", ErrInvalidParameter, p.Name, p.Pattern)
				}
			}
		}
	}

	return nil
}
