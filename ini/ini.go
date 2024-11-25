package ini

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// IniConfig maps a section to a map of keys and values
type IniConfig map[string]map[string]string

// NewIniConfig returns a new empty IniConfig map that can be used to store the data of an ini file.
func NewIniConfig() IniConfig {
	return make(IniConfig)
}

// ParseIniData parses the data of an ini file and returns it into an IniConfig format, which is a map of sections to a map of keys and values.
// If the ini has no sections, then the keys and values are added to a default section called "Settings"
func ParseIniData(iniContent []byte) (IniConfig, error) {
	config := newDefaultIniConfig()

	// The current section that is being processed is the default section called "Settings" until a new section is found
	currentSection := "Settings"

	// Turn iniContent into an io.Reader so that it can be read line by line
	ioReader := bytes.NewReader(iniContent)

	// Create a scanner to read the ini file line by line
	scanner := bufio.NewScanner(ioReader)

	scanner.Split(bufio.ScanLines)
	// Loop through the ini file line by line and parse it
	for scanner.Scan() {
		line := scanner.Text()
		var err error
		currentSection, err = processIniLine(line, &config, currentSection, scanner)
		if err != nil {
			return nil, err
		}
	}

	// Check if there was an error while reading the ini file
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// Check if other sections were added, and remove the default "Settings" section if necessary
	if len(config) > 1 {
		delete(config, "Settings")
	}

	return config, nil
}

// newDefaultIniConfig initializes an IniConfig with a default "Settings" section.
func newDefaultIniConfig() IniConfig {
	config := NewIniConfig()

	// Add a default section called "Settings" so that if the ini file has no sections, the keys and values are added to this section
	config["Settings"] = make(map[string]string)
	return config
}

// processIniLine processes a single line from the ini content and updates the config and current section accordingly.
func processIniLine(line string, config *IniConfig, currentSection string, scanner *bufio.Scanner) (string, error) {
	line = strings.TrimSpace(line)

	// Ignore comments and empty lines in the ini file
	if strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") || line == "" {
		return currentSection, nil
	}

	// If the line starts and ends with brackets, then it's a section
	if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
		currentSection = strings.TrimSpace(line[1 : len(line)-1])
		return handleSectionLine(line, config, currentSection)
	}

	return handleKeyValueLine(line, config, currentSection, scanner)
}

// handleSectionLine processes a section line and updates the current section and config map.
func handleSectionLine(line string, config *IniConfig, currentSection string) (string, error) {
	// Get the section name
	sectionName := line[1 : len(line)-1]
	if !isValidName(sectionName) {
		return currentSection, fmt.Errorf("invalid section name: %s", sectionName)
	}

	// Check for duplicate sections
	if _, exists := (*config)[sectionName]; exists {
		return currentSection, fmt.Errorf("duplicate section name: %s", sectionName)
	}

	currentSection = sectionName

	// Initialize the map for the new section.
	(*config)[currentSection] = make(map[string]string)
	return currentSection, nil
}

// handleKeyValueLine processes a key-value pair line and updates the config map.
func handleKeyValueLine(line string, config *IniConfig, currentSection string, scanner *bufio.Scanner) (string, error) {
	// Split the line into two parts, the key and the value
	parts := strings.SplitN(line, "=", 2)
	if len(parts) != 2 || !isValidName(parts[0]) {
		return currentSection, fmt.Errorf("invalid key-value pair: %s", line)
	}

	key := strings.TrimSpace(parts[0])
	value := removeQuotes(strings.TrimSpace(parts[1]))

	// Handle multiline values
	value = handleMultiLineValue(value, scanner)

	// Check for duplicate keys within the same section
	if _, exists := (*config)[currentSection][key]; exists {
		return currentSection, fmt.Errorf("duplicate key '%s' in section [%s]", key, currentSection)
	}

	// Set the key-value pair in the current section
	(*config)[currentSection][key] = value
	return currentSection, nil
}

// handleMultiLineValue processes and returns the full value if it spans multiple lines.
func handleMultiLineValue(value string, scanner *bufio.Scanner) string {
	// If a line ends with a backslash (\), treat the next line as a continuation of the current value.
	// This is a convention used in some INI-like formats for multiline values.
	for strings.HasSuffix(value, "\\") {
		value = value[:len(value)-1] // Remove trailing backslash
		if scanner.Scan() {
			continuationLine := scanner.Text()
			value += strings.TrimSpace(continuationLine)
		} else {
			break
		}
	}
	return value
}

// isValidName validates section and key names for illegal characters.
func isValidName(name string) bool {
	illegalChars := []string{"=", "[", "]", "\n"}
	for _, char := range illegalChars {
		if strings.Contains(name, char) {
			return false
		}
	}
	return true
}

// removeQuotes is a helper function that removes quotes from a string if it has any.
func removeQuotes(s string) string {
	return strings.Trim(strings.Trim(s, `'`), `"`)
}

// ParseIniFile parses an ini file and returns it into an IniConfig format, which is a map of sections to a map of keys and values.
func ParseIniFile(filename string) (IniConfig, error) {
	iniContent, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	return ParseIniData(iniContent)
}

// Keys method that returns all of the keys in the config file
func (c *IniConfig) Keys() []string {
	var keys []string
	for _, keyValueMap := range *c {
		for k := range keyValueMap {
			keys = append(keys, k)
		}
	}
	return keys
}

// Sections method that returns all of the sections in the config file
func (c *IniConfig) Sections() []string {
	var sections []string
	for section := range *c {
		sections = append(sections, section)
	}
	return sections
}

// KeysInSection method that returns all of the keys in a section
func (c *IniConfig) KeysInSection(section string) []string {
	var keys []string
	for k := range (*c)[section] {
		keys = append(keys, k)
	}
	return keys
}

// Set method that sets the value of a key in a section.
// if the section is not provided, it loops over all sections to find the key.
func (c *IniConfig) Set(section, key, value string) error {

	// If the section is provided then set the value
	if section != "" {

		// Ensure the section exists, create it if it doesn't
		if _, ok := (*c)[section]; !ok {
			return fmt.Errorf("section %s does not exist", section)
		}

		// Set the value in the specified section
		(*c)[section][key] = value
		return nil
	}

	// If the section is not provided, loop over all sections to find the key
	for _, keyValueMap := range *c {
		if _, ok := keyValueMap[key]; ok {
			keyValueMap[key] = value
			return nil
		}
	}

	// If the key is not found in any section.
	return fmt.Errorf("key %s not found in any section", key)
}

// Add method that adds a key-value pair to a section.
// If the section provided does not exist, it adds the key-value pair to the section provided.
func (c *IniConfig) Add(section, key, value string) {

	// Ensure the section exists, create it if it doesn't
	if _, ok := (*c)[section]; !ok {
		(*c)[section] = make(map[string]string)
	}

	// Add the key-value pair to the provided section
	(*c)[section][key] = value
}

// getRawValue returns the value of a key in a section.
// If the section is not provided, it loops over all sections to find the key.
func (c *IniConfig) getRawValue(section, key string) (string, error) {

	// If the section is provided then get the value
	if section != "" {

		// Ensure the key exists in the section
		value, ok := (*c)[section][key]
		if ok {
			return value, nil
		}
		return "", fmt.Errorf("key %s not found in section %s", key, section)
	}

	// If the section is not provided, loop over all sections to find the key
	for _, keyValueMap := range *c {
		value, ok := keyValueMap[key]
		if ok {
			return value, nil
		}
	}

	return "", fmt.Errorf("key %s not found in any section", key)
}

// Value returns the value of a key in a section.
// If the section is not provided, it loops over all sections to find the key.
func (c *IniConfig) Value(section, key string) (string, error) {
	return c.getRawValue(section, key)
}

// DeleteKey deletes a key from a section.
func (c *IniConfig) DeleteKey(section, key string) {
	if sectionMap, ok := (*c)[section]; ok {
		delete(sectionMap, key)
	}
}

// DeleteSection deletes an entire section.
func (c *IniConfig) DeleteSection(section string) {
	delete(*c, section)
}

// Int returns the value of a key in a section as an integer.
// If the section is not provided, it loops over all sections to find the key.
func (c *IniConfig) Int(section, key string) (int, error) {
	value, err := c.getRawValue(section, key)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(value)
}

// Bool returns the value of a key in a section as a boolean.
// If the section is not provided, it loops over all sections to find the key.
func (c *IniConfig) Bool(section, key string) (bool, error) {
	value, err := c.getRawValue(section, key)
	if err != nil {
		return false, err
	}
	return strconv.ParseBool(value)
}

// Float returns the value of a key in a section as a float64.
// If the section is not provided, it loops over all sections to find the key.
func (c *IniConfig) Float(section, key string) (float64, error) {
	value, err := c.getRawValue(section, key)
	if err != nil {
		return 0.0, err
	}
	return strconv.ParseFloat(value, 64)
}

// DataAsLines returns all of the lines including sections and keys in the config file while keeping an empty line between sections.
func (c *IniConfig) DataAsLines() string {
	var lines []string
	for section, keyValueMap := range *c {

		// Add the section name to the lines
		if section != "" {
			lines = append(lines, "["+section+"]")
		}

		// Add the keys and values to the lines
		for key, value := range keyValueMap {
			lines = append(lines, key+" = "+value)
		}

		// Add an empty line between sections
		lines = append(lines, "")
	}

	// Remove the last empty line
	return strings.TrimSpace(strings.Join(lines, "\n"))
}
