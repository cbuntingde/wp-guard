package logger

import (
	"encoding/json"
	"os"
	"time"
)

type Level string

const (
	LevelInfo  Level = "info"
	LevelWarn Level = "warn"
	LevelError Level = "error"
	LevelDebug Level = "debug"
)

type JSONLogger struct {
	output *os.File
}

func New(path string) (*JSONLogger, error) {
	if path == "" {
		return &JSONLogger{output: os.Stdout}, nil
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	return &JSONLogger{output: f}, nil
}

func (l *JSONLogger) Close() error {
	if l.output != os.Stdout {
		return l.output.Close()
	}
	return nil
}

func (l *JSONLogger) Log(level Level, msg string, fields map[string]interface{}) {
	entry := map[string]interface{}{
		"timestamp": time.Now().Format(time.RFC3339),
		"level":     level,
		"message":  msg,
	}
	for k, v := range fields {
		entry[k] = v
	}

	data, _ := json.Marshal(entry)
	l.output.Write(append(data, '\n'))
}

func (l *JSONLogger) Info(msg string, fields ...interface{}) {
	l.Log(LevelInfo, msg, pairs(fields))
}

func (l *JSONLogger) Warn(msg string, fields ...interface{}) {
	l.Log(LevelWarn, msg, pairs(fields))
}

func (l *JSONLogger) Error(msg string, fields ...interface{}) {
	l.Log(LevelError, msg, pairs(fields))
}

func (l *JSONLogger) Debug(msg string, fields ...interface{}) {
	l.Log(LevelDebug, msg, pairs(fields))
}

func pairs(fields []interface{}) map[string]interface{} {
	m := make(map[string]interface{})
	for i := 0; i < len(fields); i += 2 {
		if i+1 < len(fields) {
			if k, ok := fields[i].(string); ok {
				m[k] = fields[i+1]
			}
		}
	}
	return m
}