package logger

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"reflect"
	"runtime"
)

// initLogger is initialize zap logger
func initLogger() (*zap.Logger, error) {
	cfg := zap.Config{
		Encoding:         "json",
		OutputPaths:      []string{"stdout"},
		ErrorOutputPaths: []string{"stderr"},
		Level:            zap.NewAtomicLevelAt(zap.DebugLevel),
		EncoderConfig: zapcore.EncoderConfig{
			MessageKey: "message",
			LevelKey:   "level",
			TimeKey:    "time",
			//CallerKey:      "caller",
			EncodeDuration: zapcore.StringDurationEncoder,
			EncodeLevel:    zapcore.LowercaseLevelEncoder,
			EncodeTime:     zapcore.TimeEncoderOfLayout("2006-02-02 15:04:05"),
			EncodeCaller:   zapcore.ShortCallerEncoder,
		},
	}

	return cfg.Build()
}

type logData struct {
	Key   string
	Value interface{}
	Type  string
}

type logMiddleware struct {
	Key   string
	Value string
}

type logTrace struct {
	NumOrder int    `json:"no"`
	Value    string `json:"func"`
}

type Logger struct {
	Log              *zap.Logger
	ArrLogData       []logData
	ArrLogMiddleware []logMiddleware
	ArrLogTrace      []logTrace
}

// NewLogger is initialize logger
func NewLogger() *Logger {
	logger, err := initLogger()
	if err != nil {
		panic(err)
	}

	return &Logger{
		Log: logger,
	}
}

// LoggerMiddleware is middleware for initialize logger from request context
func (t *Logger) LoggerMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		//logger.Info("middleware")

		logMiddleware := []logMiddleware{
			{
				Key:   "method",
				Value: c.Request.Method,
			},
			{
				Key:   "url",
				Value: c.Request.URL.String(),
			},
			{
				Key:   "host",
				Value: c.Request.Host,
			},
			{
				Key:   "ip",
				Value: c.ClientIP(),
			},
		}

		t.ArrLogMiddleware = logMiddleware

		c.Next()
	}
}

// LoggerCleanUp is middleware for clean up logger from request context
func (t *Logger) LoggerCleanUp() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		t.ArrLogData = []logData{}
		t.ArrLogMiddleware = []logMiddleware{}
		t.ArrLogTrace = []logTrace{}

	}
}

// LoggerRecovery is middleware for recovery panic
func (t *Logger) LoggerRecovery() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				t.Log.Error("recovery", zap.Any("error", err))
			}
		}()

		c.Next()
	}
}

// SetSeverityLevel is set severity level
func (t *Logger) SetSeverityLevel(level string) {
	var l zapcore.Level

	switch level {
	case "debug":
		l = zap.DebugLevel
	case "info":
		l = zap.InfoLevel
	case "warn":
		l = zap.WarnLevel
	case "error":
		l = zap.ErrorLevel
	case "fatal":
		l = zap.FatalLevel
	case "panic":
		l = zap.PanicLevel
	default:
		l = zap.DebugLevel
	}

	t.Log = t.Log.WithOptions(zap.IncreaseLevel(l))
}

// L is need parameter message and data.
// Message can be key or information
func (t *Logger) L(message string, data interface{}) {
	l := logData{
		Key: message,
	}

	if data == nil {
		l.Type = "message"
		l.Value = message
	} else {
		l.Type = "payload"
		l.Value = data
	}

	t.ArrLogData = append(t.ArrLogData, l)
}

// Stack is for stack trace, parameter is function name
func (t *Logger) Stack(data interface{}) {
	l := logTrace{
		NumOrder: len(t.ArrLogTrace) + 1,
		Value:    t.getFuncName(data),
	}

	t.ArrLogTrace = append(t.ArrLogTrace, l)
}

// Info is need parameter message
func (t *Logger) Info(message string) {
	logger := t.buildZapLogger(t.Log)

	logger.Info(message)
}

// Error is need parameter message
func (t *Logger) Error(message string) {
	logger := t.buildZapLogger(t.Log)

	logger.Error(message)
}

// buildZapLoggerMiddleware is build zap logger with middleware
func (t *Logger) buildZapLoggerMiddleware(logger *zap.Logger, arrLogMiddleware []logMiddleware) *zap.Logger {
	for _, v := range arrLogMiddleware {
		logger = logger.With(zap.String(v.Key, v.Value))
	}

	return logger
}

// buildZapLoggerField is build zap logger with field
func (t *Logger) buildZapLoggerField(logger *zap.Logger, arrLogData []logData) *zap.Logger {
	for _, v := range arrLogData {
		if v.Type == "message" {
			logger = logger.With(zap.String(v.Key, v.Value.(string)))
		} else {
			logger = logger.With(zap.Any(v.Key, v.Value))
		}
	}

	return logger
}

// buildZapLogger is build all logger
func (t *Logger) buildZapLogger(logger *zap.Logger) *zap.Logger {
	for _, v := range t.ArrLogMiddleware {
		logger = logger.With(zap.String(v.Key, v.Value))
	}

	stackTrace := ""
	for i, v := range t.ArrLogTrace {
		objectStr := fmt.Sprintf(`{"no":%d,"func":"%s"}`, v.NumOrder, v.Value)
		if i == len(t.ArrLogTrace)-1 {
			stackTrace = fmt.Sprintf("%s%s", stackTrace, objectStr)
		} else {
			stackTrace = fmt.Sprintf("%s%s,", stackTrace, objectStr)
		}
	}
	stackTrace = fmt.Sprintf("[%s]", stackTrace)
	logger = logger.With(zap.String("stack_trace", stackTrace))

	for _, v := range t.ArrLogData {
		if v.Type == "message" {
			logger = logger.With(zap.String(v.Key, v.Value.(string)))
		} else {
			logger = logger.With(zap.Any(v.Key, v.Value))
		}
	}

	return logger
}

// buildZapLoggerTrace is build zap logger with trace
func (t *Logger) buildZapLoggerTrace(logger *zap.Logger, arrLogTrace []logTrace) *zap.Logger {

	var stacks []string
	for _, v := range arrLogTrace {
		objectStr := fmt.Sprintf(`{"no":%d,"func":"%s"}`, v.NumOrder, v.Value)
		stacks = append(stacks, objectStr)
	}

	return logger.With(zap.Strings(
		"stack_trace",
		stacks,
	))
}

// getFuncName is get function name for stack trace logger
func (t *Logger) getFuncName(i interface{}) string {
	return runtime.FuncForPC(reflect.ValueOf(i).Pointer()).Name()
}
