package api

import (
	"encoding/json"
	"io"

	"github.com/gin-gonic/gin"
)

func requestParams(c *gin.Context) (map[string]string, error) {
	params := map[string]string{}
	for key, values := range c.Request.URL.Query() {
		if len(values) > 0 {
			params[key] = values[0]
		}
	}
	if c.Request.Body == nil {
		return params, nil
	}
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		return nil, err
	}
	if len(body) == 0 {
		return params, nil
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}
	for key, value := range payload {
		switch typed := value.(type) {
		case string:
			params[key] = typed
		case float64:
			bytes, _ := json.Marshal(typed)
			params[key] = string(bytes)
		case bool:
			if typed {
				params[key] = "true"
			} else {
				params[key] = "false"
			}
		}
	}
	return params, nil
}
