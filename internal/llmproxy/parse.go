package llmproxy

import (
	"encoding/json"
	"strings"
)

// usage holds token counts pulled from an LLM response.
type usage struct {
	InputTokens  int
	OutputTokens int
}

// textFromContent extracts text from a chat "content" field, which may be a
// plain string (OpenAI) or an array of typed parts (Anthropic, multimodal).
func textFromContent(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var parts []struct {
		Text string `json:"text"`
	}
	if json.Unmarshal(raw, &parts) == nil {
		var b strings.Builder
		for _, p := range parts {
			b.WriteString(p.Text)
			b.WriteByte('\n')
		}
		return b.String()
	}
	return ""
}

// extractPrompt concatenates the system prompt and all message contents from a
// request body. It is provider-agnostic: it understands OpenAI chat
// completions, Anthropic messages (with a top-level system field), and legacy
// completion prompts.
func extractPrompt(body []byte) string {
	var req struct {
		System   json.RawMessage `json:"system"`
		Messages []struct {
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
		Prompt string `json:"prompt"`
	}
	if json.Unmarshal(body, &req) != nil {
		return ""
	}
	var b strings.Builder
	if t := textFromContent(req.System); t != "" {
		b.WriteString(t)
		b.WriteByte('\n')
	}
	for _, m := range req.Messages {
		b.WriteString(textFromContent(m.Content))
		b.WriteByte('\n')
	}
	b.WriteString(req.Prompt)
	return b.String()
}

// extractResponseText pulls the assistant's text out of a response body for
// both OpenAI (choices[].message.content / choices[].text) and Anthropic
// (content[].text) shapes.
func extractResponseText(body []byte) string {
	var r struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
			Text string `json:"text"`
		} `json:"choices"`
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if json.Unmarshal(body, &r) != nil {
		return ""
	}
	var b strings.Builder
	for _, c := range r.Choices {
		b.WriteString(c.Message.Content)
		b.WriteString(c.Text)
		b.WriteByte('\n')
	}
	for _, c := range r.Content {
		b.WriteString(c.Text)
		b.WriteByte('\n')
	}
	return b.String()
}

// extractUsage reads token usage from a response, supporting both OpenAI
// (prompt_tokens/completion_tokens) and Anthropic (input_tokens/output_tokens).
func extractUsage(body []byte) usage {
	var u struct {
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
			InputTokens      int `json:"input_tokens"`
			OutputTokens     int `json:"output_tokens"`
		} `json:"usage"`
	}
	_ = json.Unmarshal(body, &u)
	in := u.Usage.PromptTokens
	if in == 0 {
		in = u.Usage.InputTokens
	}
	out := u.Usage.CompletionTokens
	if out == 0 {
		out = u.Usage.OutputTokens
	}
	return usage{InputTokens: in, OutputTokens: out}
}

// extractModel returns the requested model name.
func extractModel(body []byte) string {
	var r struct {
		Model string `json:"model"`
	}
	_ = json.Unmarshal(body, &r)
	return r.Model
}

// isStreaming reports whether the request asked for a streamed response.
func isStreaming(body []byte) bool {
	var r struct {
		Stream bool `json:"stream"`
	}
	_ = json.Unmarshal(body, &r)
	return r.Stream
}
