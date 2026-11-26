using System.Text;
using System.Text.Json;

namespace ThreatIntelAggro;

public static class KqlResponseParser
{
    public static JsonElement Parse(string body, string? mediaType)
    {
        if (mediaType?.Equals("application/json", StringComparison.OrdinalIgnoreCase) == true)
            return ParseEnvelope(body);
        if (mediaType?.Equals("text/event-stream", StringComparison.OrdinalIgnoreCase) != true)
            throw new InvalidOperationException("Validator returned an unsupported content type.");

        var data = new StringBuilder();
        using var reader = new StringReader(body);
        while (reader.ReadLine() is { } line)
        {
            if (line.Length == 0)
            {
                if (data.Length == 0) continue;
                var parsed = TryParseEvent(data.ToString());
                if (parsed.HasValue) return parsed.Value;
                data.Clear();
            }
            else if (line.StartsWith("data:", StringComparison.Ordinal))
            {
                if (data.Length > 0) data.Append('\n');
                var value = line[5..];
                data.Append(value.StartsWith(' ') ? value[1..] : value);
            }
        }
        if (data.Length > 0 && TryParseEvent(data.ToString()) is { } last) return last;
        throw new InvalidOperationException("Validator returned no matching MCP result.");
    }

    private static JsonElement? TryParseEvent(string data)
    {
        using var doc = JsonDocument.Parse(data);
        if (!doc.RootElement.TryGetProperty("id", out var id) || id.ValueKind != JsonValueKind.Number || !id.TryGetInt32(out var requestId) || requestId != 1) return null;
        return ParseEnvelope(data);
    }

    private static JsonElement ParseEnvelope(string data)
    {
        using var envelope = JsonDocument.Parse(data);
        var root = envelope.RootElement;
        if (!root.TryGetProperty("jsonrpc", out var version) || version.GetString() != "2.0" || !root.TryGetProperty("id", out var id) || id.ValueKind != JsonValueKind.Number || !id.TryGetInt32(out var requestId) || requestId != 1 || !root.TryGetProperty("result", out var result) || result.ValueKind != JsonValueKind.Object)
            throw new InvalidOperationException("Validator returned an invalid MCP response.");
        if (result.TryGetProperty("isError", out var error) && error.ValueKind == JsonValueKind.True) throw new InvalidOperationException("Validator MCP call returned an error.");
        JsonElement value;
        if (result.TryGetProperty("structuredContent", out var structured)) value = structured.Clone();
        else
        {
            if (!result.TryGetProperty("content", out var content) || content.ValueKind != JsonValueKind.Array) throw new InvalidOperationException("Validator returned no diagnostics.");
            var text = content.EnumerateArray().FirstOrDefault(x => x.TryGetProperty("text", out _));
            if (text.ValueKind != JsonValueKind.Object || !text.TryGetProperty("text", out var textValue) || textValue.ValueKind != JsonValueKind.String) throw new InvalidOperationException("Validator returned no diagnostics.");
            using var payload = JsonDocument.Parse(textValue.GetString()!);
            value = payload.RootElement.Clone();
        }
        if (value.ValueKind != JsonValueKind.Object) throw new InvalidOperationException("Validator returned invalid diagnostics.");
        if (value.TryGetProperty("valid", out var valid) && valid.ValueKind is not (JsonValueKind.True or JsonValueKind.False)) throw new InvalidOperationException("Validator returned an invalid validity value.");
        if (value.TryGetProperty("state", out var state) && (state.ValueKind != JsonValueKind.String || state.GetString() is not ("valid" or "invalid" or "unavailable" or "unsupported"))) throw new InvalidOperationException("Validator returned an unknown state.");
        if (!value.TryGetProperty("valid", out _) && !value.TryGetProperty("state", out _)) throw new InvalidOperationException("Validator returned no validation state.");
        if (value.TryGetProperty("valid", out valid) && value.TryGetProperty("state", out state) &&
            ((state.GetString() == "valid" && valid.ValueKind == JsonValueKind.False) || (state.GetString() == "invalid" && valid.ValueKind == JsonValueKind.True)))
            throw new InvalidOperationException("Validator returned conflicting validity values.");
        return value;
    }
}
