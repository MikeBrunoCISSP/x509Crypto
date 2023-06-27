using System.Collections;
using System.Text.Json;

namespace Org.X509Crypto;
internal static class DataSerializer {
    internal static string SerializeObject(object obj) => JsonSerializer.Serialize(obj);

    internal static TDto DeserializeObject<TDto>(string json, bool nullsafe) {
        if (!nullsafe) {
            return JsonSerializer.Deserialize<TDto>(json);
        }
        if (typeof(TDto).IsAssignableFrom(typeof(IEnumerable))) {
            return JsonSerializer.Deserialize<TDto>(string.IsNullOrWhiteSpace(json)
            ? "[]"
            : json);
        }

        return JsonSerializer.Deserialize<TDto>(string.IsNullOrWhiteSpace(json)
        ? "{}"
        : json);
    }
}
