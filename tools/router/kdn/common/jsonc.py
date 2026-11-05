"""JSON with comments (Xray accepts JSONC)."""


def strip_json_comments(text):
    """Remove // and /* */ comments outside strings (Xray accepts JSONC)."""
    result = []
    index, length = 0, len(text)
    while index < length:
        char = text[index]
        if char == '"':
            end = index + 1
            while end < length and text[end] != '"':
                end += 2 if text[end] == "\\" else 1
            result.append(text[index:end + 1])
            index = end + 1
        elif text.startswith("//", index):
            end = text.find("\n", index)
            index = length if end < 0 else end
        elif text.startswith("/*", index):
            end = text.find("*/", index + 2)
            result.append(" ")
            index = length if end < 0 else end + 2
        else:
            result.append(char)
            index += 1
    return "".join(result)
