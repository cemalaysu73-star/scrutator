def wrap_data(text: str) -> str:
    """Fence untrusted text. Delimiter look-alikes inside the text are neutralised so
    collected content cannot close the fence and masquerade as instructions."""
    safe = text.replace("</data>", "<\\/data>").replace("<data>", "<\\data>")
    return f"<data>\n{safe}\n</data>"
