from django import template

register = template.Library()


@register.filter
def get_item(dictionary, key):
    """
    Template filter to get an item from a dictionary by key.
    Usage: {{ mydict|get_item:key_variable }}
    """
    if dictionary is None:
        return None
    return dictionary.get(key, "")
