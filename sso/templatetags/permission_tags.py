"""
Template tags for RBAC permission matrix display.
"""

from django import template

register = template.Library()


@register.simple_tag
def is_permission_set(current_perms, feature_id, permission_id):
    """
    Check if a permission is set for a feature.

    Usage in template:
        {% is_permission_set current_perms feature.id permission.id as is_checked %}
        {% if is_checked %}checked{% endif %}

    Args:
        current_perms: Dict mapping feature_id -> set of permission_ids
        feature_id: The feature ID to check
        permission_id: The permission ID to check

    Returns:
        bool: True if permission is set for this feature
    """
    feature_perms = current_perms.get(feature_id, set())
    return permission_id in feature_perms
