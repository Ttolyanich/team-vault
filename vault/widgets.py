from urllib.parse import urlencode
from django import forms
from django.core.exceptions import ValidationError
from django.urls import reverse


def search_field(field, kind, purpose, **kwargs):
    widget = SearchSelect(kind, purpose, **kwargs)
    widget.choices = field.choices
    field.widget = widget


class SearchSelect(forms.Select):
    """Render just the selected entity, keeping the full queryset for server-side validation."""
    def __init__(self, kind, purpose, *, extra=None, attrs=None):
        self.kind, self.purpose, self.extra = kind, purpose, extra or {}
        super().__init__(attrs)

    def get_context(self, name, value, attrs):
        attrs = {**(attrs or {}), "data-search-select": "", "data-source": reverse("choices") + "?" + urlencode({"kind": self.kind, "purpose": self.purpose, **self.extra})}
        return super().get_context(name, value, attrs)

    def optgroups(self, name, value, attrs=None):
        iterator = self.choices
        if not hasattr(iterator, "queryset"):
            return super().optgroups(name, value, attrs)
        selected = [item for item in value if item not in ("", None)]
        choices = [("", iterator.field.empty_label or "Выберите из списка")]
        if selected:
            try:
                choices.extend((str(item.pk), iterator.field.label_from_instance(item)) for item in iterator.queryset.filter(pk__in=selected))
            except (ValidationError, ValueError):
                pass
        original = self.choices
        self.choices = choices
        try:
            return super().optgroups(name, value, attrs)
        finally:
            self.choices = original
