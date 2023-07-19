from tree_sitter import Node
from Patches.Patch import Patch


class UseMarkup(Patch):
    """
    Patch   UseMarkup
    to      getUseMarkup()
    """

    def __init__(self, priority: int):
        super().__init__(priority)

    def get_search_pattern(self) -> str:
        return '((identifier) @use_markup (#eq? @use_markup "UseMarkup"))'

    def get_main_capture_name(self) -> str:
        return "use_markup"

    def get_patch(self, captures: [(Node, str)], src: bytes, **kwargs) -> bytes:
        return b"getUseMarkup()"
