import tkinter as tk
import tkinter.ttk
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from ttkbootstrap.scrolled import ScrolledText
import random
from colorama import Fore, Back, Style
#import pyglet
import os
import sys
#from tkinter.font import Font
from tkextrafont import Font

def resource_path(relative_path: str) -> str:
    """ Get absolute path to resource, works for dev and for PyInstaller """
    default = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '.'))
    base_path = getattr(sys, '_MEIPASS', default)
    return os.path.join(base_path, relative_path)


#for variant in ["Bold", "BoldItalic", "Italic", "Regular"]:
#    pyglet.font.add_file(resource_path(os.path.join("assets", "fonts", "FantasqueSansMono-" + variant + ".ttf")))


_extended_fonts = {}

_font_params = {
    "regular": dict(family="Fantasque Sans Mono", file=resource_path(os.path.join("assets", "fonts", "FantasqueSansMono-Regular.ttf"))),
    "bold": dict(family="Fantasque Sans Mono", weight="bold", file=resource_path(os.path.join("assets", "fonts", "FantasqueSansMono-Bold.ttf"))),
    "italic": dict(family="Fantasque Sans Mono", slant="italic", file=resource_path(os.path.join("assets", "fonts", "FantasqueSansMono-Italic.ttf"))),
    "bold_italic": dict(family="Fantasque Sans Mono", weight="bold", slant="italic", file=resource_path(os.path.join("assets", "fonts", "FantasqueSansMono-BoldItalic.ttf")))
}

print(_font_params)


def _get_font_params(bold: bool = False, italic: bool = False) -> dict:
    if bold and italic:
        return _font_params["bold_italic"]
    elif bold:
        return _font_params["bold"]
    elif italic:
        return _font_params["italic"]
    else:
        return _font_params["regular"]


def get_font_extended(size: int, bold: bool = False, italic: bool = False):
    key = (bold, italic)
    if key in _extended_fonts:
        f = _extended_fonts[key]
    else:
        f = Font(**_get_font_params(bold, italic))
        _extended_fonts[key] = f
    sized = f.copy()
    sized.configure(size=size)
    return sized


ansi_fore_to_hex = {
    Fore.BLACK: "#000000",
    Fore.BLUE: "#3993D4",
    Fore.LIGHTBLACK_EX: "#595959",
    Fore.LIGHTBLUE_EX: "#1FB0FF",
    Fore.LIGHTCYAN_EX: "#00E5E5",
    Fore.LIGHTGREEN_EX: "#4FC414",
    Fore.LIGHTMAGENTA_EX: "#ED7EED",
    Fore.LIGHTRED_EX: "#FF4050",
    Fore.LIGHTWHITE_EX: "#FFFFFF",
    Fore.LIGHTYELLOW_EX: "#E5BF00",
    Fore.CYAN: "#00A3A3",
    Fore.GREEN: "#5C962C",
    Fore.MAGENTA: "#A771BF",
    Fore.RED: "#F0524F",
    Fore.WHITE: "#808080",
    Fore.YELLOW: "#A68A0D"
}
ansi_back_to_hex = {
    Back.BLACK: "#000000",
    Back.BLUE: "#245980",
    Back.LIGHTBLACK_EX: "#424242",
    Back.LIGHTBLUE_EX: "#1778BD",
    Back.LIGHTCYAN_EX: "#006E6E",
    Back.LIGHTGREEN_EX: "#458500",
    Back.LIGHTMAGENTA_EX: "#B247B2",
    Back.LIGHTRED_EX: "#B82421",
    Back.LIGHTWHITE_EX: "#FFFFFF",
    Back.LIGHTYELLOW_EX: "#A87B00",
    Back.CYAN: "#154F4F",
    Back.GREEN: "#39511F",
    Back.MAGENTA: "#5C4069",
    Back.RED: "#772E2C",
    Back.WHITE: "#616161",
    Back.YELLOW: "#5C4F17"
}


def ansi_to_hex(ansi):
    try:
        return 0, ansi_fore_to_hex[ansi]
    except KeyError:
        try:
            return 1, ansi_back_to_hex[ansi]
        except KeyError:
            raise AttributeError("Invalid color")


def rgb_to_hex(rgb):
    return '#%02x%02x%02x' % rgb


def uuid() -> str:
    """Generate simple unique id"""
    chars = "1234567890qwertyuiopasdfghjklzxcvbnm"
    out = ""
    for _ in range(16):
        out += random.choice(chars)
    return out


existing_tags: dict[tk.Widget, set] = {}


def tag_from_params(fmt: str, fore_color: str, back_color: str, widget: tk.Text | ScrolledText) -> str:
    """Create a formatting tag from given parameters
    :param fmt: normal, bold, or italic
    :param fore_color: hex color
    :param back_color: hex color
    :param widget: tk.Text or ScrolledText widget to create tag in
    :return: tag id
    """
    name = f"auto,{fmt},{fore_color},{back_color}"#uuid()
    if isinstance(widget, ScrolledText):
        widget = widget.text
    widget: tk.Text
    if widget not in existing_tags:
        existing_tags[widget] = set()
    existing_tags_for_this_widget = existing_tags[widget]
    if name in existing_tags_for_this_widget:
        return name
    if back_color == "None":
        back_color = None
    widget.tag_configure(name,
                         foreground=fore_color,
                         background=back_color,
                         font=get_font_extended(10, bold=(fmt == "bold"), italic=(fmt == "italic")))
    existing_tags_for_this_widget.add(name)
    return name


def add_to_console(console: tk.Text | ScrolledText, string: str, end: str = "\n", autoscroll: bool = False, clear_first: bool = False):
    """Add text to console
    Implements certain ANSI codes:
    colorama.Fore.*
    colorama.Back.*
    colorama.Style.* (Dim is handled as italic)
    NOTE: Style is fully reset at end of text, \r doesn't work
    :param console: text field to write to
    :param string: Text to add
    :param end: String to put at end of text
    :param autoscroll: If true, scroll to bottom of text field
    :param clear_first: If true, clear text field before adding text
    :return: None
    """
    if isinstance(console, ScrolledText):
        console = console.text
    console: tk.Text
    string += end
    # Build formatted segments
    segments = []  # segments of text, split by formatting changes (text, tag)
    segment = ""  # segment of text currently being built
    fmt = "normal"  # normal, bold, or italic
    fore_color = ansi_to_hex(Fore.WHITE)[1]
    back_color = None
    building_ansi = False  # If we are currently inside an ansi escape sequence
    building_text = True  # If we are currently inside of normal text
    ansi_start = "\x1b"
    safe_ansi_start = "\\x1b"
    ansi_end = "m"
    ansi_in_progress = ""
    for char in string:
        if char == ansi_start:  # Ansi start encountered
            # print(segments)
            if building_text:  # We were building a segment of text, add it
                segments.append((segment, tag_from_params(fmt, fore_color, back_color, console)))
                segment = ""

            if building_ansi:
                raise ValueError("Ansi start found while building ansi")

            building_ansi = True
            building_text = False
            ansi_in_progress = ansi_start
            # print(f"Ansi start character found, bt: {building_text}, ba: {building_ansi}")
        elif building_ansi:  # We are in the middle of an ansi escape sequence
            # print(f"Ansi in progress: {ansi_in_progress.replace(ansi_start, safe_ansi_start)}")
            ansi_in_progress += char
            if char == ansi_end:  # Ansi sequence complete
                if ansi_in_progress == Style.NORMAL:
                    fmt = "normal"
                elif ansi_in_progress == Style.BRIGHT:
                    fmt = "bold"
                elif ansi_in_progress == Style.DIM:
                    fmt = "italic"
                elif ansi_in_progress == Style.RESET_ALL:
                    fmt = "normal"
                    fore_color = ansi_to_hex(Fore.WHITE)[1]
                    back_color = None
                elif ansi_in_progress == Fore.RESET:
                    fore_color = ansi_to_hex(Fore.WHITE)[1]
                elif ansi_in_progress == Back.RESET:
                    back_color = None
                else:  # Maybe it is a color
                    try:
                        kind, color = ansi_to_hex(ansi_in_progress)
                        if kind == 0:
                            fore_color = color
                        elif kind == 1:
                            back_color = color
                        else:
                            raise ValueError("kind received other than 0 or 1")
                    except AttributeError:
                        print("Invalid ansi sequence received: "
                              + ansi_in_progress.replace(ansi_start, safe_ansi_start))
                ansi_in_progress = ""
                building_ansi = False
        elif (not building_ansi) and (not building_text):  # We're not in an ansi sequence, and were in one before
            # print("Reached end of escape sequence set")
            building_text = True
        if building_text:
            # print(f"Adding char: {char}")
            segment += char
    # Make sure the last bit isn't ignored
    if building_text:  # We were building a segment of text, add it
        segments.append((segment, tag_from_params(fmt, fore_color, back_color, console)))
        segment = ""

    # Add formatted segments
    console.configure(state=tk.NORMAL)  # We need to be able to write
    if clear_first:
        console.replace("1.0", tk.END, "")
    for text, tag in segments:
        console.insert(tk.END, text, tag)
    console.configure(state=tk.DISABLED)  # User else needs to not write
    # Autoscroll
    if autoscroll:
        console.see("end")


class RegisterDisplay:
    def __init__(self, root: tk.Misc, name: str, address: str):
        self.name = name
        self.address = address
        self.root = root
        self._frame = ttk.Frame(root)
        entry_font = get_font_extended(size=10)
        self._name_entry = ttk.Entry(self._frame, bootstyle=DANGER, width=4, font=entry_font)
        self._address_entry = ttk.Entry(self._frame, bootstyle=WARNING, width=4, font=entry_font)
        self._name_entry.insert(0, name)
        self._address_entry.insert(0, address)
        self._name_entry.grid(row=0, column=0, pady=2)
        self._address_entry.grid(row=1, column=0, pady=2)
        self._name_entry.configure(state=READONLY)
        self._address_entry.configure(state=READONLY)

    def _set_label(self, label: str):
        self._name_entry.configure(state=NORMAL)
        self._name_entry.delete(0, tk.END)
        self._name_entry.insert(0, label)
        self._name_entry.configure(state=READONLY)

    def _set_value(self, address: str):
        self._address_entry.configure(state=NORMAL)
        self._address_entry.delete(0, tk.END)
        self._address_entry.insert(0, address)
        self._address_entry.configure(state=READONLY)

    label = property(fset=_set_label)
    value = property(fset=_set_value)

    def pack(self, *args, **kwargs):
        self._frame.pack(*args, **kwargs)

    def grid(self, *args, **kwargs):
        self._frame.grid(*args, **kwargs)

    def place(self, *args, **kwargs):
        self._frame.place(*args, **kwargs)
