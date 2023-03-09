import os
import time
import tkinter as tk
import tkinter.simpledialog
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from ttkbootstrap.scrolled import ScrolledText
from gui_util import RegisterDisplay
import gui_util
import emulator
import threading
import queue
from colorama import Fore, Back, Style


computer = emulator.Computer()
computer.silent = True


root = ttk.Window(themename="darkly")
#gui_util.register_fonts()
'''
b1 = ttk.Button(root, text="Button", bootstyle=SUCCESS)
b1.pack(side=LEFT, padx=5, pady=5)

b2 = ttk.Button(root, text="Button", bootstyle=INFO)
b2.pack(side=LEFT, padx=5, pady=5)

entry = ScrolledText(state=DISABLED, autohide=True)
entry.text.config(state=NORMAL)
entry.text.tag_configure("no_tag_at_all", foreground="red", background="blue", font=("Arial", 12, "italic"))
entry.insert(END, "TEST\ntest", "no_tag_at_all")
entry.insert(2.2, "hello")
entry.text.config(state=DISABLED)
entry.pack()'''

internals_frame = ttk.Frame(root)

registers_frame = ttk.Frame(internals_frame)
register_displays = []

for i in range(17):
    rd = RegisterDisplay(registers_frame, f"REGI", f"IIII")
    rd.pack(side=LEFT, padx=3, pady=3)
    register_displays.append(rd)

registers_frame.pack(side=TOP)

memdump_frame = ttk.LabelFrame(internals_frame, text="Memory", bootstyle=INFO)

#memdump_text = ScrolledText(memdump_frame, state=DISABLED, autohide=True)
#memdump_text.text.config(font=gui_util.get_font_extended(13))

memdump_text = ScrolledText(memdump_frame, state=DISABLED, autohide=True)
memdump_text.text.config(font=gui_util.get_font_extended(13))

memdump_text.pack(fill=BOTH, expand=True)

memdump_frame.pack(side=TOP, fill=BOTH, expand=True)

internals_frame.pack(side=LEFT, fill=Y)

console_frame = ttk.Frame(root)

debugger_frame = ttk.LabelFrame(console_frame, text="Debugger I/O", bootstyle=INFO)

console_out = ScrolledText(debugger_frame, state=DISABLED, autohide=True)
console_out.pack(side=TOP,fill=BOTH, expand=True)

console_in = ttk.Entry(debugger_frame, bootstyle=PRIMARY)
console_in.pack(side=BOTTOM, fill=X)

debugger_frame.pack(side=TOP, fill=BOTH, expand=True)

cpu_io_frame = ttk.LabelFrame(console_frame, text="CPU I/O", bootstyle=SUCCESS)

cpu_output_console = ScrolledText(cpu_io_frame, state=DISABLED, autohide=True)
cpu_output_console.text.config(font=gui_util.get_font_extended(13))
cpu_output_console.pack(side=TOP, fill=BOTH, expand=True)

cpu_input_entry = ttk.Entry(cpu_io_frame, bootstyle=PRIMARY, state=DISABLED)
cpu_input_entry.pack(side=BOTTOM, fill=X)

cpu_io_frame.pack(side=BOTTOM, fill=BOTH, expand=True)

console_frame.pack(side=LEFT, fill=BOTH, expand=True)


already_updating = False

_already_initialized = False

def _update_internals_display():
    global already_updating
    global _already_initialized
    if already_updating:
#        print("Skipping")
        return
    already_updating = True
    named = {
        0: "pc",
        1: "sp",
        2: "sr",
        3: "cg"
    }
    for i in range(16):
        label = ""
        if 3 < i < 10:
            label += "0"
        if i in named:
            label += named[i]
            label += "_" + str(i)
        else:
            label += str(i) + "  "
        register_displays[i].label = label
        register_displays[i].value = f"{computer.registers[i].get_word():04x}"

    register_displays[16].label = "FLAG"
    val = ""
    for name, value in [("N", computer.sr.n), ("Z", computer.sr.z), ("C", computer.sr.c), ("V", computer.sr.v)]:
        if value:
            val += name
        else:
            val += "_"
    register_displays[16].value = val

    memdump_text.text.config(state=NORMAL)
#    memdump_text.text.delete(1.0, END)
    #fill text with replace instead of delete, so that it smoothly updates
    if not _already_initialized:
        _already_initialized = True
        print("Initializing")
        for i in range(0, len(computer.memory), 0x10):
            memdump_text.text.replace(f"{i+1}.0", f"{i+1}.0", "\n")
    vertical_idx = 0
    for i in range(0, len(computer.memory), 0x10):
        vertical_idx += 1
        line = ""
        line += f"{i:04x}: "
        for j in range(0x10):
            line += f"{computer.memory[i+j]:02x}"
            if j % 2 == 1:
                line += " "
        line += "  "
        for j in range(0x10):
            if 0x20 <= computer.memory[i + j] <= 0x7e:
                line += chr(computer.memory[i+j])
            else:
                line += "."
        # memdump_text.text.replace(f"{vertical_idx}.{line_idx}", f"{vertical_idx}.{line_idx+1}", "\n")
        memdump_text.text.replace(f"{vertical_idx}.0", f"{vertical_idx}.{len(line)}", line)
    memdump_text.text.configure(state=DISABLED)
    already_updating = False


def update_internals_display():
    prev_time = time.time()
    wait_amt = 200 / 1000
    while True:
        _update_internals_display()
        time_passed = time.time() - prev_time
        if time_passed < wait_amt:
            time.sleep(wait_amt - time_passed)
        prev_time = time.time()


threading.Thread(target=update_internals_display, daemon=True).start()


execution_cmd = None
execution_cmd_lock = threading.Lock()

sleep_time = 0.1


def execution_loop():
    global execution_cmd
    global sleep_time
    steps_todo = 0
    while True:
        time.sleep(sleep_time)
        steps = None
        forever = False
        stop = False
        with execution_cmd_lock:
            if execution_cmd is not None:
                if execution_cmd == "run":
                    forever = True
                elif execution_cmd == "stop":
                    stop = True
                elif type(execution_cmd) == int:
                    steps = execution_cmd
                execution_cmd = None
        if stop:
            steps_todo = 0
        if forever:
            steps_todo = -1
        if steps is not None:
            if steps_todo == -1:
                steps_todo = 0
            steps_todo += steps
        try:
            if steps_todo == -1:
                computer.step()
            if steps_todo > 0:
                computer.step()
                steps_todo -= 1
        except emulator.ExecutionError as e:
            steps_todo = 0
            gui_util.add_to_console(console_out, f"{Fore.RED}Execution Error:\n    {e}{Style.RESET_ALL}", autoscroll=True)


def meta_execution():
    while True:
        execution_thread = threading.Thread(target=execution_loop, daemon=True)
        execution_thread.start()
        execution_thread.join()
        gui_util.add_to_console(console_out, f"{Fore.RED}Execution thread crashed. Restarting...{Style.RESET_ALL}", autoscroll=True)


threading.Thread(target=meta_execution, daemon=True).start()


last_loaded = None


def handle_console_input(event: tk.Event):
    global last_loaded
    global execution_cmd
    global sleep_time

    contents = event.widget.get()
    event.widget.delete(0, END)

    gui_util.add_to_console(console_out, f">> {Fore.GREEN}{contents}", autoscroll=True)

    command = contents.split(" ")[0]
    args = contents.split(" ")[1:]
    commands = ["help", "load", "run", "stop", "step", "reset", "sleep", "set", "exit"]
    if command not in commands:
        gui_util.add_to_console(console_out, f"{Fore.RED}Unknown command '{command}'. Type 'help' for a list of commands.{Style.RESET_ALL}", autoscroll=True)
        return

    if command == "help":
        if len(args) > 1:
            gui_util.add_to_console(console_out, f"{Fore.RED}Too many arguments for command 'help'.\n\tUsage: `help [command]`{Style.RESET_ALL}", autoscroll=True)
            return

        help_msgs = {
            "help": ("[cmd]", "Prints help messages for all commands. If a command is specified, prints the help message for that command."),
            "load": ("[file]", "Loads a program into memory. If a file is specified, loads the program from that file. If no file is specified, loads the program from the file located in the clipboard."),
            "run": ("", "Runs CPU forever."),
            "stop": ("", "Stops CPU."),
            "step": ("[steps]", "Runs CPU for one instruction, or for the specified number of instructions."),
            "reset": ("", "Resets CPU and memory to state at last load."),
            "sleep": ("[time]", "Sets the time between each step in the execution loop. Default is 0.1 seconds. If time is not specified, returns current time."),
            "set": ("reg val", "Sets the value of a register. To use hex, prefix the value with '0x'."),
            "exit": ("", "Exits the emulator.")
        }
        if len(args) == 0:
            gui_util.add_to_console(console_out, f"{Fore.LIGHTYELLOW_EX}Available commands:{Style.RESET_ALL}", autoscroll=True)
            for command, doc in help_msgs.items():
                arg_str, text_doc = doc
                arg_str_final = ""
                if arg_str != "":
                    arg_str_final = f" {Fore.BLUE}{arg_str}{Fore.LIGHTWHITE_EX}"
                gui_util.add_to_console(console_out, f"  {Style.BRIGHT}{Fore.LIGHTWHITE_EX}{command}{arg_str_final}{Style.NORMAL}: {text_doc}{Style.RESET_ALL}", autoscroll=True)
        else:
            command = args[0]
            if command not in help_msgs:
                gui_util.add_to_console(console_out, f"{Fore.RED}Unknown command '{command}'. Type 'help' for a list of commands.{Style.RESET_ALL}", autoscroll=True)
                return
            arg_str, text_doc = help_msgs[command]
            arg_str_final = ""
            if arg_str != "":
                arg_str_final = f" {Fore.BLUE}{arg_str}{Fore.LIGHTWHITE_EX}"
            gui_util.add_to_console(console_out, f"{Style.BRIGHT}{Fore.LIGHTWHITE_EX}{command}{arg_str_final}{Style.NORMAL}: {text_doc}{Style.RESET_ALL}", autoscroll=True)
    elif command == "load":
        if len(args) > 1:
            gui_util.add_to_console(console_out, f"{Fore.RED}Too many arguments for command 'load'.\n\tUsage: `load [file]`{Style.RESET_ALL}", autoscroll=True)
            return
        with execution_cmd_lock:
            execution_cmd = "stop"
        path = len(args) == 1 and args[0] or root.clipboard_get()
        if not os.path.exists(path):
            gui_util.add_to_console(console_out, f"{Fore.RED}File '{path}' does not exist.{Style.RESET_ALL}", autoscroll=True)
            return
        gui_util.add_to_console(console_out, f"{Fore.LIGHTYELLOW_EX}Loading program from '{path}'...{Style.RESET_ALL}", autoscroll=True)
        with open(path, "rb") as f:
            dat = f.read()
        computer.reset()
        start_addr = int.from_bytes(dat[:2], "big", signed=False)
        for i in range(len(dat) - 2):
            computer.memory[start_addr + i] = dat[i + 2]
        computer.pc.set_word(start_addr)
        last_loaded = dat
        gui_util.add_to_console(console_out, f"{Fore.LIGHTYELLOW_EX}Program loaded.{Style.RESET_ALL}", autoscroll=True)
    elif command == "run":
        if len(args) > 0:
            gui_util.add_to_console(console_out, f"{Fore.RED}Too many arguments for command 'run'.\n\tUsage: `run`{Style.RESET_ALL}", autoscroll=True)
            return
        with execution_cmd_lock:
            execution_cmd = "run"
    elif command == "stop":
        if len(args) > 0:
            gui_util.add_to_console(console_out, f"{Fore.RED}Too many arguments for command 'stop'.\n\tUsage: `stop`{Style.RESET_ALL}", autoscroll=True)
            return
        with execution_cmd_lock:
            execution_cmd = "stop"
    elif command == "step":
        if len(args) > 1:
            gui_util.add_to_console(console_out, f"{Fore.RED}Too many arguments for command 'step'.\n\tUsage: `step [steps]`{Style.RESET_ALL}", autoscroll=True)
            return
        steps = 1
        if len(args) == 1:
            try:
                steps = int(args[0])
            except ValueError:
                gui_util.add_to_console(console_out, f"{Fore.RED}Invalid argument '{args[0]}'. Expected an integer.{Style.RESET_ALL}", autoscroll=True)
                return

        with execution_cmd_lock:
            execution_cmd = steps
    elif command == "reset":
        if len(args) > 0:
            gui_util.add_to_console(console_out, f"{Fore.RED}Too many arguments for command 'reset'.\n\tUsage: `reset`{Style.RESET_ALL}", autoscroll=True)
            return
        with execution_cmd_lock:
            execution_cmd = "stop"
        computer.reset()
        if last_loaded is not None:
            dat = last_loaded
            start_addr = int.from_bytes(dat[:2], "big", signed=False)
            for i in range(len(dat) - 2):
                computer.memory[start_addr + i] = dat[i + 2]
            computer.pc.set_word(start_addr)
    elif command == "sleep":
        if len(args) > 1:
            gui_util.add_to_console(console_out, f"{Fore.RED}Too many arguments for command 'sleep'.\n\tUsage: `sleep time`{Style.RESET_ALL}", autoscroll=True)
            return
        if len(args) == 0:
            gui_util.add_to_console(console_out, f"{Fore.LIGHTYELLOW_EX}Current sleep time is {sleep_time} seconds.{Style.RESET_ALL}", autoscroll=True)
            return
        try:
            sleep_time = float(args[0])
        except ValueError:
            gui_util.add_to_console(console_out, f"{Fore.RED}Invalid argument '{args[0]}'. Expected a number.{Style.RESET_ALL}", autoscroll=True)
            return
    elif command == "set":
        if len(args) != 2:
            gui_util.add_to_console(console_out, f"{Fore.RED}Invalid number of arguments for command 'set'.\n\tUsage: `set register value`{Style.RESET_ALL}", autoscroll=True)
            return
        try:
            value = int(args[1], 0)
        except ValueError:
            gui_util.add_to_console(console_out, f"{Fore.RED}Invalid argument '{args[1]}'. Expected an integer.{Style.RESET_ALL}", autoscroll=True)
            return
        register = args[0].lower()
        mapping = {
            "pc": "r0",
            "sp": "r1",
            "sr": "r2",
            "cg": "r3"
        }
        if register in mapping:
            register = mapping[register]
        register = register.replace("r", "")
        try:
            register = int(register)
        except ValueError:
            gui_util.add_to_console(console_out, f"{Fore.RED}Invalid argument '{args[0]}'. Expected a register.{Style.RESET_ALL}", autoscroll=True)
            return
        if register < 0 or register > 15:
            gui_util.add_to_console(console_out, f"{Fore.RED}Invalid argument '{args[0]}'. Expected a register.{Style.RESET_ALL}", autoscroll=True)
            return
        computer.registers[register].set_word(value)
        gui_util.add_to_console(console_out, f"{Fore.LIGHTYELLOW_EX}Set register r{register} to {value} (0x{value:04X}).{Style.RESET_ALL}", autoscroll=True)
    elif command == "exit":
        if len(args) > 0:
            gui_util.add_to_console(console_out, f"{Fore.RED}Too many arguments for command 'exit'.\n\tUsage: `exit`{Style.RESET_ALL}", autoscroll=True)
            return
        root.destroy()
    else:
        raise Exception("Command not implemented: " + command)
    console_out.text.see(END)


console_in.bind("<Return>", handle_console_input)
gui_util.add_to_console(console_out, f"{Fore.LIGHTYELLOW_EX}Type a command to execute it. Type 'help' for a list of commands.{Style.RESET_ALL}", autoscroll=True)


cpu_input_requests = 0
cpu_input_queue = queue.Queue()


def handle_cpu_io_input(event):
    global cpu_input_requests
    contents = event.widget.get()
    event.widget.delete(0, END)
    event.widget.configure(state=DISABLED)
    if cpu_input_requests <= 0:
        return
    cpu_input_queue.put(contents)
    cpu_input_requests -= 1
    if cpu_input_requests > 0:
        event.widget.configure(state=NORMAL)
cpu_input_entry.bind("<Return>", handle_cpu_io_input)


def cpu_input() -> str:
    global cpu_input_requests
    cpu_input_requests += 1
    cpu_input_entry.configure(state=NORMAL)
    cpu_input_entry.focus()
    while cpu_input_queue.empty():
        time.sleep(0.001)
    return cpu_input_queue.get()


def cpu_output(text: str, end: str = "\n"):
    gui_util.add_to_console(cpu_output_console, text, end=end, autoscroll=True)


computer.input_function = cpu_input
computer.output_function = cpu_output


def scroll_to(event):
    val = tk.simpledialog.askstring("Goto", "Enter a memory address to go to (in hex). To go to the default program start, type `4400`.", parent=root)
    if val is not None:
        val = val.removeprefix("0x")
        if val == "":
            return
        try:
            addr = int(val, 16)
        except ValueError:
            gui_util.add_to_console(console_out, f"{Fore.RED}Invalid address '{val}'.{Style.RESET_ALL}")
            return
        if addr < 0 or addr >= len(computer.memory):
            gui_util.add_to_console(console_out, f"{Fore.RED}Address '{val}' is out of bounds.{Style.RESET_ALL}")
            return
        memdump_text.text.yview_moveto(addr / (len(computer.memory)+16))


root.bind("<Control-Key-g>", scroll_to)


root.mainloop()