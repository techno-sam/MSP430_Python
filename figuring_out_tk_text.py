import tkinter as tk

root = tk.Tk()

text = tk.Text(root)
text.pack()

for x in range(10):
    content = f"Line {x+1}"
    text.replace(f"{x+1}.0", f"{x+1}.{len(content)}", content+"\n")


text.replace("2.0", "2.10000", "Hello World!")
text.replace("2.0", "2.10000", "Hello World!")
text.replace("2.0", "2.10000", "Hello World!")
text.replace("3.0", "3.10000", "Hi earth!")

root.mainloop()