import os
import shutil
import tempfile
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

def generate_hash(path_to_file, hash_length=7):
    try:
        # Create a temporary copy of the file
        temp_dir = tempfile.mkdtemp()
        temp_file_path = os.path.join(
            temp_dir, 
            os.path.basename(path_to_file)
        )
        shutil.copy2(path_to_file, temp_file_path)

        # Initialize the hash object
        hash_obj = hashlib.sha256()

        # Open the temporary file in binary mode and read it in chunks
        with open(temp_file_path, 'rb') as f:
            while chunk := f.read(8192):
                hash_obj.update(chunk)

        # Clean up the temporary file
        os.remove(temp_file_path)
        os.rmdir(temp_dir)

        # Return the shortened hexadecimal representation of the hash
        return hash_obj.hexdigest()[:hash_length]  # Shorten the hash to the specified length
    except PermissionError:
        messagebox.showerror(
            "Permission Error", 
            f"Permission denied: '{path_to_file}'"
        )
        return None

def traverse_folder(folder_path):
    file_hashes = []
    for root, _, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            hash_value = generate_hash(file_path, hash_length.get())
            if hash_value:
                file_hashes.append((root, file, hash_value))
    return file_hashes

def select_folder():
    global selected_folder
    selected_folder = filedialog.askdirectory(
        initialdir=os.path.expanduser("~")
    )
    folder_label.config(
        text=f"Selected Folder: {selected_folder}" if selected_folder else "Selected Folder: None"
    )
    if selected_folder:
        check_hash_button.config(state=tk.NORMAL)

def select_file():
    global selected_file
    selected_file = filedialog.askopenfilename(
        initialdir=os.path.expanduser("~")
    )
    file_label.config(
        text=f"Selected File: {selected_file}" if selected_file else "Selected File: None"
    )
    if selected_file:
        check_hash_button.config(state=tk.NORMAL)

def check_hash():
    global file_hashes
    if selected_folder:
        file_hashes = traverse_folder(selected_folder)
    elif selected_file:
        file_hashes = [
            (
                os.path.dirname(selected_file), 
                os.path.basename(selected_file), 
                generate_hash(selected_file, hash_length.get())
            )
        ]
    else:
        messagebox.showerror("Error", "No folder or file selected")
        return

    display_hashes(file_hashes)
    if autosave_var.get():
        save_report(file_hashes)
    else:
        save_as_button.config(state=tk.NORMAL)

def display_hashes(file_hashes):
    for item in tree.get_children():
        tree.delete(item)
    
    folder_dict = {}
    for root, file, hash_value in file_hashes:
        parts = root.split(os.sep)
        parent = ''
        for part in parts:
            if parent:
                parent = os.path.join(parent, part)
            else:
                parent = part
            if parent not in folder_dict:
                parent_id = folder_dict.get(os.path.dirname(parent), '')
                folder_dict[parent] = tree.insert(
                    parent_id, 
                    'end', 
                    text=part, 
                    open=True, 
                    tags=('bold',)
                )
        tree.insert(
            folder_dict[root], 
            'end', 
            text='', 
            values=(file, hash_value)
        )

def save_report(file_hashes, report_path=None):
    if not report_path:
        report_path = os.path.join(os.getcwd(), "hash_report.txt")
    with open(report_path, 'w') as report_file:
        for root, file, hash_value in file_hashes:
            report_file.write(f"Folder: {root}\n")
            report_file.write(f"File: {file}\n")
            report_file.write(f"Hash: {hash_value}\n")
            report_file.write("\n")
    messagebox.showinfo("Report Saved", f"Report saved to {report_path}")

def save_as():
    report_path = filedialog.asksaveasfilename(
        initialdir="C://", 
        defaultextension=".txt", 
        filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
    )
    if report_path:
        save_report(file_hashes, report_path)

def toggle_save_as_button():
    if autosave_var.get():
        save_as_button.config(state=tk.DISABLED)
    else:
        save_as_button.config(state=tk.NORMAL if file_hashes else tk.DISABLED)

# Set up the main application window
root = tk.Tk()
root.title("Document Hash Check")
root.geometry("552x455")  # Set the initial window size

# Create buttons to select the folder and file
select_folder_button = tk.Button(
    root, 
    text="Select Folder", 
    command=select_folder
)
select_folder_button.place(
    x=10, 
    y=10, 
    width=91, 
    height=24
)

select_file_button = tk.Button(
    root, 
    text="Select File", 
    command=select_file
)
select_file_button.place(
    x=10, 
    y=40, 
    width=91, 
    height=24
)

# Create a "Check Hash" button
check_hash_button = tk.Button(
    root, 
    text="Check Hash", 
    command=check_hash, 
    state=tk.DISABLED
)
check_hash_button.place(
    x=420, 
    y=10, 
    width=101, 
    height=61
)

# Create a checkbox for autosave report
autosave_var = tk.BooleanVar()
autosave_checkbox = ttk.Checkbutton(
    root, 
    text="Autosave report", 
    variable=autosave_var, 
    command=toggle_save_as_button
)
autosave_checkbox.place(
    x=120, 
    y=90, 
    width=111, 
    height=20
)

# Create a "Save as..." button
save_as_button = ttk.Button(
    root, 
    text="Save as...", 
    command=save_as, 
    state=tk.DISABLED
)
save_as_button.place(
    x=430, 
    y=90, 
    width=81, 
    height=24
)

# Add a dropdown list to select the hash length
hash_length_label = tk.Label(
    root, 
    text="Hash Length", 
    anchor="w"
)
hash_length_label.place(
    x=10, 
    y=70, 
    width=81, 
    height=21
)

hash_length = tk.IntVar(value=7)
hash_length_dropdown = ttk.Combobox(
    root, 
    textvariable=hash_length, 
    values=[7, 8, 9, 10, 11, 12, 13, 14, 15]
)
hash_length_dropdown.place(
    x=10, 
    y=90, 
    width=91, 
    height=22
)

# Add labels to display the selected folder and file
folder_label = tk.Label(
    root, 
    text="Selected Folder: None", 
    anchor="w", 
    relief=tk.SUNKEN
)
folder_label.place(
    x=120, 
    y=10, 
    width=281, 
    height=21
)

file_label = tk.Label(
    root, 
    text="Selected File: None", 
    anchor="w", 
    relief=tk.SUNKEN
)
file_label.place(
    x=120, 
    y=40, 
    width=281, 
    height=21
)

# Create a Treeview widget to display the folder structure and hash values
tree = ttk.Treeview(
    root, 
    columns=("Name", "Hash"), 
    show="tree headings"
)
tree.heading("#0", text="Folder Structure")
tree.heading("Name", text="File Name")
tree.heading("Hash", text="Hash Value")
tree.column("#0", stretch=tk.YES)
tree.column("Name", stretch=tk.YES)
tree.column("Hash", width=100, anchor='center')  # Set the hash column width and center align
tree.place(
    x=20, 
    y=120, 
    width=511, 
    height=291
)

# Define a custom tag for bold text
tree.tag_configure(
    'bold', 
    font=('TkDefaultFont', 10, 'bold')
)

# Create a vertical scrollbar for the Treeview
vsb = ttk.Scrollbar(
    root, 
    orient="vertical", 
    command=tree.yview
)
vsb.place(
    x=531, 
    y=120, 
    height=291
)
tree.configure(yscrollcommand=vsb.set)

# Initialize the file_hashes variable
file_hashes = []

# Run the application
root.mainloop()