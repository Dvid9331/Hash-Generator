import os
import shutil
import tempfile
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

def generate_hash(path_to_file):
    try:
        # Create a temporary copy of the file
        temp_dir = tempfile.mkdtemp()
        temp_file_path = os.path.join(temp_dir, os.path.basename(path_to_file))
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
        return hash_obj.hexdigest()[:7]  # Shorten the hash to 7 characters
    except PermissionError:
        messagebox.showerror("Permission Error", f"Permission denied: '{path_to_file}'")
        return None

def traverse_folder(folder_path):
    file_hashes = []
    for root, _, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            hash_value = generate_hash(file_path)
            if hash_value:
                file_hashes.append((root, file, hash_value))
    return file_hashes

def select_folder_and_check_hash():
    global file_hashes
    folder_path = filedialog.askdirectory(initialdir=os.path.dirname(os.path.abspath(__file__)))
    if folder_path:
        file_hashes = traverse_folder(folder_path)
        display_hashes(file_hashes)
        expand_list()
        if autosave_var.get():
            save_report(file_hashes)
        else:
            save_as_button.config(state=tk.NORMAL)

def select_file_and_check_hash():
    global file_hashes
    file_path = filedialog.askopenfilename(initialdir=os.path.dirname(os.path.abspath(__file__)))
    if file_path:
        file_hashes = [(os.path.dirname(file_path), os.path.basename(file_path), generate_hash(file_path))]
        display_hashes(file_hashes)
        expand_list()
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
                folder_dict[parent] = tree.insert(parent_id, 'end', text=part, open=True, tags=('bold',))
        tree.insert(folder_dict[root], 'end', text='', values=(file, hash_value))

def expand_list():
    root.geometry("800x600")

def save_report(file_hashes, report_path=None):
    if report_path is None:
        report_path = os.path.join(os.getcwd(), "hash_report.txt")
    with open(report_path, 'w') as report_file:
        for root, file, hash_value in file_hashes:
            report_file.write(f"Folder: {root}\n")
            report_file.write(f"File: {file}\n")
            report_file.write(f"Hash: {hash_value}\n")
            report_file.write("\n")
    messagebox.showinfo("Report Saved", f"Report saved to {report_path}")

def save_as():
    report_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
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
root.geometry("800x200")  # Set the initial window size to be small

# Create a frame for the buttons and checkbox
button_frame = tk.Frame(root)
button_frame.pack(pady=10)

# Create buttons to select the folder, select the file, and check the hashes
select_folder_button = tk.Button(button_frame, text="Select Folder and Check Hash", command=select_folder_and_check_hash)
select_folder_button.pack(side=tk.LEFT, padx=10)

select_file_button = tk.Button(button_frame, text="Select File and Check Hash", command=select_file_and_check_hash)
select_file_button.pack(side=tk.LEFT, padx=10)

# Add a spacer
spacer = tk.Label(button_frame, text=" " * 10)
spacer.pack(side=tk.LEFT)

# Create a checkbox for autosave report
autosave_var = tk.BooleanVar()
autosave_checkbox = ttk.Checkbutton(button_frame, text="Autosave report", variable=autosave_var, command=toggle_save_as_button)
autosave_checkbox.pack(side=tk.LEFT, padx=10)

# Create a "Save as..." button
save_as_button = ttk.Button(button_frame, text="Save as...", command=save_as, state=tk.DISABLED)
save_as_button.pack(side=tk.LEFT, padx=10)

# Create a frame for the Treeview and scrollbar
frame = tk.Frame(root)
frame.pack(fill=tk.BOTH, expand=True)

# Create a Treeview widget to display the folder structure and hash values
tree = ttk.Treeview(frame, columns=("Name", "Hash"), show="tree headings")
tree.heading("#0", text="Folder Structure")
tree.heading("Name", text="File Name")
tree.heading("Hash", text="Hash Value")
tree.column("#0", stretch=tk.YES)
tree.column("Name", stretch=tk.YES)
tree.column("Hash", width=100, anchor='center')  # Set the hash column width and center align
tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

# Define a custom tag for bold text
tree.tag_configure('bold', font=('TkDefaultFont', 10, 'bold'))

# Create a vertical scrollbar for the Treeview
vsb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
vsb.pack(side=tk.RIGHT, fill=tk.Y)
tree.configure(yscrollcommand=vsb.set)

# Initialize the file_hashes variable
file_hashes = []

# Run the application
root.mainloop()