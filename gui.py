import tkinter as tk
from tkinter import scrolledtext, messagebox, END
import http.client
import sys

# List of admin pages to check (unchanged from original script)
admpagelist = [
    'admin/', 'administrator/', 'admin1/', 'admin2/', 'admin3/', 'admin4/', 'admin5/',
    'usuarios/', 'usuario/', 'moderator/', 'webadmin/', 'adminarea/', 'bb-admin/',
    'adminLogin/', 'admin_area/', 'panel-administracion/', 'instadmin/', 'memberadmin/',
    'administratorlogin/', 'adm/', 'admin/account.php', 'admin/index.php',
    'admin/login.php', 'admin/admin.php', 'admin/account.php', 'admin_area/admin.php',
    'admin_area/login.php', 'siteadmin/login.php', 'siteadmin/index.php',
    'siteadmin/login.html', 'admin/account.html', 'admin/index.html',
    'admin/login.html', 'admin/admin.html', 'admin_area/index.php',
    'bb-admin/index.php', 'bb-admin/login.php', 'bb-admin/admin.php',
    'admin/home.php', 'admin_area/login.html', 'admin_area/index.html',
    'admin/controlpanel.php', 'admin.php', 'admincp/index.asp',
    'admincp/login.asp', 'admincp/index.html', 'admin/account.html',
    'adminpanel.html', 'webadmin.html', 'webadmin/index.html',
    'webadmin/admin.html', 'webadmin/login.html', 'admin/admin_login.html',
    'admin_login.html', 'panel-administracion/login.html', 'admin/cp.php',
    'cp.php', 'administrator/index.php', 'administrator/login.php',
    'nsw/admin/login.php', 'webadmin/login.php', 'admin/admin_login.php',
    'admin_login.php', 'administrator/account.php', 'administrator.php',
    'admin_area/admin.html', 'pages/admin/admin-login.php',
    'admin/admin-login.php', 'admin-login.php', 'bb-admin/index.html',
    'bb-admin/login.html', 'acceso.php', 'bb-admin/admin.html',
    'admin/home.html', 'login.php', 'modelsearch/login.php', 'moderator.php',
    'moderator/login.php', 'moderator/admin.php', 'account.php',
    'pages/admin/admin-login.html', 'admin/admin-login.html',
    'admin-login.html', 'controlpanel.php', 'admincontrol.php',
    'admin/adminLogin.html', 'adminLogin.html', 'admin/adminLogin.html',
    'home.html', 'rcjakar/admin/login.php', 'adminarea/index.html',
    'adminarea/admin.html', 'webadmin.php', 'webadmin/index.php',
    'webadmin/admin.php', 'admin/controlpanel.html', 'admin.html',
    'admin/cp.html', 'cp.html', 'adminpanel.php', 'moderator.html',
    'administrator/login.html', 'user.html', 'administrator/account.html',
    'administrator.html', 'login.html', 'modelsearch/login.html',
    'moderator/login.html', 'adminarea/login.html',
    'panel-administracion/index.html', 'panel-administracion/admin.html',
    'modelsearch/index.html', 'modelsearch/admin.html',
    'admincontrol/login.html', 'adm/index.html', 'adm.html',
    'moderator/admin.html', 'user.php', 'account.html', 'controlpanel.html',
    'admincontrol.html', 'panel-administracion/login.php', 'wp-login.php',
    'adminLogin.php', 'admin/adminLogin.php', 'home.php', 'admin.php',
    'adminarea/index.php', 'adminarea/admin.php', 'adminarea/login.php',
    'panel-administracion/index.php', 'panel-administracion/admin.php',
    'modelsearch/index.php', 'modelsearch/admin.php',
    'admincontrol/login.php', 'adm/admloginuser.php', 'admloginuser.php',
    'admin2.php', 'admin2/login.php', 'admin2/index.php',
    'usuarios/login.php', 'adm/index.php', 'adm.php', 'affiliate.php',
    'adm_auth.php', 'memberadmin.php', 'administratorlogin.php'
]

class AdminFinderGUI:
    def __init__(self, master):
        """
        Initializes the AdminFinderGUI application.

        Args:
            master: The Tkinter root window.
        """
        self.master = master
        master.title("Admin Finder - Coded by Khedr0x00") # Changed title
        master.geometry("800x600") # Set initial window size
        master.resizable(True, True) # Allow window resizing

        # Configure columns and rows to expand
        master.grid_columnconfigure(0, weight=1)
        master.grid_rowconfigure(2, weight=1)

        # Banner display
        self.banner_label = tk.Label(master, text=self.get_banner(), font=("Courier New", 10), justify=tk.LEFT)
        self.banner_label.grid(row=0, column=0, padx=10, pady=10, sticky="ew")

        # Website input
        self.website_frame = tk.Frame(master)
        self.website_frame.grid(row=1, column=0, padx=10, pady=5, sticky="ew")
        self.website_frame.grid_columnconfigure(1, weight=1) # Allow entry to expand

        self.website_label = tk.Label(self.website_frame, text="Website :")
        self.website_label.grid(row=0, column=0, padx=5, pady=5)

        self.website_entry = tk.Entry(self.website_frame, width=50)
        self.website_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        self.website_entry.bind("<Return>", self.start_scan_event) # Bind Enter key to start scan

        self.scan_button = tk.Button(self.website_frame, text="Start Scan", command=self.start_scan)
        self.scan_button.grid(row=0, column=2, padx=5, pady=5)

        # Output text area
        self.output_text = scrolledtext.ScrolledText(master, wrap=tk.WORD, width=80, height=20, font=("Courier New", 9))
        self.output_text.grid(row=2, column=0, padx=10, pady=10, sticky="nsew")

        # Exit button
        self.exit_button = tk.Button(master, text="Exit", command=self.exit_app)
        self.exit_button.grid(row=3, column=0, padx=10, pady=10, sticky="ew")

    def get_banner(self):
        """
        Returns the ASCII art banner for the application.
        """
        # Updated banner to reflect "Coded by Khedr0x00"
        return """
          \\||                                  
         ,'_,-\\             C  O  D  E  D    B  Y    K  H  E  D  R  0  X  0  0
         ;'____\\

         || =\\=|
         ||  - |
     ,---'._--''-,,---------.--.----_,          Admin finder - Coded by Khedr0x00     
    / `-._- _--/,,|  ___,,--'--'._<       
   /-._,  `-.__;,,|'                            
  /   ;\\      / , ;                              
 /  ,' | _ - ',/, ;     
(  (   |     /, ,,;
        """

    def log_message(self, message):
        """
        Logs a message to the scrolled text area.

        Args:
            message (str): The message to log.
        """
        self.output_text.insert(END, message + "\n")
        self.output_text.see(END) # Auto-scroll to the bottom

    def start_scan_event(self, event=None):
        """
        Event handler for starting the scan (e.g., from Enter key press).
        """
        self.start_scan()

    def start_scan(self):
        """
        Initiates the admin page scanning process.
        """
        user_input = self.website_entry.get()
        if not user_input:
            messagebox.showwarning("Input Error", "Please enter a website URL.")
            return

        self.output_text.delete(1.0, END) # Clear previous output
        self.log_message(self.get_banner()) # Re-display banner in output

        site = user_input.replace('http://', '').replace('https://', '')
        self.scan_button.config(state=tk.DISABLED) # Disable button during scan
        self.website_entry.config(state=tk.DISABLED) # Disable entry during scan
        self.master.update_idletasks() # Update GUI to reflect disabled state

        # Run the scan in a separate thread or use after to keep GUI responsive
        self.master.after(100, self._perform_scan, site)

    def _perform_scan(self, site):
        """
        Performs the actual scanning of admin pages.
        This method is called via after() to prevent freezing the GUI.

        Args:
            site (str): The cleaned website URL.
        """
        try:
            # Check initial connection
            conn = http.client.HTTPConnection(site, timeout=5) # Added timeout
            conn.request("HEAD", "/") # Use HEAD request for faster initial connection check
            response = conn.getresponse()
            conn.close() # Close connection after initial check

            self.log_message(f"\n Loaded {len(admpagelist)} admin-pages \n")

            for adminpage in admpagelist:
                try:
                    # Ensure adminpage starts with '/'
                    if not adminpage.startswith('/'):
                        adminpage = '/' + adminpage
                    
                    host = site + adminpage
                    self.log_message(f"> Checking --- {host}")

                    # Re-establish connection for each request
                    conn = http.client.HTTPConnection(site, timeout=5) # Added timeout
                    conn.request('GET', adminpage)
                    response = conn.getresponse()
                    conn.close() # Close connection after each request

                    if response.status == 200:
                        self.log_message(f"\n\tPage found --- {host}\n")
                        # You can add a small pause or message box here if needed
                        # For now, just continue as per original script logic (no raw_input)
                    else:
                        pass # Page not found, continue
                except Exception as e:
                    self.log_message(f"Error Occurred checking {host}: {e}")
                    # If an error occurs during scanning, it's not critical to exit the whole app
                    # just log it and continue
            
            self.log_message("\nScan completed.")

        except http.client.HTTPException as e:
            self.log_message(f"\n Invalid URL / Offline Server: {e}\n")
            messagebox.showerror("Connection Error", f"Invalid URL or Offline Server: {e}")
        except Exception as e:
            self.log_message(f"\n An unexpected error occurred: {e}\n")
            messagebox.showerror("Error", f"An unexpected error occurred: {e}")
        finally:
            self.scan_button.config(state=tk.NORMAL) # Re-enable button
            self.website_entry.config(state=tk.NORMAL) # Re-enable entry

    def exit_app(self):
        """
        Closes the application.
        """
        self.master.destroy()
        sys.exit() # Ensure the script fully exits

if __name__ == "__main__":
    root = tk.Tk()
    app = AdminFinderGUI(root)
    root.mainloop()

