import os
import nmap
import time
import pyfiglet
import platform
import warnings
import requests
import ipaddress
import subprocess
from art import *
from PIL import Image
import multiprocessing
from requests import get
from Wappalyzer import Wappalyzer, WebPage
from PIL.ExifTags import TAGS, GPSTAGS

nm = nmap.PortScanner()

clear = lambda: os.system('cls')

# I looked it up and the Wappalyzer error I was getting was a huge warning; this resolves it. This is for the web technologies functions
warnings.filterwarnings('ignore')


# ===================== COLOR CODING / BANNER / MENU CONSTANTS ========================= #

RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
LIGHT_CYAN  = "\033[96m" 
DIM_CYAN    = "\033[2;36m"  
BOLD_CYAN = "\033[1;96m"
BOLD_OFF = "\033[22m"
RESET = "\033[0m"

# EXIF FUNCTION COLORS \/\/

HEADER = '\033[95m'  # Light Magenta for headers
OKBLUE = '\033[94m'  # Light Blue for keys
OKGREEN = '\033[92m'  # Light Green for values
WARNING = '\033[93m'  # Yellow for warnings
FAIL = '\033[91m'    # Light Red for errors
ENDC = '\033[0m'     # Reset to default color

def print_primary(text):    print(f"  {LIGHT_CYAN}{text}{RESET}")
def print_secondary(text):  print(f"  {CYAN}{text}{RESET}")
def print_dim(text):        print(f"  {DIM_CYAN}{text}{RESET}")
def print_success(text):    print(f"  {GREEN}{text}{RESET}")
def print_error(text):      print(f"  {RED}{text}{RESET}")

banner = pyfiglet.figlet_format("Bunkey's AIO Tool")
DIVIDER = CYAN + "─" * 60 + RESET


def prompt(text):
        result = input(f" {LIGHT_CYAN}{text}")
        print(RESET, end="")
        return result

# ======================================================================================= #

# ============ HOST DISCOVERY & PORT SCANNER CONSTANTS ============ #

host_address = "0.0.0.0/0" # Default variable set as localhost

active_hosts_list = [] # Hosts that are deemed active in the find_hosts function are added to here for use with nmap

ports_list = "21,22,23,25,53,80,110,135,139,143,443,445,465,587,993,995,1433,3389,8080,8443,9100" # List of ports to scan for




# ============ NETWORK SCANNER FUNCTIONS ============ #

def find_hosts():
    while True:    
        address_input = prompt(f"\n{LIGHT_CYAN}Please enter a subnet range or IP address to be scanned: (e.g. '172.16.26.0/23', '10.0.0.104'):{RESET} ")
        print_secondary(f"\n{LIGHT_CYAN}It will take a moment to ping every host to determine whether they are active or not...{RESET}")
        # Split range contents
        try:
            network = ipaddress.ip_network(address_input)
            
            start_time = time.time()

            #utilizing multiprocessing to check every possible host via the host_isAlive function
            with multiprocessing.Pool(processes=multiprocessing.cpu_count()) as pool:
                results = pool.map(host_isAlive, [str(ip) for ip in network])
            total_alive = 0
            end_time = time.time() 
            elapsed_time = end_time - start_time # Finding lapsed time it takes to finish pinging like real nmap script

            for host, is_alive in results:
                if is_alive:
                    print(f"{CYAN}[+] {GREEN}{host}{DIM_CYAN} is alive!{RESET}")
                    total_alive += 1 
                    active_hosts_list.append(host)
                else:
                    None # Returning nothing here because the assignment says to only display active hosts
            print(f"{CYAN}Total active hosts in the network '{GREEN}{address_input}{CYAN}': {GREEN}{total_alive}{RESET}")
            print(f"{CYAN}Elapsed time to ping each host: {GREEN}{round(elapsed_time, 2)} {CYAN}seconds{RESET}")
            break
        except ValueError as error:
            print(f"{YELLOW}Error processing IP: {RED}{error}.{RESET}")
            print_dim("Please try again.")
            continue


#host_isAlive pings a host and returns whether or not that host was alive or not - Works on Windows

def host_isAlive(host):
    if platform.system().lower() == 'windows': # Had to implement this platform check because I developed this across two platforms
        command = f"ping -n 1 -w 1000 {host}"  # Windows-style
    else:                                            
        command = ["ping", "-c", "1", host]  # Linux-style
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # This is to run the command and redirect all the output to this subprocesses PIPE
        # Then I am going to check if it was sucesful
        return(str(host), result.returncode == 0)
    except Exception as e:
        print(f"{YELLOW}Error pinging {GREEN}{host}{YELLOW}: {RED}{e}{RESET}")
        return(str(host), False) # Return false if an error occurs
    
# ============ /\/\/\ NETWORK SCANNER FUNCTIONS /\/\/\ ============ #



# ============ PORT SCANNER FUNCTIONS ============ #

#Function to scan all active IPs with nmap for ports
def nmap_Port_Scan(active_hosts_list):
    for host in active_hosts_list:
        nm.scan(f"{host}", f"{ports_list}")

        for host in nm.all_hosts():
            print(f"{DIM_CYAN}------------------{BOLD_CYAN} Host & Port Information {BOLD_OFF}{DIM_CYAN}-----------------{RESET}")
            print(f"{CYAN}Host: {GREEN}{host}{RESET}")
            for protocol in nm[host].all_protocols():
                print(f"{DIM_CYAN}{'-'*20}{RESET}")
                print(f"{CYAN}Protocols: {GREEN}{protocol}{RESET}")
                lport = nm[host][protocol].keys()
                open_ports_count = 0
                for port in lport:
                    port_state = nm[host][protocol][port]['state']
                    if port_state == "open":
                        print(f"{CYAN}Port: {GREEN}{port} {CYAN}\tState: {GREEN}{nm[host][protocol][port]['state']}{RESET}")
                        open_ports_count += 1
                    else:
                        None # Return nothing as the assignment requires only open ports
        print(f"{CYAN}Total open ports for {GREEN}{host}{CYAN}: {GREEN}{open_ports_count}{RESET}")
        print(f"{DIM_CYAN}{'-'*59}{RESET}")
        print("")

# ============ /\/\/\ PORT SCANNER FUNCTIONS /\/\/\ ============ #


# ============ VULNERABILITY SCANNER FUNCTIONS ================ #

# Function to get the banner information of the desired port (80!)
def fetch_banner(ip, port):
    try:
        response = get(f'http://{ip}:{port}', timeout=5)
        response.raise_for_status() # Checks for a bad response
        return response.headers # Gives us raw HTML output for response
    except requests.exceptions.RequestException as e:
        return f"Error: {e}"

# Function to parse CVE database for search terms to find vulnerabilities that line up with current host configuration
def search_cve():
    search_input = prompt(f"{LIGHT_CYAN}Enter keywords separated by spaces: (E.g: Linux Apache 1.3){RESET} ")
    keywords = search_input.split(" ")
    keywords_string = ' '.join(keywords)

    response_data = get(f'https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keywords_string}')
    data = response_data.json()

    print(f"\n{CYAN}Here are the vulnerabilities that match your search keywords:{RESET}\n")
    if "vulnerabilities" in data:
        vulnerabilities = data['vulnerabilities'] # lists all vulns
        for item in vulnerabilities:
            cve_id = item.get("cve", {}).get("id", "No ID")
            descriptions = item.get("cve", {}).get("descriptions", [])

            # Some CVEs have multiple description lines so I conjoin them all here neatly:
            description_text = ""
            for desc in descriptions:
                if 'value' in desc:
                    description_text += desc['value']
            description_text = description_text.strip()

            print(f"{CYAN}CVE ID: {GREEN}{cve_id}\n{CYAN}Description: {GREEN}{description_text}\n{RESET}")
    else:
        print(f"{YELLOW}No vulnerabilities found for provided keyword.{RESET}")
    print(f"\n{DIM_CYAN}End of list.")

    
# Get info from fetch_banner()
def get_Info():
    print(f"\n{LIGHT_CYAN}Please enter some information about the device you want to scan:{RESET} ")
    ip = input(f"{LIGHT_CYAN}Enter the IP address of target device:{RESET} ")
    port = input(f"{LIGHT_CYAN}Please enter the target port: (80...){RESET} ")
    banner = fetch_banner(ip, port)
    print(f"\n{CYAN}Banner Data for {GREEN}{ip} {CYAN}on port {GREEN}{port}.{RESET}")
    for key, value in banner.items():
        print(f"{CYAN}{key}: {GREEN}{value}{RESET}")
    
    print(f"\n{CYAN}Excellent, now lets perform a search with NISTs CVE database\nUse keywords from the banner we found.{RESET}")
    search_cve() # Going to simply perform this here rather than do anything else extraneous, since this returns all the results promptly
# ============ /\/\/\ VULNERABILITY SCANNER FUNCTIONS /\/\/\ ================ #


# ============ EXIF IMAGE DATA EXTRACTOR FUNCTIONS AND CODE ============ #

# ANSI color codes for formatted output
class Colors:
    HEADER = '\033[95m'  # Light Magenta for headers
    OKBLUE = '\033[94m'  # Light Blue for keys
    OKGREEN = '\033[92m'  # Light Green for values
    WARNING = '\033[93m'  # Yellow for warnings
    FAIL = '\033[91m'    # Light Red for errors
    ENDC = '\033[0m'     # Reset to default color
    BOLD = '\033[1m'     # Bold text

# Function to extract EXIF metadata from an image file
def get_exif_metadata(image_path):
    exifData = {}  # Initialize an empty dictionary to store EXIF metadata
    image = Image.open(image_path)  # Open the image file using PIL's Image class
    if hasattr(image, '_getexif'):  # Check if the image has EXIF data
        exifinfo = image._getexif()  # Retrieve the EXIF data from the image
        if exifinfo is not None:  # Ensure EXIF data is not None
            for tag, value in exifinfo.items():  # Iterate through the EXIF data items
                decoded = TAGS.get(tag, tag)  # Decode the tag to a human-readable format using TAGS dictionary
                exifData[decoded] = value  # Store the decoded tag and its value in the exifData dictionary
    decode_gps_info(exifData)  # Call the function to decode GPS information if available
    return exifData  # Return the dictionary containing EXIF metadata

# Function to convert GPS coordinates from degrees, minutes, seconds to decimal format
def convert_to_degress(value):
    d = float(value[0])  # Extract degrees and convert to float
    m = float(value[1])  # Extract minutes and convert to float
    s = float(value[2])  # Extract seconds and convert to float
    return d + (m / 60.0) + (s / 3600.0)  # Convert to decimal format by combining degrees, minutes, and seconds

# Function to decode GPS information within EXIF metadata
def decode_gps_info(exif):
    gpsinfo = {}  # Initialize an empty dictionary to store GPS information
    if 'GPSInfo' in exif:  # Check if GPS information is present in EXIF data
        for key in exif['GPSInfo'].keys():  # Iterate through GPS information keys
            decode = GPSTAGS.get(key, key)  # Decode the GPS tag to a human-readable format using GPSTAGS dictionary
            gpsinfo[decode] = exif['GPSInfo'][key]  # Store the decoded GPS tag and its value in the gpsinfo dictionary
        exif['GPSInfo'] = gpsinfo  # Update EXIF data with decoded GPS information

        latitude = exif['GPSInfo']['GPSLatitude']  # Retrieve latitude value from GPS information
        latitude_ref = exif['GPSInfo']['GPSLatitudeRef']  # Retrieve latitude reference (N or S) from GPS information
        longitude = exif['GPSInfo']['GPSLongitude']  # Retrieve longitude value from GPS information
        longitude_ref = exif['GPSInfo']['GPSLongitudeRef']  # Retrieve longitude reference (E or W) from GPS information

        if latitude:  # Check if latitude is available
            latitude_value = convert_to_degress(latitude)  # Convert latitude to decimal format using convert_to_degress function
            if latitude_ref != 'N':  # If latitude reference is not North
                latitude_value = -latitude_value  # Make latitude negative to indicate South
        else:
            return {}  # Return empty dictionary if latitude is not available

        if longitude:  # Check if longitude is available
            longitude_value = convert_to_degress(longitude)  # Convert longitude to decimal format using convert_to_degress function
            if longitude_ref != 'E':  # If longitude reference is not East
                longitude_value = -longitude_value  # Make longitude negative to indicate West

        exif['GPSInfo'] = {"Latitude": latitude_value, "Longitude": longitude_value}  # Update EXIF data with decimal GPS coordinates

# Function to traverse a directory and extract metadata from all image files
def print_metadata():
    processed_images = 0  # Initialize counter for processed images
    images_with_metadata = 0  # Initialize counter for images with metadata
    no_metadata_images = []  # Initialize list to store names of images without metadata

    print(f"{Colors.HEADER}Image Metadata Extraction Tool{Colors.ENDC}")  # Print header for the tool
    print(f"{Colors.OKBLUE}{'=' * 50}{Colors.ENDC}")  # Print separator line

    # Walk through the directory named 'images'
    for dirpath, dirnames, files in os.walk("images"):  # Traverse the directory tree
        for name in files:  # Iterate through each file in the directory
            file_path = dirpath + os.path.sep + name  # Construct the full file path
            print(f"\n{Colors.BOLD}{Colors.OKBLUE}[+] Metadata for file: {Colors.OKGREEN}{file_path}{Colors.ENDC}")  # Print the file path being processed
            try:
                processed_images += 1  # Increment the counter for processed images
                exif = get_exif_metadata(file_path)  # Extract EXIF metadata from the image file
                if exif:  # Check if metadata is found
                    images_with_metadata += 1  # Increment the counter for images with metadata
                    print(f"{Colors.HEADER}General Metadata:{Colors.ENDC}")  # Print header for general metadata
                    for metadata in exif:  # Iterate through the metadata items
                        # Check if metadata is GPS info for special formatting
                        if metadata == "GPSInfo":
                            print(f"{Colors.OKBLUE}  GPS Metadata:{Colors.ENDC}")  # Print header for GPS metadata
                            for gps_key, gps_value in exif["GPSInfo"].items():  # Iterate through GPS metadata items
                                print(f"    {Colors.OKBLUE}{gps_key}:{Colors.OKGREEN} {gps_value}{Colors.ENDC}")  # Print GPS metadata key and value
                        else:
                            print(f"{Colors.OKBLUE}{metadata}:{Colors.OKGREEN} {exif[metadata]}{Colors.ENDC}")  # Print general metadata key and value
                else:
                    no_metadata_images.append(name)  # Add image name to the list of images without metadata
                    print(f"{Colors.WARNING}No EXIF metadata found for this image.{Colors.ENDC}")  # Print warning message for no metadata
            except Exception as e:  # Handle exceptions
                print(f"{Colors.FAIL}Error processing file: {name}{Colors.ENDC}")  # Print error message for the file
                print(f"{Colors.FAIL}{e}{Colors.ENDC}")  # Print the exception details

    print(f"{Colors.OKBLUE}{'=' * 50}{Colors.ENDC}")  # Print separator line
    print(f"{Colors.HEADER}Summary:{Colors.ENDC}")  # Print header for summary
    print(f"{Colors.OKBLUE}Total images processed:{Colors.OKGREEN} {processed_images}{Colors.ENDC}")  # Print total images processed
    print(f"{Colors.OKBLUE}Images with metadata:{Colors.OKGREEN} {images_with_metadata}{Colors.ENDC}")  # Print total images with metadata
    if no_metadata_images:  # Check if there are images without metadata
        print(f"{Colors.WARNING}Images without metadata:{Colors.ENDC}")  # Print header for images without metadata
        for img in no_metadata_images:  # Iterate through the list of images without metadata
            print(f"{Colors.FAIL}- {img}{Colors.ENDC}")  # Print the name of each image without metadata

# ============ /\/\/\ EXIF IMAGE DATA EXTRACTOR FUNCTIONS AND CODE /\/\/\ ============ #





# ============ WEBSITE TECHNOLOGIES DISCOVERY FUNCTIONS ============ #

# Function for gathering user input
def input_gather():
    # Input loop in case an invalid URL is caught
    while True:
        url_input = input(f"{LIGHT_CYAN}Please enter a url to analyze:{RESET} ")
        try:
            webpage = WebPage.new_from_url(url_input)
            return webpage
        except Exception as e:
            print(f"{YELLOW}Invalid URL, please try again. ({RED}{e}{YELLOW}){RESET}")


# Function to perform the scanning process
def webpage_scan():
    webpage = input_gather()    
    wappalyzer = Wappalyzer.latest()
    output = wappalyzer.analyze_with_categories(webpage)

    # With the output I am separating the technologies
    # Into different formatted outputs
    grouped = {}
    for tech, value in output.items():
        for category in value['categories']:
            if category not in grouped:
                grouped[category] = []
            grouped[category].append(tech)

    print(f"\n{CYAN}Detected technologies:{RESET}")
    for category, techs in grouped.items():
        print(f"{CYAN}{category}: {GREEN}{', '.join(techs)}{RESET}")

# ============ /\/\/\ WEBSITE TECHNOLOGIES DISCOVERY FUNCTIONS /\/\/\ ============ #



# Main program function with loop to display menu
def MainMenu():
    clear()
    while True:
        clear()
        print(f"{LIGHT_CYAN}{banner}{RESET}")
        print(DIM_CYAN + "AIO Network Sample Tool made in Python\n" + RESET)
        print(DIVIDER)
        print(f"{LIGHT_CYAN}[1] Network scanner     {RESET}{CYAN}- scan a subnet for active devices{RESET}")
        print(f"{LIGHT_CYAN}[2] Port scanner        {RESET}{CYAN}- scan the devices on a subnet for open ports{RESET}")
        print(f"{LIGHT_CYAN}[3] Vuln scanner        {RESET}{CYAN}- ask for keyword(s) and search the NIST CVE database{RESET}")
        print(f"{LIGHT_CYAN}[4] EXIF Data Extractor {RESET}{CYAN}- use the images folder and scan for images and EXIF data{RESET}")
        print(f"{LIGHT_CYAN}[5] Web technologies    {RESET}{CYAN}- analyzes a webpage and discovers used technologies{RESET}")
        print(f"{LIGHT_CYAN}[6] Quit{RESET}")
        main_input = prompt(f"\n{LIGHT_CYAN}Please enter your option #: {RESET}")

        if main_input == "1":
            clear()
            print(f"{CYAN}You have selected the network scanner.{RESET}")
            find_hosts()
            eofi = input(f"{DIM_CYAN}\nPress any key to return to the menu. Scroll up to view results.{RESET}")
            if eofi:
                continue
        elif main_input == "2":
            clear()
            print(f"{CYAN}You have selected the port scanner.{RESET}")
            find_hosts()
            print(f"\n{DIM_CYAN}Press enter to end the program. Scroll up to view results.{RESET}")
            eofi = prompt(f"{LIGHT_CYAN}Enter \"nmap\" to perform a port scan on found hosts: {RESET}")
            if eofi == None:
                quit()
            elif eofi.lower() == "nmap":
                print(f"{CYAN}\nBeginning NMAP scans...\n{RESET}")
                nmap_Port_Scan(active_hosts_list)
                eofi = input(f"{DIM_CYAN}\nPress any key to return to the menu. Scroll up to view results.{RESET}")
                if eofi:
                    continue
        elif main_input == "3":
            clear()
            print(f"{CYAN}You have selected the vulnerability scanner.{RESET}")
            get_Info()
            eofi = input(f"{DIM_CYAN}\nPress any key to return to the menu. Scroll up to view results.{RESET}")
            if eofi:
                continue
        elif main_input == "4":
            clear()
            print(f"{CYAN}You have selected the EXIF data extractor.{RESET}")
            print_metadata()
            eofi = input(f"{DIM_CYAN}\nPress any key to return to the menu. Scroll up to view results.{RESET}")
            if eofi:
                continue
        elif main_input == "5":
            clear()
            print(f"{CYAN}You have selected the web technologies discover tool.{RESET}")
            webpage_scan()
            eofi = input(f"{DIM_CYAN}\nPress any key to return to the menu. Scroll up to view results.{RESET}")
            if eofi:
                continue
        elif main_input == "6":
            quit()
        else:
            input(f"\n{YELLOW}You didn't enter a correct menu option, please try again! \nHit enter to continue.{RESET}")
            clear()

# Launches the main function if the program was not imported externally
if __name__ == "__main__":
    MainMenu()

