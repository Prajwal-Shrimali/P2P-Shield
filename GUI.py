import requests
import json
import os
import subprocess
import time
import threading
import pcapng
from colorama import Fore, Style
from kivy.app import App
from kivy.uix.button import Button
from kivy.uix.textinput import TextInput
from kivy.uix.boxlayout import BoxLayout
from kivy.clock import Clock
from kivy.logger import Logger
import sys


def getFileReportData(filename, apikey):
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {'apikey': apikey}
    files = {'file': (filename, open(filename, 'rb'))}
    response = requests.post(url, files=files, params=params)
    f.write(str(response.json()))
    return response.json()

def getFileReport(resource, apikey):
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': apikey, 'resource': resource}
    responseReport = requests.get(url, params=params)
    Logger.info("getFileReport response: %s" % responseReport.text)
    Logger.info("getFileReport status code: %s" % responseReport.status_code)
    if responseReport.status_code == 204:
        print("Rate limit exceeded, sleeping for 15 seconds")
        time.sleep(15)
        return getFileReport(resource, apikey)
    f.write(str(responseReport.json()))
    return responseReport.json()

def getFiles(directoryPath):
    files = os.listdir(directoryPath)
    l = []
    for file in files:
        if file.endswith('.ini') or file.endswith('.File') or os.path.splitext(file)[1] == '':
            continue
        if os.path.isfile(os.path.join(directoryPath, file)):
            l.append(file)
    return l

def captureFileAndData(outputFile, interface):
    print("Capturing Data...")
    Logger.info("Capturing Data...")
    tshark_path = r'C:\Program Files\Wireshark\tshark.exe'
    command = [tshark_path, '-i', interface, '-w', outputFile]
    try:
        subprocess.run(command)
    except KeyboardInterrupt:
        print("\nStopped by User. Goodbye!")
        Logger.info("\nStopped by User. Goodbye!")

def extractObjects(protocol, inputFile):
    output_directory = f'{protocol}Objects/'
    tshark_path = r'C:\Program Files\Wireshark\tshark.exe'
    command = [
        tshark_path,
        '-r', inputFile,
        '--export-objects', f'{protocol},{output_directory}'
    ]
    subprocess.run(command)

def process_file(i, apikey, protocol):    
    try:
        # Acquire a permit from the semaphore before making the API call
        with semaphore:
            resource = getFileReportData(f'{protocol}Objects\\' + i, apikey)['resource']
            while True:
                report = getFileReport(resource, apikey)
                if report["response_code"] != -2:
                    break
                else:
                    time.sleep(10)
        total = report["total"]
        positives = report["positives"]
        if positives > 0:
            print(f"File: {i}")
            print(f"No of Antivirus Software Searched through: {total}")
            print(f"No of Suspected Virus Found: {positives}")
            filePath = "C:\\Users" + i.replace("%5c", "\\")
            print(f"Deleting file {file} from {filePath}")
            os.remove(filePath)
            Logger.info(f"File: {i}")
            Logger.info(f"No of Antivirus Software Searched through: {total}")
            Logger.info(f"No of Suspected Visitors Found: {positives}")
            Logger.info(f"Deleting file {file} from {filePath}")
        else:
            print(f"File: {i}")
            print(f"No of Antivirus Software Searched through: {total}")
            print(f"No of Suspected Virus Found: {positives}")
            Logger.info(f"File: {i}")
            Logger.info(f"No of Antivirus Software Searched through: {total}")
            Logger.info(f"No of Suspected virus Found: {positives}")
    except Exception as e:
        print(f"Error: {e}")
        Logger.info(f"Error: {e}")

# Create a semaphore with a maximum of 2 permits
semaphore = threading.Semaphore(2)

def main(apikey, protocol, interface):
    pcapngFile = "Data.pcapng"
    directory = f'{protocol}Objects'
    if not os.path.exists(directory):
        os.makedirs(directory)
    with open(pcapngFile, "wb") as pcap_file:
        pass
    print(f"Blank PCAPNG file '{pcapngFile}' created.")
    Logger.info(f"Blank PCAPNG file '{pcapngFile}' created")
    captureFileAndData(pcapngFile, interface)
    extractObjects(protocol, pcapngFile)
    files = getFiles(f'{protocol}Objects')
    threads = []
    for i in range(len(files)):
        thread = threading.Thread(target=process_file, args=(files[i], apikey, protocol))
        threads.append(thread)
        thread.start()
        if i % 2 == 1:  # If i is odd (meaning we've started two threads)
            time.sleep(60)  # Wait 60 seconds before starting the next thread
        else:
            # time.sleep(30)  # Wait 30 seconds before starting the next thread
            pass

    for thread in threads:
        thread.join()
    subprocess.run(['rmdir', '/s', '/q', f'{protocol}Objects'], shell=True)
    os.remove(pcapngFile)

class MyApp(App):
    def build(self):
        layout = BoxLayout(orientation='vertical')
        self.output = TextInput(readonly=True, size_hint=(1, 0.8))
        button = Button(text='Run', size_hint=(1, 0.2))
        button.bind(on_press=self.run_main)
        layout.add_widget(self.output)
        layout.add_widget(button)
        return layout

    def run_main(self, instance):
        sys.stdout = self
        Clock.schedule_once(lambda dt: main("4a76a0633ae9c1c40e8f35225189b4ea74a40196331dd82003b2932465071c30", "smb", 'Wi-Fi'), 0)

    def write(self, text):
        def update_text(dt):
            self.output.text += text
            self.output.cursor = (0, len(self.output._lines))
        Clock.schedule_once(update_text)


    def flush(self):
        pass

if __name__ == "__main__":
    MyApp().run()
