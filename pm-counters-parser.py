# -*- coding: utf-8 -*-
"""
Created on Tue Mar 21 10:31:07 2023

@author: hdhanaya

Title: Extract DU KPI's from xml file and create a csv file.
"""

import xml.etree.ElementTree as ET
import pandas as pd
import os
import sys
import threading
import time
import re


class XMLParser:
    def __init__(self, directory, setup, ns):
        self.directory = directory
        self.setup = setup
        print(f'command line arguments are {directory} and {setup}')
        self.merged_counter = {}
        self.ns = ns
        # setup = 'setup-p1-rc11_01122021'
        #ns = {'pm': 'www.radisys.com/5G/DUmeasData'}
        #ns={'pm' : 'www.radisys.com/5G/PROCMONmeasData'}
        #ns={'pm' : 'www.radisys.com/5G/SYSMONmeasData'}
        #ns={'pm' : 'www.radisys.com/5G/CUmeasData'}


    def create_csv(self,cell):
        mdf = pd.concat(self.merged_counter[cell], ignore_index=True)
        # print("GENERATING")
        # output_file = self.setup + '_merged_' + cell + '_counters' + '.csv'
        output_file = os.path.join(output_directory, self.setup + '_merged_' + cell + '_counters' + '.csv')
        mdf.to_csv(output_file, index=False)
        print(f"Generated CSV file: {output_file}")
        return output_file

    def parse_xml_du_cu(self,ns):
        for filename in os.listdir(self.directory):
            file = os.path.join(self.directory, filename)
            print(filename)
            if os.path.isfile(file):
                try:
                    tree = ET.parse(file)
                    root = tree.getroot()
                except ET.ParseError as e:
                    print(f"Error parsing XML file {filename}: {e}")
                    continue  # Skip this file and move to the next one
                except Exception as e:
                    print(f"Unexpected error processing file {filename}: {e}")
                    continue  # Skip this file and move to the next one
        
            counter_dict = {}
            time_stamp = []
            counter_val = {}
            cells = []
            cells_col = []
        

            for cell in root.iterfind('.//pm:measValue', namespaces=ns):
                if cell.attrib['measObjLdn'] not in cells:
                    cells.append(cell.attrib['measObjLdn'])

            print("Number of cell",cells)
            '''
            extract the measurement counters pegged across all cells
            '''
            for timest in root.findall('.//pm:granPeriod', namespaces=ns):
                for cell in cells:
                    if re.match("GNBCUFunction=.*",cell) :
                        print(f"MATTCHED---------------------")
                        break;
                    time_stamp.append(timest.attrib['endTime'])
                    print(f"timestamp {time_stamp} for {cell}")
                    #time_stamp.append(timest.attrib['endTime'])
                    #time_stamp.append(timest.attrib['endTime'])
           # exit(0)
            #
            for child in root.iterfind('.//pm:measInfo/pm:measType', namespaces=ns):
                # if not child.attrib['p'] in counter_dict:
                counter_dict[child.attrib['p']] = child.text
            '''
            populate the counters from xml file into dictionary, collect all the counters values under a counter and store it in list, the dictionary thus creates is a dictionary counter_id with list of values.
            '''
            
            for cell in cells:
                counter_val[cell] = {}
                for val in root.iterfind(".//pm:measValue/pm:r", namespaces=ns):
                    if val.attrib['p'] not in counter_val[cell]: 
                        counter_val[cell][val.attrib['p']] = []
                    counter_val[cell][val.attrib['p']].append(val.text)

            '''
            create dictionary from counters & counter values, create dataframe from dictionary for csv creation, counter id is ignored and counter name is retained.
            '''
            #print(len(counter_dict),  ' this are the counter values')
            for i in range(0, len(time_stamp)):
                print(i%len(cells))
                cells_col.append(i%len(cells))

            #print(counter_val, " THIS ARE THE VALUES")

        # print(cells)
            #exit(0)
            # print("HERE")
            for cell in cells:
                counter = {}
                for key in counter_dict.keys():
                    if key in counter_val[cell]:
                        counter[counter_dict[key]] = counter_val[cell][key]
                        #print(counter_dict[key], " ------> " , counter_val[cell][key])
            # exit(0)
                #print(time_stamp)
                df = pd.DataFrame(dict([(k, pd.Series(v)) for k, v in counter.items()]))
                #display(df)
                #print(df)

                #exit(0)
                df.insert(loc=0, column='timestamp', value=time_stamp)
                # df.insert(loc=1, column='cell', value=cells_col)
                '''
                        to save each counter file to csv enable below code !!!
                '''
                #df.to_csv(file + '_counters_'+ cell + '.csv', index=False)
                '''
                save counters from each cells as dictionary of list in merged counter dict !!!
                '''
                    
                if cell not in self.merged_counter:
                    self.merged_counter[cell] = []
                self.merged_counter[cell].append(df)
                self.create_csv(cell)

    def parse_xml_procmon_sysmon(self,ns):
            for filename in os.listdir(self.directory):
                file = os.path.join(self.directory, filename)
                print(filename)
                #print(file)
                #exit(0)
                if os.path.isfile(file):
                    tree = ET.parse(file)
                    root = tree.getroot()
                
                counter_dict = {}
                time_stamp = []
                counter_val = {}
                cells = []
                cells_col = []
            

                '''
                extract the number of counter occurances by date --> cell loop for number of cells that will be available
                '''
                '''for timest in root.findall('.//pm:granPeriod', namespaces=ns):
                    time_stamp.append(timest.attrib['endTime']+cells[0])
                    time_stamp.append(timest.attrib['endTime']+cells[1])
                    time_stamp.append(timest.attrib['endTime']+cells[2])
                #print("HERE ") '''
                '''
                extract the number of cells in counter file
                '''
                for cell in root.iterfind('.//pm:measValue', namespaces=ns):
                    if cell.attrib['measObjLdn'] not in cells:
                        cells.append(cell.attrib['measObjLdn'])
                '''
                extract the measurement counters pegged across all cells
                '''
                for timest in root.findall('.//pm:granPeriod', namespaces=ns):
                    time_stamp.append(timest.attrib['endTime'])
                    # time_stamp.append(timest.attrib['endTime'])
                    # time_stamp.append(timest.attrib['endTime'])
                #
                for child in root.iterfind('.//pm:measInfo/pm:measType', namespaces=ns):
                    # if not child.attrib['p'] in counter_dict:
                    counter_dict[child.attrib['p']] = child.text
                '''
                populate the counters from xml file into dictionary, collect all the counters values under a counter and store it in list, the dictionary thus creates is a dictionary counter_id with list of values.
                '''
                
                for cell in cells:
                    counter_val[cell] = {}
                    for val in root.iterfind(".//pm:measValue/pm:r", namespaces=ns):
                        if val.attrib['p'] not in counter_val[cell]: 
                            counter_val[cell][val.attrib['p']] = []
                        counter_val[cell][val.attrib['p']].append(val.text)

                '''
                create dictionary from counters & counter values, create dataframe from dictionary for csv creation, counter id is ignored and counter name is retained.
                '''
                #print(len(counter_dict),  ' this are the counter values')
                for i in range(0, len(time_stamp)):
                    # print(i%len(cells))
                    cells_col.append(i%len(cells))

                #print(counter_val, " THIS ARE THE VALUES")

            # print(cells)
                #exit(0)
                # print("HERE")
                for cell in cells:
                    counter = {}
                    for key in counter_dict.keys():
                        if key in counter_val[cell]:
                            counter[counter_dict[key]] = counter_val[cell][key]
                            #print(counter_dict[key], " ------> " , counter_val[cell][key])
                # exit(0)
                    #print(time_stamp)
                    df = pd.DataFrame(dict([(k, pd.Series(v)) for k, v in counter.items()]))
                    #display(df)
                    # print(df)
                    # print(cells_col)

                    #exit(0)
                    #df.insert(loc=0, column='timestamp', value=time_stamp)
                    df.insert(loc=1, column='cell', value=cells_col)
                    '''
                            to save each counter file to csv enable below code !!!
                    '''
                    #df.to_csv(file + '_counters_'+ cell + '.csv', index=False)
                    '''
                    save counters from each cells as dictionary of list in merged counter dict !!!
                    '''
                        
                    if cell not in self.merged_counter:
                        self.merged_counter[cell] = []
                    self.merged_counter[cell].append(df)
                    self.create_csv(cell)



def main():
    directory = sys.argv[1]
    setup = sys.argv[2]
    output_directory = sys.argv[3]
    ns_du = {'pm': 'www.radisys.com/5G/DUmeasData'}
    ns_procmon={'pm' : 'www.radisys.com/5G/PROCMONmeasData'}
    ns_sysmon={'pm' : 'www.radisys.com/5G/SYSMONmeasData'}
    ns_cu={'pm' : 'www.radisys.com/5G/CUmeasData'}

    print(f"Starting PM Counters Parser with directory={directory}, setup={setup}")
    
    du_pm_parser = XMLParser(directory, setup, ns_du)
    procmon_parser = XMLParser(directory, setup, ns_procmon)
    sysmon_parser = XMLParser(directory, setup, ns_sysmon)
    cu_pm_parser = XMLParser(directory, setup, ns_cu)
    # parser.parse_xml(ns)
    threads = []
    threads.append(threading.Thread(target=du_pm_parser.parse_xml_du_cu, args=(ns_du,), name="DU_Parser"))
    threads.append(threading.Thread(target=procmon_parser.parse_xml_procmon_sysmon, args=(ns_procmon,), name="PROCMON_Parser"))
    threads.append(threading.Thread(target=sysmon_parser.parse_xml_procmon_sysmon, args=(ns_sysmon,),  name="SYSMON_Pa`rser"))
    threads.append(threading.Thread(target=cu_pm_parser.parse_xml_du_cu, args=(ns_cu,), 
                                  name="CU_Parser"))
    
    start_time = time.time()
    print("Starting parallel parsing processes...")
    for thread in threads:
        print(f"Starting {thread.name}")
        thread.start()
    
    # Wait for all threads to complete
    for thread in threads:
        thread.join()
        print(f"{thread.name} completed")

    elapsed_time = time.time() - start_time
    print(f"All parsing processes completed in {elapsed_time:.2f} seconds")
    return 0

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)




















