#!/usr/bin/python3
import requests
import json 
import argparse
import os
import sys
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Date, and_ 
from sqlalchemy.orm import declarative_base, sessionmaker 

# DRUPAL REF API : https://www.drupal.org/drupalorg/docs/apis/rest-and-other-apis
# DRUPAL MODULE LIST : https://drupal.org/files/releases.tsv

__VERSION__ = "0.1"
DRUPAL_API_URL_SA = "https://www.drupal.org/api-d7/node.json?type=sa"
VERBOSE = False
DEBUG = False

# CLASS DEFINITION
Base = declarative_base() 

# Class Drupal Project
class Project(Base):
    __tablename__ = 'projects'
    internal_id = Column(Integer, primary_key = True)
    project_id = Column(Integer)
    name = Column(String)


# Class Drupal Advisory
class Advisory(Base):
    __tablename__ = 'advisories'
    
    advisory_id = Column(Integer, primary_key = True)
    title = Column(String)
    criticality = Column(String)
    crit_ac = Column(String)
    crit_a = Column(String)
    crit_ci = Column(String)
    crit_ii = Column(String)
    crit_e = Column(String)
    crit_td = Column(String)
    url = Column(String)
    date_creation = Column(Date())
    project_id = Column(Integer)
    project_name = Column(String)
    project_url = Column(String)
    affected_version = Column(String)
    sa_type = Column(String)
    cve = Column(String)
    nid = Column(String)
 
    def as_dict(self):
        return {c.name: str(getattr(self, c.name)) for c in self.__table__.columns}

    def as_print(self):
        output = ""
        output += f"    [>] {self.project_name} ({self.date_creation}): '{self.title}'\r\n"
        output += f"         Crit  : {self.criticality}\r\n"
        if DEBUG:
            output += f"            AC: {self.crit_ac}\r\n"
            output += f"            A : {self.crit_a}\r\n"
            output += f"            CI: {self.crit_ci}\r\n"
            output += f"            II: {self.crit_ii}\r\n"
            output += f"            E : {self.crit_e}\r\n"
            output += f"            TD: {self.crit_td}\r\n"
        output += f"         Type  : {self.sa_type}\r\n"
        cve = json.loads(self.cve)
        if cve == []:
            cve = "N/A"
        else:
            cve = ", ".join(cve)
        output += f"         CVE   : {cve}\r\n"
        output += f"         URL   : {self.url}\r\n"
        output += f"         Vers. : {self.affected_version}\r\n"
        return output


# Class OptionFormatter for ArgParse
class OptionFormatter(argparse.ArgumentDefaultsHelpFormatter,
                      argparse.RawDescriptionHelpFormatter):
    pass


################# HTTP CODE

def get_http(url):
    try:
        http_resp = requests.get(url,verify=True)
    except:
        print(f"Error HTTP Request to {url}") 
        sys.exit(1)
    
    if http_resp.status_code==200:
        return http_resp.status_code,http_resp.text
    else:
        if VERBOSE: print(f"Error HTTP {http_resp.status_code} : Request to {url}")
        if DEBUG: print(http_resp.text)
        return http_resp.status_code,""


def get_http_json_advisories(page):
    url = f"{DRUPAL_API_URL_SA}&page={page}"
    return get_http(url)


def get_http_json_project(project_url):
    url = f"{project_url}.json"
    return get_http(url)


def get_http_json_advisories_default():
    url = f"{DRUPAL_API_URL_SA}"
    return get_http(url)


def parse_advisories_default(http_json_advisory_default):
    json_advisory_default = json.loads(http_json_advisory_default)
    try:
        url_max_page = json_advisory_default['last']
    except:
        return 0
    max_page = url_max_page.split("page=")[1]
    return int(max_page)


def parse_project(http_json_project):
    json_project = json.loads(http_json_project)
    try:
        project_name = json_project['field_project_machine_name']
    except:
        project_name = "Error_No_Project_Name"
    return project_name


def get_project_name(project_url):
    if project_url == "Error_No_Project_URL":
        return "Error_Invalid_Project_URL"
    http_code,http_json_project = get_http_json_project(project_url)
    project_name = parse_project(http_json_project)
    return project_name


def parse_advisory(json_advisory):
    # Parse JSON advisory and extract key information
    advisory = Advisory()
    
    # "title": "Drupal core - Critical - Arbitrary PHP code execution - SA-CORE-2020-013"
    try:
        advisory.title = json_advisory['title']
    except:
        advisory.title = "Error_No_Title"

    # "field_sa_criticality": "AC:Basic/A:Admin/CI:Some/II:Some/E:Theoretical/TD:All"
    #     AC Access complexity
    #     A	 Authentication
    #     CI Confidentiality impact
    #     II Integrity impact
    #     E	 Exploit (Zero-day impact)
    #     TD Target distribution
    try: 
        advisory.criticality = json_advisory['field_sa_criticality']
        advisory_criticality_split = advisory.criticality.split("/")
        advisory.crit_ac = advisory_criticality_split[0].split(":")[1]
        advisory.crit_a = advisory_criticality_split[1].split(":")[1]
        advisory.crit_ci = advisory_criticality_split[2].split(":")[1]
        advisory.crit_ii = advisory_criticality_split[3].split(":")[1]
        advisory.crit_e = advisory_criticality_split[4].split(":")[1]
        advisory.crit_td = advisory_criticality_split[5].split(":")[1]
    except: 
        advisory.criticality = "Error_No_Criticality"
        advisory.crit_ac = "Error_No_AC"
        advisory.crit_a = "Error_No_A"
        advisory.crit_ci = "Error_No_CI"
        advisory.crit_ii = "Error_No_II"
        advisory.crit_e = "Error_No_E"
        advisory.crit_td = "Error_No_TD"
     
    # "url": "https://www.drupal.org/sa-core-2020-013"
    try:
        advisory.url = json_advisory['url']
    except:
        advisory.url = "Error_No_URL"
     
    # "created": "1606348668"
    try:
        advisory_timestamp = json_advisory['created']
        advisory_date_creation = datetime.utcfromtimestamp(int(advisory_timestamp)).strftime('%Y-%m-%d')
        advisory.date_creation = datetime.strptime(advisory_date_creation , '%Y-%m-%d')
    except:
        advisory.date_creation = "Error_No_Date_Creation"
 
    # "field_project": {
    #     "uri": "https://www.drupal.org/api-d7/node/3060",
    #     "id": "3060"
    # ... }    
    try:
        advisory.project_id = int(json_advisory['field_project']['id'])
    except:
        advisory.project_id = "Error_No_Project_ID"
     
    try:
        advisory.project_url = json_advisory['field_project']['uri']
    except: 
        advisory.project_url = "Error_No_Project_URL"
    
    # "nid": "3184889"
    try:
        advisory.nid = json_advisory['nid']
    except:
        advisory.nid = "Error_No_Nid"
     
    # "field_sa_type": "Arbitrary PHP code execution"
    try:
        advisory.sa_type = json_advisory['field_sa_type']
    except:
        advisory.sa_type = "Error_No_Type"
     
    # "field_sa_cve": [ "CVE-2020-28949", "CVE-2020-28948" ]
    try:
        advisory.cve = json.dumps(json_advisory['field_sa_cve'])
    except:
        advisory.cve = "Error_No_CVE"
    
    try:
        advisory.affected_version = json_advisory['field_affected_versions']
    except:
        advisory.affected_version = "Error_No_Affected_Version"
    
    return advisory


def parse_advisories(session, http_json_advisories,update_mode):
    json_page_advisories = json.loads(http_json_advisories)
    json_advisories = json_page_advisories['list']
    
    if update_mode=="full":
        list_json_advisories = json_advisories
    else:
        list_json_advisories = reversed(json_advisories)
    
    for json_advisory in list_json_advisories:
        advisory = parse_advisory(json_advisory)
        
        # Check if advisory (nid) already exists in database 
        if sql_check_exists_nid(session,advisory.nid):
            if DEBUG: print(f"Record nid:{advisory.nid} already exists")
            if update_mode=="incremental":
                # Stop incremental update, last_advisory is already in database
                return True
            else:
                # Should not happen in normal mode
                continue
        
        # Find project name from project id
        if sql_check_exists_project_id(session,advisory.project_id):
            if DEBUG: print(f"Project ID : {advisory.project_id} found in database")
            #Get Project Name from Project Table
            advisory.project_name = sql_get_project_name(session,advisory.project_id)
        else:
            if DEBUG: print(f"Project ID : {advisory.project_id} not found in database")
            # Request project name from API
            advisory.project_name = get_project_name(advisory.project_url)
            
            if DEBUG: print(f"Project '{advisory.project_name}' found for Project ID {advisory.project_id} from URL Query") 
            # Store Project Name and Project ID in Table
            sql_add_project(session, advisory.project_id, advisory.project_name)
        
        # Store Advisory in Database
        sql_add_advisory(session, advisory)
                             
        if VERBOSE or DEBUG :
            print(f"        + {advisory.nid} ({advisory.date_creation}): {advisory.project_name} - '{advisory.title}'")
         
    return False


def get_last_advisory_nid(http_json_advisories):
    json_page_advisories = json.loads(http_json_advisories)
    try:
        json_advisories = json_page_advisories['list']
        last_advisory = json_advisories[len(json_advisories)-1]
        nid = last_advisory['nid']
    except: 
        return "error"
    return nid


def get_max_advisories_page():
    http_code,http_json_advisories_default = get_http_json_advisories_default()
    if http_code!=200:
        return 0
    max_page = parse_advisories_default(http_json_advisories_default)
    return max_page
 
 
################# UPDATE CODE 

def check_update(session):
    print("[+] Checking update for Drupal Security Advisories")
    
    max_page = get_max_advisories_page()
    if not(max_page):
        print("Error while retrieving update status")
        return False
    
    http_code,http_json_advisories = get_http_json_advisories(max_page)
    if http_code!=200:
        print("Error while retrieving update status")
        return False
    
    nid = get_last_advisory_nid(http_json_advisories)
    if sql_check_exists_nid(session,nid):
        print("[>] Database already up to date")
        print()
        return False
    else:
        print("[>] Update required")
        print()
        return True
 
 
def update_advisories(session,update_mode):
    print(f"[>] Updating Drupal Security Advisories Database ({update_mode} update)")
    print()
    print("        !!! DO NOT PRESS [CTRL+C] OR INTERRUPT PROCESS !!!")
    print()
    
    max_page = get_max_advisories_page()
    if not(max_page):
        print("Error while retrieving update")
        return False
    
    if update_mode=="full":
        page_numbers = range(0,max_page+1)
    elif update_mode=="incremental":
        page_numbers = range(max_page,0,-1)
    elif update_mode=="test":
        page_numbers = range(max_page,max_page-1,-1)
    else:
        page_numbers = range(0,0)
    
    for page in page_numbers:
        if VERBOSE:
            if update_mode=="full":
                print(f"        (F) Parsing Drupal Security Advisories : Page {page+1}/{max_page+1}")
            elif update_mode=="incremental":
                print(f"        (I) Parsing Drupal Security Advisories : Page {max_page-page+1}/{max_page+1}")
        http_code,http_json_advisories = get_http_json_advisories(page)
        if http_code!=200:
            print("Error while retrieving update status")
            return False
        update_finished = parse_advisories(session,http_json_advisories,update_mode)
        if(update_finished):
            print("[>] Incremental update finished")
            return
    print("[>] Full update finished")


def update_manager(sqlite_database,full_update,update_check):
    global VERBOSE

    if not(os.path.isfile(sqlite_database)) or full_update:
        # First run/deleted database file or Full update requested
        if full_update:
            print("[+] Performing full database update")
        else:
            print("[+] First launch detected, creating initial database...")
        session = init_database(sqlite_database)
        stored_verbose = VERBOSE
        VERBOSE = True
        sql_clear_all_data(session)
        try:
            update_advisories(session,"full")
        except:
            sql_clear_all_data(session)
            print("[!] Update aborted : DATABASE IS IN INCORRECT STATE, FULL UPDATE REQUIRED")
            print("[>] Next time perform full update with option '-fu' or '--full-update'")
            sys.exit(1)
        VERBOSE = stored_verbose
    else:
        # Normal run
        session = init_database(sqlite_database)
        # Check if database update is needed
        if update_check :
            if check_update(session):
                print("[+] Performing incremental database update")
                stored_verbose = VERBOSE
                VERBOSE = True
                try:
                    update_advisories(session,"incremental")
                except: 
                    print("[!] Update aborted : DATABASE IS IN INCORRECT STATE, FULL UPDATE REQUIRED")
                    print("[>] Next time perform full update with option '-fu' or '--full-update'")
                    sys.exit(1)
                VERBOSE = stored_verbose
        else:
            print("[+] Skipping update check")
            print()
    if VERBOSE:
        num_advisory = session.query(Advisory.advisory_id).count()
        print(f"[+] {num_advisory} advisories in database")
        print()
    return session


################# DATABASE CODE

def create_db_engine(filename):
    engine = create_engine(f"sqlite:///{filename}")
    return engine


def init_database(filename):
    engine = create_db_engine(filename)
    Base.metadata.create_all(engine) 
    Session = sessionmaker(bind=engine) 
    session = Session() 
    return session


def sql_check_exists_nid(session,advisory_nid):
    nid_exists = session.query(Advisory)\
        .filter(Advisory.nid==advisory_nid)\
        .first() is not None
    return nid_exists


def sql_add_advisory(session, advisory):
    if sql_check_exists_nid(session,advisory.nid):
        if DEBUG: print(f"Record nid:{advisory.nid} already exists")
        return True
      
    session.add(advisory)
    session.commit()
    if DEBUG: print(f"Record nid:{advisory.nid} successfully added")
    return False


def sql_find_advisory_for_module(session,module,exploit_only,year):
    if year!="":
        try:
            int_year = int(year)
            year = datetime.strptime(f"{year}-01-01", '%Y-%m-%d')
        except:
            print(f"Invalid Year value '{year}' provided, ignoring it")
            year = ""
                
    # Build Query
    query = session.query(Advisory).filter(Advisory.project_name==module)
    
    if exploit_only:
        query = query.filter(and_(Advisory.crit_e!='Theoretical',
                                  Advisory.criticality!='Error_No_Criticality'))

    if year!="":
        query = query.filter(Advisory.date_creation>=year)
    
    return query.all(),query.count()


def sql_check_exists_project_id(session,project_id):
    project_id_exists = session.query(Project)\
        .filter(Project.project_id==project_id)\
        .first() is not None
    return project_id_exists


def sql_get_project_name(session,project_id):
    result = session.query(Project)\
        .filter(Project.project_id==project_id)\
        .first()
    return result.name
 
 
def sql_add_project(session, project_id, project_name):
    if sql_check_exists_project_id(session,project_id):
        if DEBUG: print(f"Record project_id:{project_id} already exists")
        return True
    
    project = Project(project_id = project_id,
                      name = project_name)
                                            
    session.add(project)
    session.commit()
    if DEBUG: print(f"Record project_id:{project_id} successfully added")
    return False


def sql_clear_all_advisories(session):
    if DEBUG: print("[+] Flushing existing advisory data")
    rows_deleted = session.query(Advisory).delete()
    if DEBUG: print(f"[>] {rows_deleted} Rows deleted")
    return rows_deleted


def sql_clear_all_projects(session):
    if DEBUG: print("[+] Flushing existing projects data")
    rows_deleted = session.query(Project).delete()
    if DEBUG: print(f"[>] {rows_deleted} Rows deleted")
    return rows_deleted

def sql_clear_all_data(session):
    sql_clear_all_advisories(session)
    sql_clear_all_projects(session)

#################    MAIN CODE

def write_file(filename,data):
    try:
        myfile = open(filename,"w")
        myfile.write(data)
        myfile.close()
    except:
        print(f"Error writing to file '{filename}'")
        return
    
    print(f"Output written to file '{filename}'")
    return


def build_module_list(module,input_file):
    modules = []
    if input_file!="":
        myfile = open(input_file,"r")
        for line in myfile:
            modules.append(line.rstrip())
        myfile.close()
    elif module!="":
        if "," in module:
            module_list = module.split(",")
            for single_module in module_list:
                modules.append(single_module)
        else:
            modules.append(module)
    else:
        print("No Drupal module provided : Use '-m' with module name or '-i' with input file. Use '-h' or '--help' for Help")
        sys.exit(1)
    return modules

    
def find_vuln_modules(session,modules,exploit_only,output_json,year):
    # Prepare output
    if output_json:
        results = {}
    else:
        results = ""
    # Find vuln for modules 
    for module in modules:
        if VERBOSE: print(f"[+] Searching module '{module}'")
        advisories,nb_advisories = sql_find_advisory_for_module(session,module,exploit_only,year)
        if nb_advisories != 0:
            if output_json:
                module_results_output = []
                for advisory in advisories:
                    module_results_output.append(advisory.as_dict())
                results[module] = module_results_output
            else:
                module_results_output    = ""
                module_results_output += f"[+] {module} : {nb_advisories} advisory found \r\n"
                for advisory in advisories:
                    module_results_output += advisory.as_print()
                results += module_results_output
    return results

    
def display_results(results,output_json,filename):
    # Diplay output or save in file
    if VERBOSE:
        print("[>] Showing results")
        print()
    if(output_json):
        if output_file!="":
            write_file(output_file,json.dumps(results))
        else:
            print(json.dumps(results))
    else:
        if output_file!="":
            write_file(output_file,results)
        else:
            print(results)


################# ARGUMENTS CODE

def load_arguments(args):
    global DEBUG
    global VERBOSE 
    
    module = args.module
    input_file = args.input_file
    exploit_only = args.exploit_only
    year = args.year
    output_json = args.json
    output_file = args.output_file
    update_check = not(args.no_update)
    full_update = args.full_update
    database = args.database
    DEBUG = args.debug
    VERBOSE = args.verbose 
    
    if DEBUG:
        VERBOSE = True
    
    if DEBUG : 
        display_arguments(module, input_file, exploit_only, year, output_json,
                          output_file, update_check, full_update, database)

    check_arguments(module, input_file, exploit_only, year, output_json, 
                    output_file, update_check, full_update, database)

    return (module, input_file, exploit_only, year, output_json, \
            output_file, update_check, full_update, database)


def display_arguments(module, input_file, exploit_only, year, 
                      output_json, output_file, update_check,
                      full_update, database):
    print("[+] Arguments")
    print(f"    [>] Module : {module}")
    print(f"    [>] Input File : {input_file}")
    print(f"    [>] Exploit-Only : {exploit_only}")
    print(f"    [>] Year : {year}")
    print(f"    [>] JSON Output : {output_json}")
    print(f"    [>] Output File : {output_file}")
    print(f"    [>] No Update : {not(update_check)}")
    print(f"    [>] Full Update : {full_update}")
    print(f"    [>] Database File : {database}")
    print(f"    [>] Debug : {DEBUG}")
    print(f"    [>] Verbose : {VERBOSE}")
    print()


def check_arguments(module, input_file, exploit_only, year,
                    output_json, output_file, update_check,
                    full_update, database):
    if not(update_check) and full_update:
        print("Incompatible options -nu/--no-update and -fu/--full-update selected, choose one")
        sys.exit(1)
    
    if input_file!="":
        if not(os.path.isfile(input_file)):
            print(f"Input file '{input_file}' does not exist")
            sys.exit(1)


def print_banner():
    print(f"drupalcapwn v{__VERSION__} : Drupal Module Vulnerability Checker")
    print()
 
        
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='python3 ./drupalcapwn.py',
        description=f"drupalcapwn v{__VERSION__} : Drupal Module Vulnerability Checker",
        epilog='''
Examples:
    %(prog)s -m drupal -e -j
    %(prog)s -i input.txt -o output.txt -nu
    ''',
        formatter_class= OptionFormatter)
    
    parser.add_argument('-m','--module',type=str,default="",help='Drupal module name to look for, separated by commas (IE: -m drupal, -m webform,restws)')
    parser.add_argument('-i','--input-file',type=str,default="",help='File containing module names, one by line') 
    parser.add_argument('-e','--exploit-only',default=False,action="store_true",help="Display only vulnerabilities with available exploit (IE: not 'Theoretical' vulnerabilities)")
    parser.add_argument('-y','--year',type=str,default="",help="Oldest year to start looking for advisories")
    parser.add_argument('-j','--json',default=False,action="store_true",help="Output vulnerability results in JSON")
    parser.add_argument('-o','--output-file',type=str,default="",help="Output vulnerability results in specific file")
    parser.add_argument('-nu','--no-update',default=False,action="store_true",help='Disable automatic update check')
    parser.add_argument('-fu','--full-update',default=False,action="store_true",help='Force full update')
    parser.add_argument('-db','--database',type=str,default="advisories_drupal.db",help="Specify Database filename")
    parser.add_argument('-d','--debug',default=False,action="store_true",help="Display debug information")
    parser.add_argument('-v','--verbose',default=False,action="store_true",help="Verbose mode")
    
    args = parser.parse_args()
    
    # Display start up banner
    print_banner()
    
    # Load and check arguments
    (module, input_file, exploit_only, year, output_json, output_file,
     update_check, full_update, database) = load_arguments(args)
    
    # Check for update and get session on database
    session = update_manager(database, full_update, update_check)
        
    # Build module list to check
    modules = build_module_list(module,input_file)
    
    # Find vulns for modules
    results = find_vuln_modules(session, modules, exploit_only, output_json, year)
    
    # Display vuln results
    display_results(results, output_json, output_file)
    
    sys.exit(0)