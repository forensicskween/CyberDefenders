import pandas
import os
import json
import sqlite3
import sys
import numpy as np

def do_events(directory):
    records = []
    for file in os.listdir(directory):
        filename = os.path.join(directory, file)
        records.append(get_event_records(filename))
    return records

def get_event_records(filename):
    f = open(filename, "r")
    file_content = f.readlines()
    fixed = []
    events = []
    d = " }{"
    for line in file_content:
        if d in line:
            new_line = line.replace(d, "}NEWJSON{")
            fixed.append(new_line)
        else:
            fixed.append(line)
    fixed_file = "".join(fixed)
    jsons = fixed_file.split("NEWJSON")
    for i in range(len(jsons)):
        json_dat = json.loads(jsons[i])
        json_dat["Filename"] = os.path.basename(filename).replace(".txt", "")
        events.append(json_dat)
    return events


event_column_names = ['Filename', 'System', 'UserData', 'EventData']

def events_to_data_frame(_event_records):
    flat_records = [item for sublist in _event_records for item in sublist]
    df = pandas.DataFrame(flat_records, columns = event_column_names)
    df_sys = pandas.json_normalize(df['System'])
    df_sys = df_sys.applymap(lambda x: np.nan if isinstance(x, str) and x == '' else x)
    df_sys['Filename'] = df['Filename']
    cols = ['Version', 'Opcode', 'Execution.ProcessID', 'Execution.ThreadID', 'EventID.Qualifiers']
    df_sys[cols] = df_sys[cols].astype('Int64')
    df_sysinfo = df_sys[['Version', 'Level', 'Task', 'Opcode', 'Keywords', 'Provider.Guid', 'Provider.EventSourceName', 'Correlation.ActivityID']]
    df_sys['Sysinfo'] = df_sysinfo.apply(lambda x: json.dumps(x.dropna().to_dict(), indent=4),axis=1)
    df_sys = df_sys.drop(['Version', 'Level', 'Task', 'Opcode', 'Keywords', 'Provider.Guid', 'Provider.EventSourceName', 'Correlation.ActivityID'], axis=1)
    df_sys = df_sys.rename(columns={'TimeCreated.SystemTime': 'Timestamp', 'Execution.ProcessID': 'PID', 'Execution.ThreadID': 'ThreadID', 'Security.UserID': 'SID', 'EventID.Qualifiers': 'Qualifier', 'Provider.Name': 'Provider', 'EventID.Value': 'EventID'})
    df_sys['EventData'] = df['EventData'].apply(lambda x: json.dumps(x, indent=4)if type(x) != float else x)
    df_sys['UserData'] = df['UserData'].apply(lambda x: json.dumps(x, indent=4) if type(x) != float else x)
    df_sys['Timestamp'] = pandas.to_datetime(df_sys['Timestamp'], unit="s").dt.strftime("%Y-%m-%d %H:%M:%S")
    df_sys = df_sys[['EventRecordID', 'Timestamp', 'EventID', 'Computer', 'EventData', 'Sysinfo', 'Provider', 'SID','UserData', 'PID', 'ThreadID', 'Channel', 'Filename']]
    return df_sys


def main():
    print("Usage: python3 evtx2db.py input_directory output_dbname")
    directory = sys.argv[1]
    db_name = sys.argv[2]
    event_records = do_events(directory)
    df_evt = events_to_data_frame(event_records)
    connection = sqlite3.connect(db_name)
    df_evt.to_sql("TIMELINE", connection, if_exists="replace", index=False)

if __name__ == '__main__':
  main()
