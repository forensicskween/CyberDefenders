
import pandas
import os
from Registry import *
import json
import sqlite3
import ast


def do_events(db_path):
	conn = sqlite3.connect(db_path)
	df_evt = pandas.read_sql("SELECT * FROM TIMELINE;", conn)
	df_evt['Sysinfo'] = df_evt['Sysinfo'].apply(lambda x: ast.literal_eval(x))
	df_sysinfo = pandas.json_normalize(df_evt['Sysinfo'])
	df_sysinfo[['Computer','Provider', 'SID','PID', 'ThreadID', 'Channel']] = df_evt[['Computer','Provider', 'SID','PID', 'ThreadID', 'Channel']]
	cols = ['Version', 'Opcode', 'PID', 'ThreadID']
	df_sysinfo[cols] = df_sysinfo[cols].astype('Int64')
	df_evt['Sysinfo'] = df_sysinfo.apply(lambda x: json.dumps(x.dropna().to_dict(), indent=4),axis=1)
	df_info = df_evt[['EventID', 'EventRecordID']].copy()
	df_evt['Information'] = df_info.apply(lambda x: json.dumps(x.dropna().to_dict(), indent=4),axis=1)
	df_evt['Data'] = df_evt.EventData.fillna(df_evt.UserData)
	df_evt['RecordType'] = 'EventLogs'
	df_evt = df_evt[['Filename', 'Timestamp', 'Information', 'Sysinfo', 'Data', 'RecordType']]
	return df_evt

column_names = ['Filename', 'Timestamp', 'Information', 'Sysinfo', 'Data', 'RecordType']

def recurse_reg(key, hive_name):
    rows = []
    row = {key: [] for key in column_names}
    row['Filename'] = hive_name
    if key._nkrecord.has_parent_key():
        row['Information'] = key._nkrecord.path()
        if key._nkrecord.timestamp() is not None:
            ts = key._nkrecord.timestamp()
            row['Timestamp'] = str(ts).split('.')[0]
        else:
            row['Timestamp'] = ''
        if key._nkrecord.values_number() > 0:
            ss = key._nkrecord.values_list().values()
            for v in ss:
                row['Sysinfo'] = {'Name': v.name(), 'ValueType': v.data_type_str()}
                try:
                    row['Sysinfo']['Value'] = str(v.data())
                except Exception:
                    pass
                row['Data'] = v.raw_data()
        rows.append(row)
    for subkey in key.subkeys():
        recurse_reg(subkey,hive_name)
    return rows


def do_registry(dir):
 dat = []
 for file in os.listdir(dir):
    f = os.path.join(dir, file)
    _hive = Registry.Registry(f)
    _hive_name = _hive.hive_type().value
    dat.append(recurse_reg(_hive.root(),_hive_name))
 return dat

def do_users(dir1):
 del rows
 dat = []
 for root, dirs, files in os.walk(dir1):
    for file in files:
        if file.endswith(".DAT"):
            f = os.path.join(root, file)
            pp = root.replace(dir1, '').split()[0]
            rows = []
            _hive = Registry.Registry(f)
            _hive_name = pp + '-' + _hive.hive_type().value
            dat.append(recurse_reg(_hive.root(),_hive_name))
 return dat



def registry_to_df(reg_data):
	flat_data = [item for sublist in reg_data for item in sublist]
	df_reg = pandas.DataFrame(flat_data,columns = column_names)
	df_reg = df_reg.mask(df_reg.applymap(type).eq(list) & ~df_reg.astype(bool))
	df_reg['RecordType'] = 'Windows Registry'
	df_reg['Sysinfo'] = df_reg['Sysinfo'].apply(lambda x: json.dumps(x, indent=4))
	df_reg = df_reg[['Filename', 'Timestamp', 'Information', 'Sysinfo', 'Data', 'RecordType']]
	return df_reg

#prefetch_csv = path to prefetch_run_counts.csv

def do_prefetch(prefetch_csv):
	prefetch_df = pandas.read_csv(prefetch_csv)
	prefetch_df.fillna('', inplace=True)
	prefetch_df['Timestamp'] = prefetch_df['last_run_time ']
	prefetch_df['Filename'] = prefetch_df['exe_file ']
	prefetch_df['RecordType'] = 'Prefetch'
	temp_info = prefetch_df[['pf_run_count ', 'pf_file ', 'pf_hash ']]
	prefetch_df['Information'] = temp_info.apply(lambda x: json.dumps(x.dropna().to_dict(), indent=4),axis=1)
	temp_sysinfo = prefetch_df[['volume_count ', 'volume_timestamp ', 'volume_dev_path ', 'volume_serial_number ', 'volume_timestamp .1', 'volume_dev_path .1', 'volume_serial_number']]
	prefetch_df['Sysinfo'] = temp_sysinfo.apply(lambda x: json.dumps(x.dropna().to_dict(), indent=4),axis=1)
	prefetch_df['Data'] = prefetch_df['pf_run_count ']
	prefetch_df = prefetch_df[['Filename', 'Timestamp', 'Information', 'Sysinfo', 'Data', 'RecordType']]
	return prefetch_df


def do_mft(mft_csv):
	mft_df = pandas.read_csv(mft_csv)
	mft_df['RecordType'] = 'MFT ' + mft_df['Source']
	mft_df.fillna('', inplace=True)
	mft_df['Filename'] = mft_df['Path']
	mft_sysinfo = mft_df[['Is in use', 'Is directory','File size']]
	mft_data = mft_df[['$SI M timestamp','$SI A timestamp', '$SI C timestamp', '$SI E timestamp','$SI USN value', '$FN M timestamp', '$FN A timestamp','$FN C timestamp', '$FN E timestamp', '$OBJID timestamp','WSL M timestamp', 'WSL A timestamp', 'WSL CH timestamp']]
	mft_info = mft_df[['Log file sequence number','MFT reference number']]
	mft_df['Sysinfo'] = mft_sysinfo.apply(lambda x: json.dumps(x.dropna().to_dict(), indent=4),axis=1)
	mft_df['Data'] = mft_data.apply(lambda x: json.dumps(x.dropna().to_dict(), indent=4),axis=1)
	mft_df['Information'] = mft_info.apply(lambda x: json.dumps(x.dropna().to_dict(), indent=4),axis=1)
	mft_df['$FN M timestamp'] = mft_df['$FN M timestamp'].replace('', np.NaN)
	mft_df['Timestamp'] = mft_df['$FN M timestamp'].fillna(mft_df['$SI M timestamp'])
	mft_df = mft_df[['Filename', 'Timestamp', 'Information', 'Sysinfo', 'Data', 'RecordType']]
	return mft_df

#vol_sqlite path to volatility2 timeliner sqlite

def vol_ts(item):
	item['Timestamp'] = item['Timestamp'].split(' UTC')[0]
	return item

def do_vol_tl(vol_sqlite):
	con = sqlite3.connect(vol_sqlite)
	vol_df = pandas.read_sql_query("SELECT * from TimeLiner", con)
	vol_df.rename(columns = {'Start':'Timestamp', 'Details': 'RawData', 'Item': 'Filename', 'Header': 'Information'}, inplace=True)
	vol_df['RecordType'] = 'VolatilityTimeline'
	vol_df.rename(columns = {'Path':'Filename'}, inplace=True)
	vol_df.drop(['id'], axis=1, inplace=True)
	vol_df = vol_df.apply(lambda r: vol_ts(r), axis=1)
	con.close()
	return vol_df
df_vol = do_vol_tl(vol_db)


prefetch_csv = 'parsed/Prefetch_run_count.csv'
mft_csv = 'parsed/parsed_mft.csv'

df_events = do_events(db_path)

reg_events = do_registry(dir)
reg_events.append(do_users(dir1))
df_reg = registry_to_df(reg_data)

prefetch_df = do_prefetch(prefetch_csv)

df_mft = do_mft(mft_csv)

frames = [df_evt, df_reg,prefetch_df, df_mft]
final_frame = pandas.DataFrame()
for k in frames:
    final_frame = final_frame.append(k)



conn_out = sqlite3.connect("CyberCorp-TL.db")
final_frame.to_sql("Timeline", conn_out, index=False)
conn_out.close()
