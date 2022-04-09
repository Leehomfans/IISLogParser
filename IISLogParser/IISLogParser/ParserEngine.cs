using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace IISLogParser
{
    public class ParserEngine : IDisposable
    {
        private readonly StreamReader _logfile;

        private string[] _headerFields;

        private Hashtable dataStruct = new Hashtable();

        private readonly int _mbSize;

        public string FilePath
        {
            get;
            set;
        }

        public bool MissingRecords
        {
            get;
            private set;
        } = true;


        public int MaxFileRecord2Read
        {
            get;
            set;
        } = 1000000;


        public int CurrentFileRecord
        {
            get;
            private set;
        }

        public ParserEngine(string filePath)
        {
            if (File.Exists(filePath))
            {
                FilePath = filePath;
                FileStream stream = new FileStream(FilePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                _logfile = new StreamReader(stream);

                _mbSize = (int)new FileInfo(filePath).Length / 1024 / 1024;
                return;
            }

            throw new Exception("Could not find File " + filePath);
        }

        public IEnumerable<IISLogEvent> ParseLog()
        {
            if (_mbSize < 50)
            {
                return QuickProcess();
            }

            return LongProcess();
        }

        private IEnumerable<IISLogEvent> QuickProcess()
        {
            List<IISLogEvent> list = new List<IISLogEvent>();
            List<string> logList = new List<string>();
            while (true)
            {
                string line = _logfile.ReadLine();
                if (string.IsNullOrEmpty(line))
                {
                    break;
                }
                logList.Add(line);

            }
            foreach (string line in logList)
            {
                ProcessLine(line, list);
            }

            MissingRecords = false;
            return list;
        }

        private IEnumerable<IISLogEvent> LongProcess()
        {
            List<IISLogEvent> list = new List<IISLogEvent>();
            MissingRecords = false;
            string line;
            while (!string.IsNullOrEmpty(line = _logfile.ReadLine()))
            {
                ProcessLine(line, list);
                if (list != null && list.Count > 0 && list?.Count % MaxFileRecord2Read == 0)
                {
                    MissingRecords = true;
                    break;
                }
            }

            return list;
        }

        private void ProcessLine(string line, List<IISLogEvent> events)
        {
            if (line.StartsWith("#Fields:"))
            {
                _headerFields = line.Replace("#Fields: ", string.Empty).Split(' ');
            }

            if (!line.StartsWith("#") && _headerFields != null)
            {
                string[] fieldsData = line.Split(' ');
                FillDataStruct(fieldsData, _headerFields);
                events?.Add(NewEventObj());
                CurrentFileRecord++;
            }
        }

        private IISLogEvent NewEventObj()
        {
            return new IISLogEvent
            {
                DateTimeEvent = GetEventDateTime(),
                sSitename = dataStruct["s-sitename"]?.ToString(),
                sComputername = dataStruct["s-computername"]?.ToString(),
                sIp = dataStruct["s-ip"]?.ToString(),
                csMethod = dataStruct["cs-method"]?.ToString(),
                csUriStem = dataStruct["cs-uri-stem"]?.ToString(),
                csUriQuery = dataStruct["cs-uri-query"]?.ToString(),
                sPort = ((dataStruct["s-port"] != null) ? new int?(int.Parse(dataStruct["s-port"]?.ToString())) : null),
                csUsername = dataStruct["cs-username"]?.ToString(),
                cIp = dataStruct["c-ip"]?.ToString(),
                csVersion = dataStruct["cs-version"]?.ToString(),
                csUserAgent = dataStruct["cs(User-Agent)"]?.ToString(),
                csCookie = dataStruct["cs(Cookie)"]?.ToString(),
                csReferer = dataStruct["cs(Referer)"]?.ToString(),
                csHost = dataStruct["cs-host"]?.ToString(),
                scStatus = ((dataStruct["sc-status"] != null) ? new int?(int.Parse(dataStruct["sc-status"]?.ToString())) : null),
                scSubstatus = ((dataStruct["sc-substatus"] != null) ? new int?(int.Parse(dataStruct["sc-substatus"]?.ToString())) : null),
                scWin32Status = ((dataStruct["sc-win32-status"] != null) ? new long?(long.Parse(dataStruct["sc-win32-status"]?.ToString())) : null),
                scBytes = ((dataStruct["sc-bytes"] != null) ? new int?(int.Parse(dataStruct["sc-bytes"]?.ToString())) : null),
                csBytes = ((dataStruct["cs-bytes"] != null) ? new int?(int.Parse(dataStruct["cs-bytes"]?.ToString())) : null),
                timeTaken = ((dataStruct["time-taken"] != null) ? new int?(int.Parse(dataStruct["time-taken"]?.ToString())) : null)
            };
        }

        private DateTime GetEventDateTime()
        {
            return DateTime.Parse(string.Format("{0} {1}", dataStruct["date"], dataStruct["time"]));
        }

        private void FillDataStruct(string[] fieldsData, string[] header)
        {
            dataStruct.Clear();
            for (int i = 0; i < header.Length; i++)
            {
                dataStruct.Add(header[i], (fieldsData[i] == "-") ? null : fieldsData[i]);
            }
        }

        public void Dispose()
        {
            _logfile?.Close();
        }
    }
}
