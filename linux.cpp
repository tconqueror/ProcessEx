#include <sys/types.h>
#include <dirent.h>
#include <string> 
#include <iostream>
#include <string.h>
#include <fstream>
#include <sstream>

using namespace std;

bool isDigit(char * pos)
{
    while (*pos > '0' && *pos <'9') pos ++;
    return !(*pos);
}

int main()
{
    DIR* dirp = opendir("/proc");
    if (dirp == NULL)
        return 1;
    struct dirent * dp;
    while ((dp = readdir(dirp)) != NULL)
    {
        if (dp->d_type == DT_DIR && isDigit(dp->d_name))
        {
            string name;
            string pid = dp->d_name;
            string ppid = "N/A";
            string cmdline = "N/A";
            string c_dir = "/proc/" + (string)(dp->d_name);
            DIR * c_dirp = opendir(c_dir.c_str());
            if (c_dirp == NULL)
                continue;
            ifstream status;
            status.open((c_dir + "/status").c_str());
            if (!status)
                continue;
            string line = "";
            while (getline(status,line))
            {
                string temp;
                stringstream ss;
                ss << line;
                ss >> temp;
                if (!(temp.compare("Name:")))
                {
                    ss >> temp;
                    name = temp;
                    continue;
                }
                if (!(temp.compare("PPid:")))
                {
                    ss >> temp;
                    ppid = temp;
                    continue;
                }
            }
            status.close();
            ifstream cline;
            cline.open((c_dir + "/cmdline").c_str());
            if (cline)
            {
                getline(cline, cmdline);
            }
            cout << "Process ID: " << pid << endl;
            cout << "Process Name: " << name << endl;
            cout << "Parent Process ID: " << ppid << endl;
            cout << "Commandline: " << (cmdline.size() ? cmdline : "N/A") << endl;
            cout  << "............................................................................." << endl;
        } 
    }
    return 0;
}
