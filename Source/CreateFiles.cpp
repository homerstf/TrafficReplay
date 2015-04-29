//============================================================================
// Name        : CreateFiles.cpp
// Author      : Scott Fortner
// Version     :
// Copyright   : 2015 Scott Fortner
// Description : Creates files for use by "TrafficReplay"
//
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 3 of the License.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with this program.  If not, see <http://www.gnu.org/licenses/>.
//
//============================================================================

#include <iostream>
#include <fstream>
#include <sstream>
#include "mysql_connection.h"
#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <cppconn/resultset.h>
#include <cppconn/statement.h>
#include <cppconn/prepared_statement.h>
#include <vector>
#include <boost/random.hpp>
#include <boost/random/normal_distribution.hpp>
#include <boost/math/distributions/uniform.hpp>
#include <boost/filesystem.hpp>
#include <crafter.h>
#include <sys/stat.h>

using namespace std;
using namespace sql;

typedef unsigned char* byte;

//Globals
Driver* dbDriver;
Connection* dbConnection;
int packet_counter = 0;
int ports[] = {21,22,23,25,53,80,443};
static const vector<int> COMMON_PORTS (ports, ports + sizeof(ports) / sizeof(int) );
static string path;
static int playback_time;
static int total_flows;
static float total_time;
static int total_packet_counter = 0;

//Constants
static int const SYN = 0;
static int const SYN_ACK = 1;
static int const ACK = 2;
static int const FIN = 3;
static int const GET = 4;
static int const DATA = 5;

//Simple method to convert int to string
string intToStr(int num){
    stringstream ss;
    ss << num;
    string str = ss.str();
    return str;
}

string floatToStr(float num){
    //stringstream ss;
    //ss.precision(6);
    //ss << num;
    //string str = ss.str();
    string str =  boost::str(boost::format("%.6f")%num);
    return str;
}

float parseLine(string line){
	float answer;
	int numFields = 1;
	string ans;
	for (unsigned int i=0; i<line.size(); i++){
		if (numFields == 3){
			while(line[i] != ','){
				ans += line[i];
				i++;
			}
			answer = atof(ans.c_str());
			break;
		}
		while (line[i] != ',' and i < line.size()){ i++; }
		numFields++;
	}
	return answer;
}

string applyOffset(string time, string first_time){
	string offset = "";
	unsigned int i = 0;
	while (first_time[i] != '.'){
		offset += first_time[i];
		i++;
	}

	string s, m;
	s = m = "";
	i = 0;
	while (time[i] != '.'){
		s += time[i];
		i++;
	}
	i++;
	while (i<time.size()){
		m += time[i];
		i++;
	}
	int sec = atoi(s.c_str()) - atoi(offset.c_str());

	/*Ensure that the microseconds has appropriate padding ad the end for correct interpretation*/
	/*Exanmple: 7450 should be represented as 745000*/
	if (m.size() < 6){
		int missingZeros = 6-m.size();
		for (int i=0; i<missingZeros; i++){
			m+="0";
		}
	}

	return intToStr(sec) + "." + m;
}

void writeFile(string first_time){

	//Handle File Creation *********************************************************
	string filename = path + "configfiles/ConfigFile.txt";
	Statement* stmt = dbConnection->createStatement();
	ResultSet* res;
	ofstream myfile;
	myfile.open (filename.c_str());

	//Split the result fetching into smaller chunks to allow for very large data sets
	res = stmt->executeQuery("select count(*) from ip4_packets");
	res->next();
	int numResults = res->getInt(1);
	int lower = 0;
	while (lower < numResults){
		string query = "select s_mac, d_mac, time, "
				"src_ip, dst_ip, s_port, d_port, protocol, packet_size, payload_size, packet_counter "
				"from ip4_packets "
				"limit " + intToStr(lower) + ", 600000";
		res = stmt->executeQuery(query);
		lower += 600000;

		while (res->next()) {
			if (myfile.is_open()){ //TCP PACKETS
				myfile << res->getString(1) << "," << res->getString(2) << "," << applyOffset(res->getString(3), first_time) << "," << res->getString(4) << ","
				   << res->getString(5) << "," << res->getInt(6) << "," << res->getInt(7) << "," << res->getInt(8) << ","
				   << res->getInt(9) << "," << res->getInt(10) <<  "," << res->getInt(11) << "\n";
			}
		}
	}
	myfile.close();
	delete stmt;
	delete res;
}

void connectDatabase(){
	try{
		dbDriver = get_driver_instance();
		dbConnection = dbDriver->connect("localhost", "user", "password");
		dbConnection->setSchema("pcapdatabase");
		cout << "Database connection successful" << endl;
	}
	catch (SQLException &e){
		cout << "Unable to connect to database" << endl;
	}
}

struct flowStat {
	int flow_num;
	int protocol;
	int port_one;
	int port_two;
	string ip_one;
	string ip_two;
	float ips_mean;
	float ips_stdev;
	float paysize_mean;
	float paysize_stdev;
	int num_packets;
	float flow_dur;
	float start_time;
	bool is_out;
	int percent_match_first;
};

struct portFlow {
	int port_num;
	flowStat fs;
};

struct portStat {
	int port_num;
	int avg_packets;
	float avg_ifs;
	float avg_duration;
	float avg_packet_size;
	float avg_ips;
	int avg_percent_out_packets;
	int percent_out_start;
};

float getAvgIfs(vector<float> start_times){
	float sum = 0;
	for (unsigned int i=1; i<start_times.size(); i++){
		sum += abs(start_times[i] - start_times[i-1]);
	}
	return sum / (start_times.size() - 1);
}

vector<portStat> getPortStatList(vector<flowStat> fs){

	vector<portStat> psvec;
	vector<vector<portFlow> > pfvec;

	//Initialize each index with a blank placeholder
	for (unsigned int i=0; i<COMMON_PORTS.size(); i++){
		vector<portFlow> vec;
		//vec.push_back(portFlow());
		pfvec.push_back(vec);
	}

	for (unsigned int i=0; i<fs.size(); i++){

		bool is_new = true;
		int port; int portIndex;

		for (unsigned int j=0; j<COMMON_PORTS.size(); j++){ //See if either port is in the list of common ports
			if (fs[i].port_one == COMMON_PORTS[j]){
				portIndex = j;
				port = fs[i].port_one;
				is_new = false;
				fs[i].is_out = false;
				break;
			} else if (fs[i].port_two == COMMON_PORTS[j]){
				portIndex = j;
				port = fs[i].port_two;
				is_new = false;
				fs[i].is_out = true;
				break;
			}
		}

		//Create the portFlow
		portFlow pf;
		pf.port_num = port;
		pf.fs = fs[i];

		if(is_new){ //Add it to the 'other' list, at the end of the vector
			pfvec[COMMON_PORTS.size() - 1].push_back(pf);
		} else { //Add it to the index corresponding to the common port that was matched
			pfvec[portIndex].push_back(pf);
		}
	}

	//For each port group (portFlow), calculate the stats and add the resulting portStat to psvec
	for(unsigned int i = 0; i<pfvec.size(); i++){ //For each port
		int port_num = COMMON_PORTS[i];
		int num_packets_sum = 0;
		vector<float> start_times;
		float durations_sum = 0;
		float avg_packet_sizes_sum = 0;
		float avg_ips_sum = 0;
		int percent_out_packets_sum = 0;
		int out_start_count = 0;

		for(unsigned int j = 0; j<pfvec[i].size(); j++){ //For each flow in that port
			//Add the stats of the flow to the running count for that port
			flowStat fs = pfvec[i][j].fs;
			num_packets_sum += fs.num_packets;
			start_times.push_back(fs.start_time);
			durations_sum += fs.flow_dur;
			avg_packet_sizes_sum += fs.paysize_mean;
			avg_ips_sum += fs.ips_mean;

			if (fs.is_out){
				percent_out_packets_sum += fs.percent_match_first;
				out_start_count++;
			} else {
				percent_out_packets_sum += (100 - fs.percent_match_first);
			}
		}

		//Calculate the combined stats for the port and
		//Create a portStat with these results then add it to the psvec
		int num_flows = pfvec[i].size();
		portStat ps;

		if (num_flows > 0) {
			ps.avg_duration = durations_sum / num_flows;
			ps.avg_ifs = getAvgIfs(start_times);
			ps.avg_ips = avg_ips_sum / num_flows;
			ps.avg_packet_size = avg_packet_sizes_sum / num_flows;
			ps.avg_packets = num_packets_sum /num_flows;
			ps.avg_percent_out_packets = percent_out_packets_sum / num_flows;
			ps.percent_out_start = (out_start_count / num_flows) * 100;
			ps.port_num = port_num;
		} else {
			ps.avg_duration = 0;
			ps.avg_ifs = 0;
			ps.avg_ips = 0;
			ps.avg_packet_size = 0;
			ps.avg_packets = 0;
			ps.avg_percent_out_packets = 0;
			ps.percent_out_start = 0;
			ps.port_num = port_num;
		}

		psvec.push_back(ps);

	}

	return psvec;
}

float getStanDev(vector<float>& list, float mean){

	float newMean = 0.0;
	for (unsigned int i=0; i < list.size(); i++){
		newMean += (pow(list[i]-mean, 2));
	}
	return sqrt(newMean/list.size());
}

float getStanDev(vector<int>& list, float mean){

	float newMean = 0.0;
	for (unsigned int i=0; i < list.size(); i++){
		newMean += (pow(list[i]-mean, 2));
	}
	return sqrt(newMean/list.size());
}

/*These normal values are added to the mean then added to the previoud value before being inserted into the vector
 * This allows for an incremental series of values
 * */
vector<float> getAdjustedNormalDistValues(vector<float>& values, int num_needed, float mean, int seed){

	vector<float> times;
	times.push_back(0.0 + seed); //Begin at time 0.0 seconds + some seed value (in seconds)

	boost::mt19937 rng;
	boost::normal_distribution<> nd(mean, getStanDev(values, mean));
	boost::variate_generator<boost::mt19937&, boost::normal_distribution<> > var_nor(rng, nd);

	for (int i = 0; i < num_needed - 1; i++) {
	  double d = var_nor();
	  while (d < 0){ //Can't accept negative values so we fake it a bit
		  d = var_nor();
	  }
	  float prev_time = times[times.size()-1];
	  times.push_back((prev_time + d));
	}

	return times;
}

/*This simply returns a vector of normal districution values.  They are not incremented in series*/
vector<float> getNormalDistValues(vector<float>& values, int num_needed, float mean){

	vector<float> deviations;

	boost::mt19937 rng;
	boost::normal_distribution<> nd(mean, getStanDev(values, mean));
	boost::variate_generator<boost::mt19937&, boost::normal_distribution<> > var_nor(rng, nd);

	for (int i = 0; i < num_needed; i++) {
	  double d = var_nor();
	  while (d < 0){ //Can't accept negative values so we fake it a bit
		  d = var_nor();
	  }
	  deviations.push_back(d); //TODO: Should this really be mean + d?
	}

	return deviations;
}

vector<float> getNormalDistValues(vector<int>& values, int num_needed, float mean){

	vector<float> deviations;

	boost::mt19937 rng;
	boost::normal_distribution<> nd(mean, getStanDev(values, mean));
	boost::variate_generator<boost::mt19937&, boost::normal_distribution<> > var_nor(rng, nd);

	for (int i = 0; i < num_needed; i++) {
	  double d = var_nor();
	  while (d < 0){ //Can't accept negative values so we fake it a bit
		  d = var_nor();
	  }
	  deviations.push_back(d); //TODO: Should this really be mean + d?
	}

	return deviations;
}

vector<float> getUniformDistValues(float lower, float upper, int num_needed){

	vector<float> values;

	boost::mt19937 rng;
	boost::uniform_real<> nd(lower, upper);
	boost::variate_generator<boost::mt19937&, boost::uniform_real<> > var_nor(rng, nd);


	for (int i = 0; i < num_needed; i++) {
		float d = var_nor();
		values.push_back(d);
	}

	return values;
}

string getRandomIP(){
	return string(intToStr(rand()%256) +"."+ intToStr(rand()%256) +"."+ intToStr(rand()%256) +"."+ intToStr(rand()%256));
}

vector<string> lineParser(string& line){
	int j = 0;
	vector<string> result;

	for (int i=0; i< 11; i++){
		string item = "";
		while (line[j] != ',' and line[j] != '\0'){
			item += line[j];
			j++;
		}
		j++;
		result.push_back(item);
	}

	return result;
}

unsigned char* generatePayload(int size) {
	unsigned char* data;
	data = new unsigned char[size];
	for(int i=0; i<size; i++){
		data[i] = 0;
	}
	return data;
}

void createPacketFileTCP(string data, int flags){

	//Parse the line
	vector<string> vec = lineParser(data);

	Crafter::Packet packet;

	Crafter::Ethernet eth_header;
	eth_header.SetSourceMAC(vec[0]);
	eth_header.SetDestinationMAC(vec[1]);

	Crafter::IP ip_header;
	ip_header.SetSourceIP(vec[3]);
	ip_header.SetDestinationIP(vec[4]);

	Crafter::TCP tcp_header;
	tcp_header.SetSrcPort(atoi(vec[5].c_str()));
	tcp_header.SetDstPort(atoi(vec[6].c_str()));

	switch (flags) {
		case 0: //SYN
			tcp_header.SetFlags(Crafter::TCP::SYN);
			packet = eth_header / ip_header / tcp_header;
			break;
		case 1: //SYN_ACK
			tcp_header.SetFlags(Crafter::TCP::SYN | Crafter::TCP::ACK);
			packet = eth_header / ip_header / tcp_header;
			break;
		case 2: //ACK
			tcp_header.SetFlags(Crafter::TCP::ACK);
			packet = eth_header / ip_header / tcp_header;
			break;
		case 3: //FIN
			tcp_header.SetFlags(Crafter::TCP::FIN);
			packet = eth_header / ip_header / tcp_header;
			break;
		case 4: //GET
		case 5: //DATA
			int payload_size = atoi(vec[9].c_str());
			const unsigned char* payload = generatePayload(payload_size);
			Crafter::RawLayer raw_header(payload, payload_size);
			packet = eth_header / ip_header / tcp_header / raw_header;
			//delete payload; //TODO: Add this and see if it crashes
	}

	//Convert to binary and write to the binary file
	unsigned char* buffer = new unsigned char;
	buffer = (unsigned char*) packet.GetRawPtr();
	size_t packet_size = packet.GetSize();
	string filename = path + "statfiles/bin" + vec[10] + ".bin";
	ofstream stream(filename.c_str(), ios::out | ios::binary);
	stream.write((char*) buffer, packet_size);
	stream.close();
}

void createPacketFileUDP(string data, int flags){

	//Parse the line
	vector<string> vec = lineParser(data);

	Crafter::Packet packet;

	Crafter::Ethernet eth_header;
	eth_header.SetSourceMAC(vec[0]);
	eth_header.SetDestinationMAC(vec[1]);

	Crafter::IP ip_header;
	ip_header.SetSourceIP(vec[3]);
	ip_header.SetDestinationIP(vec[4]);

	Crafter::UDP udp_header;
	udp_header.SetSrcPort(atoi(vec[5].c_str()));
	udp_header.SetDstPort(atoi(vec[6].c_str()));

	//Currently a worthless switch, but put here for expansion
	switch (flags) {
		case 5: //DATA
			int payload_size = atoi(vec[9].c_str());
			const unsigned char* payload = generatePayload(payload_size);
			Crafter::RawLayer raw_header(payload, payload_size);
			packet = eth_header / ip_header / udp_header / raw_header;
			//delete payload; //TODO: Add this and see if it crashes
	}

	//Convert to binary and write to the binary file
	unsigned char* buffer = new unsigned char;
	buffer = (unsigned char*) packet.GetRawPtr();
	size_t packet_size = packet.GetSize();
	string filename = path + "statfiles/bin" + vec[10] + ".bin";
	ofstream stream(filename.c_str(), ios::out | ios::binary);
	stream.write((char*) buffer, packet_size);
	stream.close();
}

void http_packet_generator(vector<vector<string> >& packets_list, vector<portStat>& tcp_ports, int num_flows){

	/*	int port_num;
		int avg_packets;
		float avg_ifs;
		float avg_duration;
		float avg_packet_size;
		float avg_ips;
		int avg_percent_out_packets;
		int percent_out_start;
	*/

	//Calculate the stats of the combined TCP flows.  Uses normal distribution
	vector<float> ifs_values, dur_values, psize_values, ips_values;
	vector<int> npackets_values, out_values, percent_out;
	float ifs_sum = 0.0; float ips_sum = 0.0; //float dur_sum = 0.0;  //float psize_sum = 0.0;
	int npackets_sum = 0; int out_sum = 0; int percent_out_sum = 0;
	for (unsigned int i=0; i<tcp_ports.size(); i++){
		if (tcp_ports[i].avg_packets != 0) {
			ifs_values.push_back(tcp_ports[i].avg_ifs);
			ifs_sum += tcp_ports[i].avg_ifs;

			//dur_values.push_back(tcp_ports[i].avg_duration);
			//dur_sum += tcp_ports[i].avg_duration;

			//psize_values.push_back(tcp_ports[i].avg_packet_size);
			//psize_sum += tcp_ports[i].avg_packet_size;

			ips_values.push_back(tcp_ports[i].avg_ips);
			ips_sum += tcp_ports[i].avg_ips;

			npackets_values.push_back(tcp_ports[i].avg_packets);
			npackets_sum += tcp_ports[i].avg_packets;

			out_values.push_back(tcp_ports[i].avg_percent_out_packets);
			out_sum += tcp_ports[i].avg_percent_out_packets;

			//percent_out.push_back(tcp_ports[i].percent_out_start);
			percent_out_sum += tcp_ports[i].percent_out_start;
		}
	}

	//int seed = 0;
	//vector<float> start_times = getAdjustedNormalDistValues(ifs_values, num_flows, ifs_sum/tcp_ports.size(), seed);
	vector<float> start_times = getUniformDistValues(1.0f, (float) (playback_time * 60), num_flows);
	//vector<float> durations = getNormalDistValues(dur_values, num_flows, dur_sum/tcp_ports.size());
	//vector<float> packet_sizes = getNormalDistValues(psize_values, num_flows, psize_sum/tcp_ports.size());
	vector<float> ips_sizes = getNormalDistValues(ips_values, num_flows, ips_sum/tcp_ports.size());
	vector<float> packet_numbers = getNormalDistValues(npackets_values, num_flows, npackets_sum/tcp_ports.size());
	//vector<float> out_numbers = getNormalDistValues(out_values, num_flows, out_sum/tcp_ports.size());
	//vector<float> percent_out_numbers = getNormalDistValues(percent_out, num_flows, percent_out_sum/tcp_ports.size());
	int num_out_flows = percent_out_sum/tcp_ports.size();

	//Create the packets for each flow and add them to the config list
	int out_flow_counter = 0;

	for (int i=0; i<num_flows; i++){ //For each flow
		int s_port, d_port;

		string mac1, mac2;
		//Determine flow direction via randomn generator, not to exceed to calculated percentage
		if((rand()%100) < 50 and out_flow_counter < num_out_flows){
			//is_out = true;
			out_flow_counter++;
			s_port=80;
			d_port=rand()%655355+1024;
			mac1 = "00:00:00:00:00:00";
			mac2 = "11:11:11:11:11:11";
		} else{
			d_port=80;
			s_port=rand()%655355+1024;
			mac2 = "00:00:00:00:00:00";
			mac1 = "11:11:11:11:11:11";
		}

		//Establish flow specific data, such as IP addresses and ports
		string ip_one = getRandomIP();
		string ip_two = getRandomIP();

		//Determine the individual packet times based on ips from previous packet time, beginning from the flow start time
		float packet_start = start_times[i];

		string line;
		vector<string> vec;
		//Create the 3-way handshake
		line = mac1+","+mac2+","+floatToStr(packet_start)+","+ip_one+","+ip_two+","+intToStr(s_port)+","+intToStr(d_port)+",6,66,0"+","+intToStr(total_packet_counter); //SYN
		createPacketFileTCP(line, SYN); //Craft the packet and make the binary file
		vec.push_back(line);
		vec.push_back(floatToStr(packet_start));
		packets_list.push_back(vec);
		vec.clear();
		total_packet_counter++; cout << ".";

		packet_start += ips_sizes[i];
		line = mac2+","+mac1+","+floatToStr(packet_start)+","+ip_two+","+ip_one+","+intToStr(d_port)+","+intToStr(s_port)+",6,66,0"+","+intToStr(total_packet_counter); //SYN-ACK
		createPacketFileTCP(line, SYN_ACK); //Craft the packet and make the binary file
		vec.push_back(line);
		vec.push_back(floatToStr(packet_start));
		packets_list.push_back(vec);
		vec.clear();
		total_packet_counter++; cout << ".";

		packet_start += ips_sizes[i];
		line = mac1+","+mac2+","+floatToStr(packet_start)+","+ip_one+","+ip_two+","+intToStr(s_port)+","+intToStr(d_port)+",6,66,0"+","+intToStr(total_packet_counter); //ACK
		createPacketFileTCP(line, ACK); //Craft the packet and make the binary file
		vec.push_back(line);
		vec.push_back(floatToStr(packet_start));
		packets_list.push_back(vec);
		vec.clear();
		total_packet_counter++; cout << ".";

		packet_start += ips_sizes[i];
		line = mac2+","+mac1+","+floatToStr(packet_start)+","+ip_two+","+ip_one+","+intToStr(d_port)+","+intToStr(s_port)+",6,624,558"+","+intToStr(total_packet_counter); //GET
		createPacketFileTCP(line, GET); //Craft the packet and make the binary file
		vec.push_back(line);
		vec.push_back(floatToStr(packet_start));
		packets_list.push_back(vec);
		vec.clear();
		total_packet_counter++; cout << ".";

		//Create all data and ack packets and alternate them
		for (int k=0; k < (int) packet_numbers[i] - 8; k++){
			packet_start += ips_sizes[i];
			line = mac2+","+mac1+","+floatToStr(packet_start)+","+ip_two+","+ip_one+","+intToStr(d_port)+","+intToStr(s_port)+",6,1514,1448"+","+intToStr(total_packet_counter); //DATA
			createPacketFileTCP(line, DATA); //Craft the packet and make the binary file
			vec.push_back(line);
			vec.push_back(floatToStr(packet_start));
			packets_list.push_back(vec);
			vec.clear();
			total_packet_counter++;

			packet_start += ips_sizes[i];
			line = mac1+","+mac2+","+floatToStr(packet_start)+","+ip_one+","+ip_two+","+intToStr(s_port)+","+intToStr(d_port)+",6,66,0"+","+intToStr(total_packet_counter); //ACK
			createPacketFileTCP(line, ACK); //Craft the packet and make the binary file
			vec.push_back(line);
			vec.push_back(floatToStr(packet_start));
			packets_list.push_back(vec);
			vec.clear();
			total_packet_counter++;
			k++;
			cout << ".";
		}

		//Create FIN and ACK packets.
		packet_start += ips_sizes[i];
		line = mac1+","+mac2+","+floatToStr(packet_start)+","+ip_one+","+ip_two+","+intToStr(s_port)+","+intToStr(d_port)+",6,66,0"+","+intToStr(total_packet_counter); //FIN
		createPacketFileTCP(line, FIN); //Craft the packet and make the binary file
		vec.push_back(line);
		vec.push_back(floatToStr(packet_start));
		packets_list.push_back(vec);
		vec.clear();
		total_packet_counter++; cout << ".";

		packet_start += ips_sizes[i];
		line = mac2+","+mac1+","+floatToStr(packet_start)+","+ip_two+","+ip_one+","+intToStr(d_port)+","+intToStr(s_port)+",6,66,0"+","+intToStr(total_packet_counter); //ACK
		createPacketFileTCP(line, ACK); //Craft the packet and make the binary file
		vec.push_back(line);
		vec.push_back(floatToStr(packet_start));
		packets_list.push_back(vec);
		vec.clear();
		total_packet_counter++; cout << ".";

		packet_start += ips_sizes[i];
		line = mac2+","+mac1+","+floatToStr(packet_start)+","+ip_two+","+ip_one+","+intToStr(d_port)+","+intToStr(s_port)+",6,66,0"+","+intToStr(total_packet_counter); //FIN
		createPacketFileTCP(line, FIN); //Craft the packet and make the binary file
		vec.push_back(line);
		vec.push_back(floatToStr(packet_start));
		packets_list.push_back(vec);
		vec.clear();
		total_packet_counter++; cout << ".";

		packet_start += ips_sizes[i];
		line = mac1+","+mac2+","+floatToStr(packet_start)+","+ip_one+","+ip_two+","+intToStr(s_port)+","+intToStr(d_port)+",6,66,0"+","+intToStr(total_packet_counter); //ACK
		createPacketFileTCP(line, ACK); //Craft the packet and make the binary file
		vec.push_back(line);
		vec.push_back(floatToStr(packet_start));
		packets_list.push_back(vec);
		total_packet_counter++; cout << ".";
	}
	cout << endl;
}

/*Simulates the data portion of a VOIP session.  No call initiation or tear-down, only UDP data in both directions*/
void voip_packet_generator(vector<vector<string> >& packets_list, vector<portStat>& udp_ports, int num_flows){
	//Calculate the stats of the combined TCP flows.  Uses normal distribution
		vector<float> ifs_values, dur_values, psize_values, ips_values;
		vector<int> npackets_values, out_values, percent_out;
		float ifs_sum = 0.0; float dur_sum = 0.0; float ips_sum = 0.0; //float psize_sum = 0.0;
		int npackets_sum = 0; int out_sum = 0; int percent_out_sum = 0;
		for (unsigned int i=0; i<udp_ports.size(); i++){
			if (udp_ports[i].avg_packets != 0) {
				ifs_values.push_back(udp_ports[i].avg_ifs);
				ifs_sum += udp_ports[i].avg_ifs;

				dur_values.push_back(udp_ports[i].avg_duration);
				dur_sum += udp_ports[i].avg_duration;

				//psize_values.push_back(tcp_ports[i].avg_packet_size);
				//psize_sum += tcp_ports[i].avg_packet_size;

				ips_values.push_back(udp_ports[i].avg_ips);
				ips_sum += udp_ports[i].avg_ips;

				npackets_values.push_back(udp_ports[i].avg_packets);
				npackets_sum += udp_ports[i].avg_packets;

				out_values.push_back(udp_ports[i].avg_percent_out_packets);
				out_sum += udp_ports[i].avg_percent_out_packets;

				//percent_out.push_back(tcp_ports[i].percent_out_start);
				percent_out_sum += udp_ports[i].percent_out_start;
			}
		}

		//int seed = 1;
		//vector<float> start_times = getAdjustedNormalDistValues(ifs_values, num_flows, ifs_sum/udp_ports.size(), seed);
		vector<float> start_times = getUniformDistValues(1.0f, (float) (playback_time*60), num_flows);
		//vector<float> durations = getNormalDistValues(dur_values, num_flows, dur_sum/udp_ports.size());
		//vector<float> packet_sizes = getNormalDistValues(psize_values, num_flows, psize_sum/tcp_ports.size());
		vector<float> ips_sizes = getNormalDistValues(ips_values, num_flows, ips_sum/udp_ports.size());
		vector<float> packet_numbers = getNormalDistValues(npackets_values, num_flows, npackets_sum/udp_ports.size());
		vector<float> out_numbers = getNormalDistValues(out_values, num_flows, out_sum/udp_ports.size());
		//vector<float> percent_out_numbers = getNormalDistValues(percent_out, num_flows, percent_out_sum/tcp_ports.size());
		int num_out_flows = percent_out_sum/udp_ports.size();

		//Create the packets for each flow and add them to the config list
		int out_flow_counter = 0;

		for (int i=0; i<num_flows; i++){ //For each flow
			int s_port, d_port;
			string mac1, mac2;
			//Determine flow direction via randomn generator, not to exceed to calculated percentage
			if((rand()%100) < 50 and out_flow_counter < num_out_flows){
				//is_out = true;
				out_flow_counter++;
				s_port=rand()%655355+1024;
				d_port=rand()%655355+1024;
				mac1 = "00:00:00:00:00:00";
				mac2 = "11:11:11:11:11:11";
			} else{
				d_port=rand()%655355+1024;
				s_port=rand()%655355+1024;
				mac2 = "00:00:00:00:00:00";
				mac1 = "11:11:11:11:11:11";
			}

			//Establish flow specific data, such as IP addresses and ports
			string ip_one = getRandomIP();
			string ip_two = getRandomIP();

			//Determine the individual packet times based on ips from previous packet time, beginning from the flow start time
			float packet_start = start_times[i];

			string line;

			//Create all data and ack packets and alternate them
			int num = (int) packet_numbers[i];
			if (num < 1){
				num = 1;
			}
			for (int k=0; k < num; k++){
				vector<string> vec;
				packet_start += ips_sizes[i];
				line = mac1+","+mac2+","+floatToStr(packet_start)+","+ip_two+","+ip_one+","+intToStr(d_port)+","+intToStr(s_port)+",17,1514,1448,"+intToStr(total_packet_counter); //DATA
				createPacketFileUDP(line, DATA); //Craft the packet and make the binary file
				vec.push_back(line);
				vec.push_back(floatToStr(packet_start));
				packets_list.push_back(vec);
				vec.clear();
				total_packet_counter++;

				packet_start += ips_sizes[i];
				line = mac2+","+mac1+","+floatToStr(packet_start)+","+ip_one+","+ip_two+","+intToStr(s_port)+","+intToStr(d_port)+",17,1514,1448,"+intToStr(total_packet_counter); //DATA
				createPacketFileUDP(line, DATA); //Craft the packet and make the binary file
				total_packet_counter++;
				vec.push_back(line);
				vec.push_back(floatToStr(packet_start));
				packets_list.push_back(vec);
				k++;
				cout << ".";
			}
		}
		cout << endl;
}

//Used by sort function to compare the order of packets based on time
bool compareTimes(vector<string>& a, vector<string>& b){
	bool ans = atof(a[1].c_str()) < atof(b[1].c_str());
	return ans;
}


void flowGenerator(vector<portStat>& tcp_ports, vector<portStat>& udp_ports, int percent_tcp){
	vector<vector<string> > packets;

	//Calculate the total number of flows for the given time period
	int num_flows = int((total_flows / total_time) * (playback_time*60)); //total_time is in seconds and playback_time is in minutes
	int tcp_flows_count = num_flows * ((float) percent_tcp / (float) 100);
	int udp_flows_count = num_flows * ((float) (100-percent_tcp) / (float) 100);

	//Create the tcp flows spread out over the requested time period (% of total)
	//To expand this, determine the number of flows per common port and call a custom packet generator for each type of traffic
	//Call http_packet_generator for each flow
	cout << "Generating TCP packets" << endl;
	http_packet_generator(packets, tcp_ports, tcp_flows_count);
	cout << "TCP packets complete" << endl << endl;

	//Create the udp flows spread out over the requested time period (% of total)
	//To expand this, determine the number of flows per common port and call a custom packet generator for each type of traffic
	//Call voip_packet_generator for each flow
	cout << "Generating UDP packets" << endl;
	voip_packet_generator(packets, udp_ports, udp_flows_count);
	cout << "UDP packets complete" << endl << endl;

	//Rearrange the packets according to time order
	cout << "Sorting packets by time" << endl;
	std::sort(packets.begin(), packets.end(), compareTimes);
	cout << "Sorting complete" << endl << endl;

	//Write the packets to the config file
	cout << "Writing config file" << endl;
	string filename = path + "configfiles/StatConfigFile.txt";
	ofstream myfile;
	myfile.open (filename.c_str());

	if (myfile.is_open()){ //TCP PACKETS
		for (unsigned int i=0; i<packets.size(); i++){
			myfile << packets[i][0] << "\n";
		}
		myfile.close();
	}
	cout << "Config file complete" << endl << endl;
}

void generateStats(){
	cout << "Generating Statistics" << endl;

	//Initialize
	float percent_tcp;
	vector<flowStat> tcp_flows;
	vector<flowStat> udp_flows;

	//Collect stats from DB
	Statement* stmt = dbConnection->createStatement();
	ResultSet* res;

	//Retrive the total number of flows in the capture
	res = stmt->executeQuery("select count(distinct(flow_num)) from ip4_flows");
	res->next();
	total_flows = res->getInt(1);

	stmt->close();
	delete stmt;
	delete res;
	stmt = dbConnection->createStatement();

	//Retrive to total time of the capture
	res = stmt->executeQuery("select max(time), min(time) from ip4_packets");
	res->next();
	total_time = atof(res->getString(1).c_str()) - atof(res->getString(2).c_str());

	stmt->close();
	delete stmt;
	delete res;
	stmt = dbConnection->createStatement();

	//Get the rest of the stats
	res = stmt->executeQuery("select * from ip4_stats");
			/* 1. flow_num INT			8. ips_stdev FLOAT
			 * 2. protocol INT			9. paysize_mean FLOAT
			 * 3. port_one INT			10. paysize_stdev FLOAT
			 * 4. port_two INT			11. num_packets INT
			 * 5. ip_one varchar(30)	12. flow_dur FLOAT
			 * 6. ip_two varchar(30)	13. start_time FLOAT
			 * 7. ips_mean FLOAT		14. dir_match_percent FLOAT
			*/
	stmt->close();
	delete stmt;

	//Split flows between TCP and UDP
	while (res->next()) {
		flowStat fs;
		fs.flow_num = res->getInt(1);
		fs.protocol = res->getInt(2);
		fs.port_one = res->getInt(3);
		fs.port_two = res->getInt(4);
		fs.ip_one = res->getString(5);
		fs.ip_two = res->getString(6);
		fs.ips_mean = res->getDouble(7);
		fs.ips_stdev = res->getDouble(8);
		fs.paysize_mean = res->getDouble(9);
		fs.paysize_stdev = res->getDouble(10);
		fs.num_packets = res->getInt(11);
		fs.flow_dur = res->getDouble(12);
		fs.start_time = res->getDouble(13);
		fs.percent_match_first = int(res->getDouble(14));

		if (res->getInt(2) == 6) { //Add to TCP vector
			tcp_flows.push_back(fs);

		} else { //Add to UDP vector
			udp_flows.push_back(fs);
		}
	}

	cout << "Complete" << endl << endl;

	//Set the TCP percentage
	percent_tcp = ((float) tcp_flows.size() / (float) total_flows) * 100;

	//Get list of port numbers and aggregated stats for TCP
	vector<portStat> tcp_ports = getPortStatList(tcp_flows);

	//Get list of port numbers and aggregated stats for UDP
	vector<portStat> udp_ports = getPortStatList(udp_flows);

	//Call the Flow Generator to generate config file and packets from config file
	flowGenerator(tcp_ports, udp_ports, percent_tcp);

	delete res;
}

/*Verify folder exists and that old files are removed before beginning*/
int checkDirectory(string folder){

	struct stat sb;

	cout << "Deleting old files" << endl;
	if (stat(folder.c_str(), &sb) == 0 && S_ISDIR(sb.st_mode)) {
	    //Delete the folders contents
		boost::filesystem::remove_all(folder);
	}

	boost::filesystem::path dir(folder);
	if(boost::filesystem::create_directory(dir)) {
		std::cout << "Empty Folder Created" << endl;
	} else {
		return 0;
	}

	return 1;
}


/*Arguments:
 * 			-path to folder location
 * 			-include stats (0 or 1)
 * 			-playback duration in minutes
*/
int main(int argc, char** argv) {

	if (argc < 2 and atoi(argv[2]) == 0) {
		cout << "Please enter the file path (ex: /myfiles/ or /) and a 0 or 1 for statistical playback.  Quitting." << endl;
		return 0;
	} else if((argc < 3) and (atoi(argv[2]) == 1)){
		cout << "Please enter the file path (ex: /myfiles/ or /), a 1 for statistical playback, and the playback time in whole minutes.  Quitting." << endl;
		return 0;
	}
	path = argv[1];

	cout << "Connecting to database." << endl;
	connectDatabase();
	string choice = argv[2];
	if (choice == "1") {
		//First ensure there's a folder for the files
		if (!checkDirectory(path + "statfiles")){
			cout << "Error finding path for binary files." << endl;
			return 0;
		}
		cout << "Writing stats files." << endl;
		playback_time = atoi(argv[3]);
		generateStats();
		cout << "Complete." << endl;
	}else {
		//First ensure there's a folder for the files
		if (!checkDirectory(path + "replayfiles")){
			cout << "Error finding path for binary files." << endl;
			return 0;
		}

		//Verify folder for config file exists
		if (!checkDirectory(path + "configfiles")){
			cout << "Error folder for config file." << endl;
			return 0;
		}

		//Determine time offset
		Statement* stmt = dbConnection->createStatement();
		ResultSet* res;
		res = stmt->executeQuery("select time from ip4_packets limit 1");
		res->next();
		string first_time = res->getString(1);

		delete stmt; delete res;

		cout << "Writing config file." << endl;
		writeFile(first_time);
		cout << "Complete." << endl;
	}

	dbConnection->close();
	return 0;
}
