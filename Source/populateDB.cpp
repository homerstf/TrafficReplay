//============================================================================
// Name        : populateDB.cpp
// Author      : Scott Fortner
// Version     :
// Copyright   : 2015 Scott Fortner
// Description :Populates DB with pcap headers and creates packet binary files
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
//============================================================================

#include <iostream>
#include <fstream>
#include <vector>
#include <crafter.h>
#include "mysql_connection.h"
#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <cppconn/resultset.h>
#include <cppconn/statement.h>
#include <cppconn/prepared_statement.h>
#include <bitset>
#include "StatHolder.h"
#include <math.h>
#include <sys/stat.h>
#include <dirent.h>
#include <boost/filesystem.hpp>

using namespace std;
using namespace Crafter;
using namespace sql;

typedef unsigned char byte;

//Globals
Driver* dbDriver;
Connection* dbConnection;
static int numPackets = 0;
static int flowNumber = 1;
static int packet_counter = 0;
static string path;

//Simple method to convert int to string
string intToStr(int num){
    stringstream ss;
    ss << num;
    string str = ss.str();
    return str;
}

//Converts the timeval struct to a string representing a float.
//If usec is less than 6 characters then leading zeros were removed
//and need to added back in.
string convertTS(timeval ts){
	string oldUsec = intToStr(ts.tv_usec);
	string newUsec = "";

	int missingZeros = 6 - oldUsec.size();
	for (int i=0; i < missingZeros; i++){
		newUsec += "0";
	}
	newUsec += oldUsec;
	return intToStr(ts.tv_sec) + "." + newUsec;
}

/*Add IPv4 header data to ip4_header table*/
void processIp4Packet(Packet* packet){

	Ethernet* eth_layer = GetEthernet(*packet);
	IP* ip_layer = GetIP(*packet);
	PreparedStatement* prepStmt;
	unsigned char* buffer = new unsigned char;
	int protocol = ip_layer->GetProtocol();
	size_t packet_size = packet->GetSize();

	//Check for malformed packets based on stated vs actual length
	int totlen = ip_layer->GetTotalLength();
	int iphlen = ip_layer->GetHeaderLength()*4;
	if (((protocol == 6) and ((totlen - iphlen) < 20)) or ((protocol == 17) and ((totlen - iphlen) < 8)) or ((int) packet_size < totlen)) {
		return;
	}

	/*Handle the raw packet*/
	buffer = (unsigned char*) packet->GetRawPtr();
	string filename = path + "replayfiles/bin" + intToStr(packet_counter) + ".bin";
	ofstream stream(filename.c_str(), ios::out | ios::binary);
	stream.write((char*) buffer, packet_size);
	stream.close();

	//PreparedStatement* prepStmt;
	prepStmt = dbConnection->prepareStatement("INSERT INTO ip4_packets (time, s_mac, d_mac, src_ip, dst_ip, s_port, d_port, protocol, seq_num, packet_size, payload_size, packet_counter, is_retrans) values(?,?,?,?,?,?,?,?,?,?,?,?,?)");
	prepStmt->setString(1, convertTS(packet->GetTimestamp()));
	prepStmt->setString(2, eth_layer->GetSourceMAC());
	prepStmt->setString(3, eth_layer->GetDestinationMAC());
	prepStmt->setString(4, ip_layer->GetSourceIP());
	prepStmt->setString(5, ip_layer->GetDestinationIP());
	prepStmt->setInt(8, protocol);
	prepStmt->setInt(10, packet_size);
	prepStmt->setInt(12, packet_counter);
	prepStmt->setBoolean(13, 0); //is_retrans
	if (protocol == 6){ //TCP
		TCP* tcp = GetTCP(*packet);
		prepStmt->setInt(6, tcp->GetSrcPort());
		prepStmt->setInt(7, tcp->GetDstPort());
		prepStmt->setUInt(9, tcp->GetSeqNumber());
		prepStmt->setInt(11, ip_layer->GetTotalLength() - ip_layer->GetHeaderLength()*4 - tcp->GetDataOffset()*4);
	} else if(protocol == 17){ //UDP
		UDP* udp = GetUDP(*packet);
		prepStmt->setInt(6, udp->GetSrcPort());
		prepStmt->setInt(7, udp->GetDstPort());
		prepStmt->setInt(9, 0); //Seq_num
		prepStmt->setInt(11, totlen - iphlen - udp->GetLength());
	} else {
		prepStmt->close();
		delete prepStmt;
		return; //Not UDP or TCP so don't process it
	}
	prepStmt->executeUpdate();
	prepStmt->close();
	delete prepStmt;
	++packet_counter;
}

/*Handle IPv6 packet*/
void processIp6Packet(Packet* packet){

	Ethernet* eth_layer = GetEthernet(*packet);
	IP* ip_layer = GetIP(*packet);
	PreparedStatement* prepStmt;
	int protocol = ip_layer->GetProtocol();

	/*Handle the raw packet*/
	size_t packet_size = packet->GetSize();
	const unsigned char* buffer = new unsigned char;
	buffer = packet->GetRawPtr();
	string filename = path + "replayfiles/bin" + intToStr(packet_counter) + ".bin";
	ofstream stream(filename.c_str(), ios::out | ios::binary);
	stream.write((char*) buffer, packet_size);
	stream.close();

	prepStmt = dbConnection->prepareStatement("INSERT INTO ip6_packets (time, s_mac, d_mac, src_ip, dst_ip, s_port, d_port, protocol, seq_num, packet_size, payload_size, packet_counter, is_retrans) values(?,?,?,?,?,?,?,?,?,?,?,?,?)");
	prepStmt->setString(1, convertTS(packet->GetTimestamp()));
	prepStmt->setString(2, eth_layer->GetSourceMAC());
	prepStmt->setString(3, eth_layer->GetDestinationMAC());
	prepStmt->setString(4, ip_layer->GetSourceIP());
	prepStmt->setString(5, ip_layer->GetDestinationIP());
	prepStmt->setInt(8, protocol);
	prepStmt->setInt(10, packet_size);
	prepStmt->setInt(12, packet_counter);
	prepStmt->setBoolean(13, 0);

	if (protocol == 6){ //TCP
		TCP* tcp = GetTCP(*packet);
		prepStmt->setInt(6, tcp->GetSrcPort());
		prepStmt->setInt(7, tcp->GetDstPort());
		prepStmt->setUInt(9, tcp->GetSeqNumber());
		prepStmt->setInt(11, tcp->GetPayloadSize());
	} else if (protocol == 17){ //UDP
		UDP* udp = GetUDP(*packet);
		prepStmt->setInt(6, udp->GetSrcPort());
		prepStmt->setInt(7, udp->GetDstPort());
		prepStmt->setInt(9, 0);
		prepStmt->setInt(11, udp->GetPayloadSize());
	}else {
		prepStmt->close();
		delete prepStmt;
		return; //Not UDP or TCP so don't process it
	}
	prepStmt->executeUpdate();
	prepStmt->close();
	delete prepStmt;
	++packet_counter;
	//if (buffer != NULL) {delete buffer;}
}

/* Handles each packet read from the PCAP file.  Called by readpcap() */
void PacketHandler(Packet* sniff_packet, void* user) {
	try {
		if (GetIP(*sniff_packet)){
			processIp4Packet(sniff_packet);
			numPackets += 1;
		}else if (GetIPv6(*sniff_packet)){
			processIp6Packet(sniff_packet);
			numPackets += 1;
		}
	} catch (SQLException &e){
		cout << "SQL Error: " << e.getErrorCode() << endl;
	} catch (...) {
		cout << "Packet not processed due to unknown error.  Might be a corrupt packet." << endl;
		//if (buffer != NULL) {delete buffer;}
	}

	/*Progress Indicator for user*/
	//cout << numPackets << endl;
	if (numPackets % 20 == 0) {
		cout << numPackets << " Packets processed." << endl;
	}
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

struct flowSpecs {
	int id;
	string src_ip;
	string dst_ip;
	int s_port;
	int d_port;
};

/*Determines TCP flows by examining packet data and populates tcp_flow table with results.
 * Uses socket pair to determine if the packets belong to the same flow
 * */
void handleTCP(int type){
	cout << "Adding TCP Flows for IPv" + intToStr(type) + "." << endl;
	ResultSet* res;
	Statement *stmt;
	stmt = dbConnection->createStatement();

	if (type == 4){ //IPv4
		res = stmt->executeQuery("select packet_id, src_ip, dst_ip, "
			"s_port, d_port from ip4_packets "
			"where protocol = 6 and is_retrans = 0");
	}else{ //IPv6
		res = stmt->executeQuery("select packet_id, src_ip, dst_ip, "
			"s_port, d_port from ip6_packets "
			"where protocol = 6 and is_retrans = 0");
	}

	vector<flowSpecs> flowVector; //Essentially a vector of structs that each contain the packet id and socket pair
	map<int,vector<int> > flowDict; //key is the packet id of the first packet with a specific socket pair
	while (res->next()) {
		bool add = true;
		for (unsigned int i=0; i<flowVector.size(); i++){
			if (res->getString(2) == flowVector[i].src_ip and res->getString(3) == flowVector[i].dst_ip
			                and res->getInt(4) == flowVector[i].s_port and res->getInt(5) == flowVector[i].d_port){
				add = false;
				int id = flowVector[i].id;
				flowDict[id].push_back(res->getInt(1));
				break;
			}else if (res->getString(3) == flowVector[i].src_ip and res->getString(2) == flowVector[i].dst_ip
			                and res->getInt(5) == flowVector[i].s_port and res->getInt(4) == flowVector[i].d_port){
				int id = flowVector[i].id;
				add = false;
				flowDict[id].push_back(res->getInt(1));
				break;
			}
		}
		if (add == true){
			flowSpecs fs;
			fs.id = res->getInt(1);
			fs.src_ip = res->getString(2);
			fs.dst_ip = res->getString(3);
			fs.s_port = res->getInt(4);
			fs.d_port = res->getInt(5);
			flowVector.push_back(fs);
			flowDict[fs.id].push_back(fs.id);
		}
	}

	  for (map<int,vector<int> >::iterator it=flowDict.begin(); it!=flowDict.end(); ++it){
		//PreparedStatement* ps;

		/*if (type == 4){
			ps = dbConnection->prepareStatement("INSERT INTO ip4_flows (packet_num, flow_num) values(?,?)");
		}else{
			ps = dbConnection->prepareStatement("INSERT INTO ip6_flows (packet_num, flow_num) values(?,?)");
		}

		ps->setInt(1, it->first);
		ps->setInt(2, flowNumber);
		ps->executeUpdate();*/

		for (vector<int>::iterator it2=it->second.begin(); it2!=it->second.end(); ++it2){
			PreparedStatement* ps;

			if (type == 4){
				ps = dbConnection->prepareStatement("INSERT INTO ip4_flows (packet_num, flow_num) values(?,?)");
			}else{
				ps = dbConnection->prepareStatement("INSERT INTO ip6_flows (packet_num, flow_num) values(?,?)");
			}
				ps->setInt(1, *it2);
				ps->setInt(2, flowNumber);
				ps->executeUpdate();
				ps->close();
				delete ps;
		}
		flowNumber++;
	}
	  delete res;
	  delete stmt;
	cout << "TCP Flows complete" << endl;
}

/*Determines UDP flows by examining packet data and populates udp_flow table with results.
 * Uses socket pair to determine if the packets belong to the same flow
 * */
void handleUDP(int type){
	cout << "Adding UDP Flows for IPv" + intToStr(type) + "." << endl;
	ResultSet* res;
	Statement *stmt;
	stmt = dbConnection->createStatement();

	if (type == 4){ //IPv4
		res = stmt->executeQuery("select packet_id, src_ip, dst_ip, "
			"s_port, d_port from ip4_packets "
			"where protocol = 17 and is_retrans = 0");
	}else{ //IPv6
		res = stmt->executeQuery("select packet_id, src_ip, dst_ip, "
			"s_port, d_port from ip6_packets "
			"where protocol = 17 and is_retrans = 0");
	}
	vector<flowSpecs> flowVector;
	map<int,vector<int> > flowDict;
	while (res->next()) {
		bool add = true;
		for (unsigned int i=0; i<flowVector.size(); i++){
			if (res->getString(2) == flowVector[i].src_ip and res->getString(3) == flowVector[i].dst_ip
			                and res->getInt(4) == flowVector[i].s_port and res->getInt(5) == flowVector[i].d_port){
				add = false;
				int id = flowVector[i].id;
				flowDict[id].push_back(res->getInt(1));
				break;
			}else if (res->getString(3) == flowVector[i].src_ip and res->getString(2) == flowVector[i].dst_ip
			                and res->getInt(5) == flowVector[i].s_port and res->getInt(4) == flowVector[i].d_port){
				int id = flowVector[i].id;
				add = false;
				flowDict[id].push_back(res->getInt(1));
				break;
			}
		}
		if (add == true){
			flowSpecs fs;
			fs.id = res->getInt(1);
			fs.src_ip = res->getString(2);
			fs.dst_ip = res->getString(3);
			fs.s_port = res->getInt(4);
			fs.d_port = res->getInt(5);
			flowVector.push_back(fs);
			flowDict[fs.id].push_back(fs.id);
		}
	}

	  for (map<int,vector<int> >::iterator it=flowDict.begin(); it!=flowDict.end(); ++it){
		//PreparedStatement* ps;

		/*if (type == 4){
			ps = dbConnection->prepareStatement("INSERT INTO ip4_flows (packet_num, flow_num) values(?,?)");
		}else{
			ps = dbConnection->prepareStatement("INSERT INTO ip6_flows (packet_num, flow_num) values(?,?)");
		}

		ps->setInt(1, it->first);
		ps->setInt(2, flowNumber);
		ps->executeUpdate();*/

		for (vector<int>::iterator it2=it->second.begin(); it2!=it->second.end(); ++it2){
			PreparedStatement* ps;

			if (type == 4){
				ps = dbConnection->prepareStatement("INSERT INTO ip4_flows (packet_num, flow_num) values(?,?)");
			}else{
				ps = dbConnection->prepareStatement("INSERT INTO ip6_flows (packet_num, flow_num) values(?,?)");
			}
			ps->setInt(1, *it2);
			ps->setInt(2, flowNumber);
			ps->executeUpdate();
			ps->close();
			delete ps;
		}
		flowNumber++;
	}
	  delete res;
	  delete stmt;
	cout << "UDP Flows complete" << endl;
}

/*Calls function to populate flow tables*/
void handleFlows(){
	handleTCP(4); //IPv4
	//handleTCP(6); //IPv6
	handleUDP(4); //IPv4
	//handleUDP(6); //IPv6
}

void markRetrans(int type){
	vector<vector<int> > tcp_packets;
	vector<int> retransList;
	ResultSet* res;
	ResultSet* macRes;
	Statement* stmt;
	stmt = dbConnection->createStatement();
	string statement;
	string srcMAC, dstMAC;

	/*get list of sequence numbers, packet ids and payload sizes*/
	if (type == 4){
		macRes = stmt->executeQuery("SELECT s_mac from ip4_packets limit 1");

		macRes->next();
		srcMAC = macRes->getString(1);

		statement = "SELECT packet_id, seq_num, payload_size, s_mac "
				"from ip4_packets "
				"where protocol = 6 and s_mac = '" + srcMAC + "'";
	}else{
		macRes = stmt->executeQuery("SELECT s_mac, d_mac from ip4_packets limit 1");

		macRes->next();
		srcMAC = macRes->getString(1);

		statement = "SELECT packet_id, seq_num, payload_size, s_mac "
						"from ip6_packets "
						"where protocol = 6 and s_mac = '" + srcMAC + "'";
	}
	res = stmt->executeQuery(statement);

	/*Sort through list and find any duplicates*/
	/*Check payload size of duplicates and add those that aren't zero or one to a list*/
	/*This has to be done twice to account for packets in both directions*/
	while (res->next()){
		if(res->getString(4) != srcMAC){
			continue;
		}
		int seq_num = res->getUInt(2);
		int size = res->getInt(3);
		bool do_push = true;
		//bool is_match = false;
		for (unsigned int i=0; i<tcp_packets.size(); i++){
			if (seq_num == tcp_packets[i][1]){
				do_push = false;
				if (size > 1){
					retransList.push_back(res->getInt(1));
				}
				break;
			}
		}
		if (do_push and size > 1){
			tcp_packets.push_back(vector<int>(res->getInt(1), seq_num));
		}
	}

	res->first();
	tcp_packets.clear();

	while (res->next()){
		if(res->getString(4) == srcMAC){
			continue;
		}
		int seq_num = res->getUInt(2);
		bool do_push = true;
		for (unsigned int i=0; i<tcp_packets.size(); i++){
			if (seq_num == tcp_packets[i][1]){
				if (res->getInt(3) > 1){
					retransList.push_back(res->getInt(1));
				}else {
					do_push = false;
				}
			}
		}
		if (do_push){
			tcp_packets.push_back(vector<int>(res->getInt(1), seq_num));
		}
	}

	/*Go back through the database and mark all of those that are in the list*/
	if (type == 4){
		for (unsigned int i=0; i<retransList.size(); i++){
			statement = "UPDATE ip4_packets "
			"SET is_retrans = 1 "
			"WHERE packet_id = " + intToStr(retransList[i]);
			stmt->executeUpdate(statement);
		}
	}else {
		for (unsigned int i=0; i<retransList.size(); i++){
			statement = "UPDATE ip6_packets "
			"SET is_retrans = 1 "
			"WHERE packet_id = " + intToStr(retransList[i]);
			stmt->executeUpdate(statement);
		}
	}
}

float getMean(vector<float>& list){

	float mean = 0.0;
	for(unsigned int j = 0; j<list.size(); j++){
		mean += list[j];
	}
	mean = mean/list.size();
	return mean;
}
float getMean(vector<int>& list){

	float mean = 0.0;
	for(unsigned int j = 0; j<list.size(); j++){
		mean += list[j];
	}
	mean = mean/list.size();
	return mean;
}

float getStanDev(vector<float>& list, float mean){

	float newMean = 0.0;
	for (unsigned int i=0; i < list.size(); i++){
		newMean += (pow(list[i]-mean, 2));
	}
	return newMean/list.size();
}

float getStanDev(vector<int>& list, float mean){

	float newMean = 0.0;
	for (unsigned int i=0; i < list.size(); i++){
		newMean += (pow(list[i]-mean, 2));
	}
	return sqrt(newMean/list.size());
}

void decodeTime(string time, int& sec, int& msec){
	string s, m;
	s = m = "";
	unsigned int i = 0;
	while (time[i] != '.'){
		s += time[i];
		i++;
	}
	i++;
	while (i<time.size()){
		m += time[i];
		i++;
	}
	sec = atoi(s.c_str());
	/*Ensure that the microseconds has appropriate padding ad the end for correct interpretation*/
	/*Exanmple: 7450 should be represented as 745000*/
	if (m.size() < 6){int missingZeros = 6-m.size();
		for (int i=0; i<missingZeros; i++){
			m+="0";
		}
	}
	msec = atoi(m.c_str());
}

float subtractTimes(int& sec1, int& msec1, int&sec2, int& msec2){
	int sec = sec2-sec1;
	int msec;
	if (msec2 > msec1){
		msec = msec2-msec1;
	}else {
		sec--;
		msec = 1000000 - msec1 + msec2;
	}
	string time = intToStr(sec) + "." + intToStr(msec);
	return atof(time.c_str());
}

void computeStats(){

	ResultSet* res;
	Statement *stmt;
	stmt = dbConnection->createStatement();

	//Initialize the data structure that will temporarily hold our stat data before adding it to the database
	vector<StatHolder> *statVector;
	statVector = new vector<StatHolder>;

	//Determine number of flows
	res = stmt->executeQuery("select max(flow_num) from ip4_flows");
	res->next();
	int lastFlowNum = res->getInt(1);
	delete res;

	//Get earliest time to use in normalizing all other time values
	res = stmt->executeQuery("select min(time) from ip4_packets");
	res->next();
	int firstSeconds, firstMSeconds;
	decodeTime(res->getString(1), firstSeconds, firstMSeconds);
	delete res;

	for (int i = 0; i < lastFlowNum; i++){
		res = stmt->executeQuery("select count(*) from ip4_flows where flow_num = " + intToStr(i+1));
		res->next();
		statVector->push_back(StatHolder(i+1, res->getInt(1))); //Sets the flow numbers and the number of packets in the flow
		delete res;

		/*Determine spacing between the packets in each flow then calculate the mean and standard deviation for each flow*/
		vector<string> times;
		vector<int> sizes;
		res = stmt->executeQuery("select time, payload_size from ip4_flows "
				"inner join ip4_packets "
				"on packet_num = packet_id "
				"where flow_num = " + intToStr(i+1));

		while (res->next()){
			times.push_back(res->getString(1));
			sizes.push_back(res->getInt(2));
		}
		delete res;
		vector<float> spaces;

		if (times.size() > 1) { //Make sure the flow has more than one packet
			for (unsigned int j=0; j<times.size() - 1; j++){
				int sec1, msec1, sec2, msec2;
				decodeTime(times[j], sec1, msec1);
				decodeTime(times[j+1], sec2, msec2);
				spaces.push_back(subtractTimes(sec1, msec1, sec2, msec2));
			}
		} else {
			spaces.push_back(0.0);
		}

		//Set Mean
		float mean = getMean(spaces);
		(*statVector)[i].setIpsMean(mean);
		//Set SD
		(*statVector)[i].setIpsDev(getStanDev(spaces, mean));
		//Set duration of flow
		int sec1, sec2, msec1, msec2;
		decodeTime(times[times.size()-1], sec2, msec2);
		decodeTime(times[0], sec1, msec1);
		(*statVector)[i].setFlowDuration(subtractTimes(sec1, msec1, sec2, msec2));
		//Set payload mean
		mean = getMean(sizes);
		(*statVector)[i].setPayloadMean(mean);
		//Set payload SD
		(*statVector)[i].setPayloadDev(getStanDev(sizes, mean));

		//Retrieve the 5-tuple for each flow (ip #'s, port #'s, and protocol
		res = stmt->executeQuery("select src_ip, dst_ip, s_port, d_port, protocol, time from ip4_flows "
				"inner join ip4_packets on packet_num = packet_id "
				"where flow_num = " + intToStr(i+1) + " limit 1");
		res->next();
		(*statVector)[i].setIpOne(res->getString(1)); //Set first ip address
		(*statVector)[i].setIpTwo(res->getString(2)); //Set second ip address
		(*statVector)[i].setPortOne(res->getInt(3)); //Set first port number
		(*statVector)[i].setPortTwo(res->getInt(4)); //Set second port number
		(*statVector)[i].setProtocol(res->getInt(5)); //Set protocol
		int s, ms;
		decodeTime(res->getString(6), s, ms);
		//string time = res->getString(6);
		//float timef = atof((res->getString(6)).c_str());
		(*statVector)[i].setTime(subtractTimes(firstSeconds, firstMSeconds, s, ms)); //Flow start time
		delete res;

		//Determine the start direction and the percentage of packets that are outgoing
		res = stmt->executeQuery("select s_port from ip4_flows inner join ip4_packets on packet_num = packet_id where flow_num = " + intToStr(i+1));
		float sum = 1.0; float count = 1.0;
		res->next(); //Skip the first packet since we are comparing everything to that one

		//Use first packet to determine flow direction.  Set number of packets matching the first as matching
		while (res->next()){
			if (res->getInt(1) == (*statVector)[i].getPortOne()) {
				sum++;
			}
			count++;
		}
		(*statVector)[i].setDirectionMatch(sum/count*100); //Set the match percentage
		delete res;
	}

	//Write all data for each flow to the database
	PreparedStatement* prepStmt;
	for (unsigned int i=0; i < statVector->size(); i++){
		prepStmt = dbConnection->prepareStatement("INSERT INTO ip4_stats (flow_num, protocol, ip_one, ip_two, port_one, port_two, ips_mean, "
				"ips_stdev, paysize_mean, paysize_stdev, num_packets, flow_dur, start_time, dir_match_percent) values(?,?,?,?,?,?,?,?,?,?,?,?,?,?)");
		prepStmt->setInt(1, (*statVector)[i].getFlowNum());
		prepStmt->setInt(2, (*statVector)[i].getProtocol());
		prepStmt->setString(3, (*statVector)[i].getIpOne());
		prepStmt->setString(4, (*statVector)[i].getIpTwo());
		prepStmt->setInt(5, (*statVector)[i].getPortOne());
		prepStmt->setInt(6, (*statVector)[i].getPortTwo());
		prepStmt->setDouble(7, (*statVector)[i].getIpsMean());
		prepStmt->setDouble(8, (*statVector)[i].getIpsDev());
		prepStmt->setDouble(9, (*statVector)[i].getPayloadMean());
		prepStmt->setDouble(10, (*statVector)[i].getPayloadDev());
		prepStmt->setInt(11, (*statVector)[i].getNumPackets());
		prepStmt->setDouble(12, (*statVector)[i].getFlowDuration());
		prepStmt->setDouble(13, (*statVector)[i].getTime());
		prepStmt->setDouble(14, (*statVector)[i].getDirectionMatch());
		prepStmt->execute();
	}
	prepStmt->close();
	delete prepStmt;
	delete statVector;
}

int checkDirectory(string folder){

	struct stat sb;

	if (stat(folder.c_str(), &sb) == 0 && S_ISDIR(sb.st_mode)) {
	    //Delete the folders contents
		boost::filesystem::remove_all(folder);
	}

	boost::filesystem::path dir(folder);
	if(boost::filesystem::create_directory(dir)) {
		std::cout << "Binary Folder Created" << endl;
	} else {
		return 0;
	}

	return 1;
}


int main(int argc, char* argv[]) {
	if (argc < 3){
		cout << "Not enough arguments entered: (filename, path)";
		return 0;
	}
	string folder = argv[2];
	folder +=  "replayfiles";

	if (!checkDirectory(folder)){
		cout << "Error finding path for binary files." << endl;
		return 0;
	}

	path = argv[2];
	connectDatabase();

	cout << "Adding packets to database.  This may take a while." << endl;
	ReadPcap(argv[1], PacketHandler, 0, "");
	cout << "Done inserting packets." << endl;

	cout << "Marking retransmissions" << endl;  //TODO: Make this a user option
	//markRetrans(4);
	//markRetrans(6);
	cout << "Retransmissions marked." << endl;

	cout << "Calculating flow data." << endl;
	handleFlows();
	cout << "Flows complete." << endl;

	cout << "Calculating PCAP Statistics" << endl;
	computeStats();
	cout << "Done Calculating Statistics" << endl;

	cout << "PCAP successfully added to database." << endl;
    return 0;
}
