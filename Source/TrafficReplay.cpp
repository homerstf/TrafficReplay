//============================================================================
// Name        : TrafficReplay.cpp
// Author      : Scott Fortner
// Version     :
// Copyright   : 2015 Scott Fortner
// Description : Performs replay of recorded network traffic
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

#include "SimpleQueue.h"
#include <sys/socket.h>
#include <iostream>
#include <stdlib.h>
#include <crafter.h>
#include <fstream>
#include <sstream>
#include <cstdlib>
#include <stdio.h>
#include <boost/thread/thread.hpp>
#include "boost/date_time/posix_time/posix_time.hpp" //include all types plus i/o
#include <net/ethernet.h>
#include <sys/timerfd.h>
#include <sched.h>
#include <pcap.h>
#include "packet_queue.hpp"

using namespace std;
using namespace Crafter;
using namespace boost::posix_time;
using namespace boost::gregorian;
using namespace NpsTap;

static const int PACKETSIZE = 8;
static const int PACKETNUM = 10;
static const int RECV = 2;
static const int SEND = 1;
static const int SCHED_PRIORITY = 99;
static int WAITTIME = 1000; //Wait timeout in microseconds
static int ISTIMEPRI;

//TODO: Add support for mac addresses passed as arguments
static const string MAC1 = "c8:60:00:22:7d:c4";
static const string MAC2 = "c8:1f:66:07:15:e1";
static PacketQueue<Packet> recvQueue;
static SimpleQueue sendQueue;
static string localMAC;
static int latency_micros;

//FTO
static vector<ptime> receiveTimes;

/*Simple helper method to convert int to string*/
string intToStr(int& num){
    stringstream ss;
    ss << num;
    string str = ss.str();
    return str;
}

/*Return system local date and time*/
ptime getTime(){
	ptime t(microsec_clock::local_time());
    return t;
}

/*Read in entire flow file into a vector of vectors (flowVector)*/
vector<vector<string> > getFlowFile(string& path){
													//cout << "Running getFlowFile" << endl;
    string packetLine, packetField;
    vector<string> flowLine;
    string filename = path + "configfiles/ConfigFile.txt";
    ifstream inFile (filename, ifstream::in);
    vector<vector<string> > flowVector;

    if (inFile.is_open()){
    												//cout << "File is open" << endl;
        while (getline(inFile, packetLine)){ //Loop through each packet
            stringstream ss;
            flowLine.clear();
            packetField = "";
            ss.str(packetLine);
            while (getline(ss, packetField, ',')){ //Loop through each field in the packet
                flowLine.push_back(packetField);
            }
            flowVector.push_back(flowLine);
        }
        inFile.close();
    }
    return flowVector;
}

/*Helper function that converts a string to hex.  Used by decode_item*/
int hexToDecimal(string& value){
	stringstream s;
	int x;
	s << hex << value;
	s >> x;
	return x;
}

/*Decodes a portion of the hex string returned by Libcrafter method*/
int decode_item(string& option, int num_segments, unsigned int& iter){
	int j = 1; string item = "";
	while (j<=num_segments and iter < option.size()){
		if (option[iter] != '\\'){
			item += option[iter];
		}else{
			j++;
			iter++;
		}
		iter++;
	}
	return hexToDecimal(item);
}

/*Creates a packet from a binary packet file*/
Packet* createPacket(vector<string>& packetVector, string& path, string localMAC){

	string filename = path + "replayfiles/bin" + packetVector[PACKETNUM] + ".bin";
	ifstream fin(filename.c_str(), ios::in | ios::binary);
	int size = atoi(packetVector[PACKETSIZE].c_str());
	if(!(fin.is_open())) cout << "UNABLE TO OPEN TCP BINARY FILE" << endl;
	char* payloadBuff = new char[size];
	fin.read(payloadBuff, size);
	fin.close();
	Packet* packet = new Packet();
	packet->PacketFromEthernet((unsigned char*) payloadBuff, size);
	delete[] payloadBuff;

	Ethernet* eth = GetEthernet(*packet);
	if (localMAC == MAC1){
		eth->SetSourceMAC(MAC1);
		eth->SetDestinationMAC(MAC2);
	}else {
		eth->SetSourceMAC(MAC2);
		eth->SetDestinationMAC(MAC1);
	}

    return packet;
}

/*Helper function for creating a raw socket*/
int createSocket(const char* if_name){

	int socket_num = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	//Configure the socket
	struct ifreq ifr;
	struct sockaddr_ll addr;
	memset(&addr,0,sizeof(addr));
	memset(&ifr,0,sizeof(ifr));
	strncpy((char *)ifr.ifr_name, if_name, IFNAMSIZ);

	if (ioctl(socket_num,SIOCGIFINDEX,&ifr)==-1) {
		cout << "Error getting interface number" << endl;
	}

	addr.sll_family = AF_PACKET;
	addr.sll_ifindex = ifr.ifr_ifindex;
	addr.sll_halen=ETHER_ADDR_LEN;
	addr.sll_protocol=htons(ETH_P_ALL);

	::bind(socket_num, (struct sockaddr*) &addr, sizeof(addr));
	return socket_num;
}

/*Helper function for converting string timestamp to second and microsecond integer values*/
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
	msec = atoi(m.c_str());
}

/*Method that the packet builder thread uses to build the packets ahead of time*/
/*Performs batch processing by crafting only 2k packets at a time, sleeping for a short period and if the queue size is below 500, then it crafts another 2k.
 * Process is repeated until all packets are processed.
 * */
void buildPackets(vector<vector<string> > &flowVector, string& path){
	int packets_remaining = flowVector.size();


	while (packets_remaining > 2000){
		if (sendQueue.getSize() < 500){ //Only process more packets when the queue has less than 500 left
			for (unsigned int i=0; i < 2000; i++){
				try{
					if (localMAC == flowVector[i][0]){//Packet to be sent
						Packet* packet = createPacket(flowVector[i], path, localMAC);
						packet->PreCraft();
						sendQueue.push(packet);
						packets_remaining--;
					}
				}catch (...) {
					cout << "Problem creating a packet." << endl;
					packets_remaining--;
				}
			}
		}
		usleep(10000); //Sleep for 10 ms then check
	}

	//Now craft the remaining packets
	for (unsigned int i=0; i < packets_remaining; i++){
		try{
			if (localMAC == flowVector[i][0]){//Packet to be sent
				Packet* packet = createPacket(flowVector[i], path, localMAC);
				packet->PreCraft();
				sendQueue.push(packet);
			}
		}catch (...) {
			cout << "Problem creating a packet." << endl;
		}
	}

	cout << sendQueue.getSize() << " packets built" << endl;
}

/*Helper function that converts a ptime object to a timespec object*/
inline timespec ptime_to_timespec (const ptime &tm)
{
	const ptime epoch(date(1970,1,1));
	time_duration duration (tm - epoch);
	timespec ts;
	ts.tv_sec = duration.total_seconds();
	ts.tv_nsec = duration.total_nanoseconds() % 1000000000;
	return ts;
}


#define handle_error(msg) \
               do { perror(msg); exit(EXIT_FAILURE); } while (0)


/*Helper functionn for adding or deleting latency value from a given timestamp
 * Adds the latency value if marked to receive.
 * Subtracts latency if marked to send
 * */
string adjustTimestamp(int sendOrRecv, string ts){
	int tempSec, tempMsec;
	if (sendOrRecv == SEND){
		//Subtract latency_micros from ts
		decodeTime(ts, tempSec, tempMsec);
		tempMsec = tempMsec - latency_micros;
	}else{
		//Add latency_micros to ts
		decodeTime(ts, tempSec, tempMsec);
		tempMsec = tempMsec + latency_micros;
		if (tempMsec >= 1000000){
			tempSec += 1;
			tempMsec -= 1000000;
		}
	}
	string micro = intToStr(tempMsec);
	int size = micro.size();
	if (size < 6){
		for (int i=0; i < 6-size; i++){
			micro = "0" + micro;
		}
	}
	return intToStr(tempSec) + "." + micro;
}

/*Helper function for comparing two times for ordering*/
bool sortVec(const vector<string> &vec1, const vector<string> &vec2){
	int sec1, msec1, sec2, msec2;
	decodeTime(vec1[2], sec1, msec1);
	decodeTime(vec2[2], sec2, msec2);
	 if(sec1 < sec2){
		 return true;
	 }else if (sec1 == sec2){
		 return msec1 < msec2;
	 }else {
		 return false;
	 }
}

void reorderPackets(string localMAC, vector<vector<string> >& flowVector){
	cout << "Reordering packets to account for latency" << endl;

	//Change the times
	for (unsigned int i=0; i < flowVector.size(); i++){
		if (flowVector[i][0] == localMAC){ //Recv packet
			flowVector[i][2] = adjustTimestamp(SEND, flowVector[i][2]);
		}else{ //Send packet
			flowVector[i][2] = adjustTimestamp(RECV, flowVector[i][2]);
		}
	}

	//Reorder the vector according to the new times
	sort(flowVector.begin(), flowVector.end(), sortVec);

	cout << "Packets sorted" << endl;
}

/*This function is called each time an appropriate packet is received by the sniffer*/
void PacketHandler(Packet* sniff_packet, void* user) {

	//FTO: Record the time a racket is received*********************************************
	ptime recvTime(microsec_clock::local_time());
	receiveTimes.push_back(recvTime);
	//End FTO*******************************************************************************

	recvQueue.Enqueue(*sniff_packet);
}

/*The run script for the Internal node*/
void runPrimary(vector<vector<string> >& flowVector,  char** argv, const char* iface, string& path){

	cout << "\r\nRunning as primary node" << endl;

	//Configure
	localMAC = flowVector[0][0];
	int hrs = atoi(argv[5]);
	int mins = atoi(argv[6]);
	ptime time1 = getTime();
	date today = time1.date();

	int socket_num = createSocket("eth0"); //THIS FREEZES HERE IF ON REALTIME SCHEDULING

	//Determine offset from GMT
	std::time_t current_time;
	std::time(&current_time);
	struct std::tm *timeinfo = std::localtime(&current_time);
	long offset = timeinfo->tm_gmtoff;

	//Get start time with offset applied
	ptime* startTime = new ptime(today, hours(hrs) + minutes(mins) + seconds(0) + microseconds(0));
	ptime* startTime1 = new ptime();
	*startTime1 = *startTime + hours(-(offset/3600));

	//Convert start time to a timespec struct for timerfd
	timespec tsp = ptime_to_timespec(*startTime1); //Give seconds, nsec since epoch for GMT.  User can enter local time.
	uint64_t missed;
	struct itimerspec new_value;
	new_value.it_interval.tv_sec = 0;
	new_value.it_interval.tv_nsec = 0;
	new_value.it_value.tv_sec = tsp.tv_sec + 2; //Set wakeup time to 2 seconds prior to start time
	new_value.it_value.tv_nsec = tsp.tv_nsec;

	if (!(new_value.it_value.tv_nsec < 1000000000)){
		new_value.it_value.tv_sec = new_value.it_value.tv_sec + 1;
		new_value.it_value.tv_nsec = new_value.it_value.tv_nsec - 1000000000;
	}
	int fd = timerfd_create(CLOCK_REALTIME, 0);
	if (fd == -1){
		handle_error("timerfd_create");
	}

	/*Thread will wait until just before start time*/
	if (timerfd_settime(fd, TFD_TIMER_ABSTIME, &new_value, NULL) == -1){
		handle_error("timerfd_settime");
	}

	try{
		struct sched_param param;
		param.sched_priority = SCHED_PRIORITY;
		pthread_setschedparam(pthread_self(),SCHED_RR, &param);

		//Start Packet Builiding thread
		boost::thread packetBuilder(buildPackets, flowVector, path);
		cout << endl << "Starting Packet Building Thread" << endl;
		usleep(1000); //For quick starts, must give packetBuilder a head start

		//Start Sniffer thread
		cout << "Starting sniffer" << endl;
		Sniffer sniff("tcp or udp and inbound",iface,PacketHandler);
		try{
			sniff.Spawn(-1);
		} catch (...){
			cout << "Error starting sniffer" << endl;
		}

		cout << "Replay will begin at time: " << argv[5] << ":" << argv[6] << endl;

		ptime sendTime, recvTime;
		int packetSec, packetMsec;
		vector<string> line;
		Packet* packet;

		cout << "Thread sleeping until start time" << endl;

		//Thread waits here
		if (read(fd, &missed, sizeof(missed)) == -1){
			cout << "Error with first fd read" << endl;//Ignores return value
		}
		cout << "Thread waking up" << endl;

		/*Begin sending packets and checking for received packets*/

		//uint64_t missed;
		//struct itimerspec new_value;
		//new_value.it_interval.tv_sec = 0;
		//new_value.it_interval.tv_nsec = 0;

		/*TIME CRITICAL AREA*/
		for (unsigned int i=0; i < flowVector.size(); i++){
			line = flowVector[i];
			decodeTime(line[2], packetSec, packetMsec);

			if (localMAC == line[0]){ //Packet to be sent

				/*SLEEP UNTIL TIME TO SEND (TIMERFD)*********************************************************/
				new_value.it_value.tv_sec = tsp.tv_sec + packetSec;
				new_value.it_value.tv_nsec = tsp.tv_nsec + (packetMsec*1000);

				if (!(new_value.it_value.tv_nsec < 1000000000)){
					new_value.it_value.tv_sec = new_value.it_value.tv_sec + 1;
					new_value.it_value.tv_nsec = new_value.it_value.tv_nsec - 1000000000;
				}

				if (timerfd_settime(fd, TFD_TIMER_ABSTIME, &new_value, NULL) == -1){
					cout << "Send: " << endl;
					handle_error("timerfd_settime");
				}
				packet = sendQueue.pop();

				if (read(fd, &missed, sizeof(missed)) == -1){
					handle_error("read");
				}

				ptime start_time(microsec_clock::local_time()); //FTO*************************************************************************************************************

				/*SEND PACKET***********************************************************************/
				try{
					packet->SocketSend(socket_num);
				}catch (...){
					cout << "Error sending packet.  Possibly empty" << endl;
				}
				delete packet;
				receiveTimes.push_back(start_time); //FTO*************************************************************************************************************

			} else{//Packet to be received

				if (ISTIMEPRI){ //For timing priority
					recvTime = *startTime + seconds(packetSec) + microseconds(packetMsec + WAITTIME);
					while (!(recvQueue.Dequeue()) and (getTime() < recvTime))
					{ /*Wait for receiving packet to arrive or timeout to occur*/ }

				} else { //For sequencing priority remove the timeout
					while (!(recvQueue.Dequeue()))
					{ /*Wait for receiving packet to arrive*/ }
				}
			}
		}
		/*END TIME CRITICAL AREA*/
		try {
			//pcap_breakloop(handle);
			sniff.Cancel();
			delete startTime;
			delete startTime1;
			close(fd);
		} catch (...) {
			cout << "Error cleaning up" << endl;
		}

	} catch (...) {
		cout << "Exception Thrown During Run" << endl;
	}
	cout << "Running complete" << endl;

	//FTO: Print timing data structure to file****************************************************************************************************************
	//For outputing receive times
	try {
		ofstream timeFile;
		timeFile.open("AllTimes.txt");
		cout << "File open" << endl;

		for (unsigned int i = 0; i < receiveTimes.size(); i++){
			if (receiveTimes.size() > 0){
				timeFile << to_simple_string(receiveTimes[i]) << "\r\n";
			}
		}
		timeFile.close();
		cout << "File closed" << endl;
	} catch (...) {
		cout << "Error with writing times to file" << endl;
	}
	//END *********************************************************************************************************************
}

/*The run script for the secondary node*/
/*Secondary node waits for the first packet to arrive then begins timing from there*/
void runSecondary(vector<vector<string> >& flowVector, char** argv, const char* iface, string& path){
	cout << endl << "Replay will begin when first packet is received from primary node" << endl;
	localMAC = flowVector[0][1];
	int socket_num = createSocket("eth0");

	/*Reorder the packets to account for transmission delay*/
	reorderPackets(localMAC, flowVector);

	//Set real-time scheuling priority
	struct sched_param param;
	param.sched_priority = SCHED_PRIORITY;
	pthread_setschedparam(pthread_self(),SCHED_RR, &param);

	//Start Packet Builiding thread
	cout << "Starting Packet Building Thread" << endl;
	boost::thread packetBuilder(buildPackets, flowVector, path);

	//Start sniffer
	cout << "Starting sniffer. " << endl;
	Sniffer sniff("tcp or udp and inbound",iface,PacketHandler);
	try{
		sniff.Spawn(-1);
	} catch (...){
		cout << "Error starting sniffer" << endl;
	}

	ptime* startTime = new ptime();
	ptime* startTime1 = new ptime();
	ptime timenow, sendTime, recvTime;
	int packetSec, packetMsec;
	vector<string> line;
	decodeTime(flowVector[0][2], packetSec, packetMsec);

	uint64_t missed;
	struct itimerspec new_value;
	new_value.it_interval.tv_sec = 0;
	new_value.it_interval.tv_nsec = 0;
	int fd = timerfd_create(CLOCK_REALTIME, 0);
	if (fd == -1){
		handle_error("timerfd_create");
	}
	Packet* packet;

	//Determine offset in seconds from GMT
	std::time_t current_time;
	std::time(&current_time);
	struct std::tm *timeinfo = std::localtime(&current_time);
	long offset = timeinfo->tm_gmtoff;

	cout << "Waiting to receive first packet to begin timing" << endl;

	recvTime = *startTime + seconds(packetSec) + microseconds(packetMsec + WAITTIME);
	while (!recvQueue.Dequeue())
	{ /*Wait for receiving packet to show arrive*/ }

	*startTime = getTime() - seconds(packetSec) - microseconds(packetMsec + latency_micros); //Receive time of first packet minus the time it was scheduled to send and the estimated latency
	*startTime1 = *startTime + hours(-(offset/3600)); //StartTime adjusted for offset so user can enter local time (as the computer sees it)
	cout << "Running" << endl;

	//Convert start time to a timespec struct for timerfd
	timespec tsp = ptime_to_timespec(*startTime1); //Give seconds, nsec since epoch for GMT.

	/*Now begin send and receive functionality*/
	/*TIME CRITICAL AREA*/
	for (unsigned int i=1; i < flowVector.size(); i++){
		line = flowVector[i];
		decodeTime(line[2], packetSec, packetMsec);

		if (localMAC == line[0]){//Packet to be sent

			/*SLEEP UNTIL TIME TO SEND (TIMERFD)*********************************************************/
			new_value.it_value.tv_sec = tsp.tv_sec + packetSec;
			new_value.it_value.tv_nsec = tsp.tv_nsec + (packetMsec*1000);

			if (!(new_value.it_value.tv_nsec < 1000000000)){
				new_value.it_value.tv_sec = new_value.it_value.tv_sec + 1;
				new_value.it_value.tv_nsec = new_value.it_value.tv_nsec - 1000000000;
			}

			if (timerfd_settime(fd, TFD_TIMER_ABSTIME, &new_value, NULL) == -1){
				cout << "Send: ";
				handle_error("timerfd_settime");
			}

			packet = sendQueue.pop();

			if (read(fd, &missed, sizeof(missed)) == -1){
				handle_error("read");
			}

			/*SEND PACKET***********************************************************************/
			try{
				packet->SocketSend(socket_num);
			}catch (...){
				cout << "Error sending packet" << endl;
			}
			delete packet;

		} else{//Packet to be received
			recvTime = *startTime + seconds(packetSec) + microseconds(packetMsec + WAITTIME);
			while (!(recvQueue.Dequeue()))// and (getTime() < recvTime))
			{ /*Wait for receiving packet to show up or timeout to occur*/ }
		}
	}
	/*END TIME CRITICAL AREA*/

	try {
		sniff.Cancel();
		delete startTime;
		delete startTime1;
		close(fd);
	} catch (...) {
		cout << "Problem cleaning up" << endl;
	}
	cout << "Running complete" << endl;
}


/* Arguments:
 * node number (1 or 2)
 * root path of files
 * sequencing vs timing priority (0 or 1)
 * start hour
 * start minutes*/
int main(int argc, char** argv) {
	if ((argc < 7 and atoi(argv[1]) == 1) or (argc < 5 and atoi(argv[1]) == 2)){
		cout << "Not enough arguments.  Terminating." << endl;
		return 0;
	}

	latency_micros = atoi(argv[4]); //User defined network latency
	string path = argv[2]; //Path to files
	ISTIMEPRI = atoi(argv[3]);
	const char* iface = "eth0"; //Receiving interface

	vector<vector<string> > flowVector;
	string filename = path + "configfiles/ConfigFile.txt";
	FILE *file = NULL;
	if ((file = fopen(filename.c_str(), "r"))) //Checks for file existence before continuing.  If not found then quit with error.
	{
		fclose(file);
		cout << "Config file found!" << endl;
		flowVector = getFlowFile(path);
	} else {
		cout << "Config File not found at the following path: " << filename << endl;
		return 0;
	}

	//Execute main process based on user node choice
	if (atoi(argv[1]) == 1){
		runPrimary(flowVector, argv, iface, path);
	}else{
		runSecondary(flowVector, argv, iface, path);
	}

	return 0;
}
