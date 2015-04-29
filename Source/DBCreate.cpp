//============================================================================
// Name        : DBCreate.cpp
// Author      : Scott Fortner
// Version     :
// Copyright   : 2015 Scott Fortner
// Description : Creates/Clears DB structure prior to population
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
#include "mysql_connection.h"
#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <cppconn/statement.h>

using namespace std;
using namespace sql;

Driver* dbDriver;
Connection* dbConnection;

int connectDatabase(){
	try{
		dbDriver = get_driver_instance();
		dbConnection = dbDriver->connect("localhost", "user", "password");
		dbConnection->setSchema("pcapdatabase");
		cout << "Database connection successful" << endl;
		return 1;
	}
	catch (SQLException &e){
		cout << "Unable to connect to database" << endl;
		return 0;
	}
}

void cleanTables(){
	Statement* stmnt;
	stmnt = dbConnection->createStatement();
	stmnt->execute("DROP TABLE IF EXISTS ip4_packets");
	stmnt->execute("DROP TABLE IF EXISTS ip6_packets");
	stmnt->execute("DROP TABLE IF EXISTS ip4_flows");
	stmnt->execute("DROP TABLE IF EXISTS ip6_flows");
	stmnt->execute("DROP TABLE IF EXISTS all_flows");
	stmnt->execute("DROP TABLE IF EXISTS ip4_stats");
	cout << "Tables dropped.  Database is clean." << endl;
	delete stmnt;
}

void createTables(){
	Statement* stmnt;
	stmnt = dbConnection->createStatement();

	//IPv4 Packet table
	stmnt->execute("CREATE TABLE ip4_packets (packet_id INT UNSIGNED NOT NULL AUTO_INCREMENT, "
			"PRIMARY KEY(packet_id), time VARCHAR(30), s_mac VARCHAR(30), d_mac VARCHAR(30),  src_ip VARCHAR(30), dst_ip VARCHAR(30), "
			"s_port INT, d_port INT, protocol INT, seq_num INT UNSIGNED, packet_size INT, payload_size INT, packet_counter INT, is_retrans BOOL)");
	cout << "IPv Packet table created." << endl;

	//IPv6 Packet Table
	stmnt->execute("CREATE TABLE ip6_packets (packet_id INT UNSIGNED NOT NULL AUTO_INCREMENT, "
				"PRIMARY KEY(packet_id), time VARCHAR(30), s_mac VARCHAR(30), d_mac VARCHAR(30), src_ip VARCHAR(50), dst_ip VARCHAR(50), "
				"s_port INT, d_port INT, protocol INT, seq_num INT UNSIGNED, packet_size INT, payload_size INT, packet_counter INT, is_retrans BOOL)");
	cout << "IP6 Packet table created." << endl;

	//IP4 flows table
	stmnt->execute("CREATE TABLE ip4_flows(ip4_flows_id INT UNSIGNED NOT NULL AUTO_INCREMENT, "
			"PRIMARY KEY(ip4_flows_id), packet_num INT, flow_num INT)");
	cout << "IP4 flows table created." << endl;

	//IP6 flows table
	stmnt->execute("CREATE TABLE ip6_flows(ip6_flows_id INT UNSIGNED NOT NULL AUTO_INCREMENT, "
			"PRIMARY KEY(ip6_flows_id), packet_num INT, flow_num INT)");
	cout << "IP6 flows table created." << endl;

	//All flows table
	stmnt->execute("CREATE TABLE all_flows(all_flows_id INT UNSIGNED NOT NULL AUTO_INCREMENT, "
			"PRIMARY KEY(all_flows_id), ip_type INT, flow_num INT, timestamp varchar(30))");
	cout << "All flows table created." << endl;

	//IP4 Stats table
	stmnt->execute("CREATE TABLE ip4_stats (flow_num INT NOT NULL, "
				"PRIMARY KEY(flow_num), protocol INT, port_one INT, port_two INT, ip_one varchar(30), ip_two varchar(30), ips_mean FLOAT, "
				"ips_stdev FLOAT, paysize_mean FLOAT, paysize_stdev FLOAT, num_packets INT, flow_dur FLOAT, start_time FLOAT, dir_match_percent FLOAT)");
	cout << "IP4 Stats table created." << endl;
	delete stmnt;
}

int main() {
	if (connectDatabase() == 0){
		return 0;
	}
	cleanTables();
	createTables();
	delete dbConnection;
	cout << "Database connection closed" << endl;
	return 0;
}
