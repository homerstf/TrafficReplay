//============================================================================
// Name        : StatHolder.h
// Author      : Scott Fortner
// Version     :
// Copyright   : 2015 Scott Fortner
// Description : Simple container for statistical flow data
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

#ifndef STATHOLDER_H_
#define STATHOLDER_H_

#include <string>

using namespace std;

class StatHolder {
public:
	StatHolder(int flowNum, int numPackets);
	virtual ~StatHolder();

	float getFlowDuration() const {
		return flow_duration;
	}

	void setFlowDuration(float flowDuration) {
		flow_duration = flowDuration;
	}

	int getFlowNum() const {
		return flow_num;
	}

	void setFlowNum(int flowNum) {
		flow_num = flowNum;
	}

	const string& getIpOne() const {
		return ip_one;
	}

	void setIpOne(const string& ipOne) {
		ip_one = ipOne;
	}

	const string& getIpTwo() const {
		return ip_two;
	}

	void setIpTwo(const string& ipTwo) {
		ip_two = ipTwo;
	}

	float getIpsDev() const {
		return ips_dev;
	}

	void setIpsDev(float ipsDev) {
		ips_dev = ipsDev;
	}

	float getIpsMean() const {
		return ips_mean;
	}

	void setIpsMean(float ipsMean) {
		ips_mean = ipsMean;
	}

	float getPayloadDev() const {
		return payload_dev;
	}

	void setPayloadDev(float payloadDev) {
		payload_dev = payloadDev;
	}

	float getPayloadMean() const {
		return payload_mean;
	}

	void setPayloadMean(float payloadMean) {
		payload_mean = payloadMean;
	}

	int getPortOne() const {
		return port_one;
	}

	void setPortOne(int portOne) {
		port_one = portOne;
	}

	int getPortTwo() const {
		return port_two;
	}

	void setPortTwo(int portTwo) {
		port_two = portTwo;
	}

	int getProtocol() const {
		return protocol;
	}

	void setProtocol(int protocol) {
		this->protocol = protocol;
	}

	int getNumPackets() const {
		return num_packets;
	}

	void setNumPackets(int numPackets) {
		num_packets = numPackets;
	}

	void setTime(float time) {
		start_time = time;
	}

	float getTime() {
		return start_time;
	}

	void setDirectionMatch(float value) {
		dir_match_percent = value;
	}

	int getDirectionMatch() {
		return dir_match_percent;
	}

private:
	int flow_num;
	int protocol;
	string ip_one;
	string ip_two;
	int port_one;
	int port_two;
	float ips_mean;
	float ips_dev;
	float payload_mean;
	float payload_dev;
	int num_packets;
	float flow_duration;
	float start_time;
	float dir_match_percent;

};

#endif /* STATHOLDER_H_ */
