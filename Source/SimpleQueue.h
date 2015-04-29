//============================================================================
// Name        : SimpleQueue.h
// Author      : Scott Fortner
// Version     :
// Copyright   : 2015 Scott Fortner
// Description : Very simply Packet queue with minimal locks
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

#ifndef SIMPLEQUEUE_H_
#define SIMPLEQUEUE_H_

#include <crafter.h>
#include <queue>
#include <boost/thread/thread.hpp>

class SimpleQueue {
public:
	SimpleQueue();
	virtual ~SimpleQueue();
	bool push(Crafter::Packet* packet);
	bool push();
	Crafter::Packet* pop();
	bool simplePop();
	int getSize();
	bool isEmpty();
private:
	int _size;
	bool _isEmpty;
	boost::mutex _mutex;
	void incSize();
	void decSize();
	struct node {
	  Crafter::Packet* packet;
	  node *next;
	  node *previous;
	};
	node* first;
	node* last;
};

#endif /* SIMPLEQUEUE_H_ */
