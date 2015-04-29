//============================================================================
// Name        : SimpleQueue.cpp
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

#include "SimpleQueue.h"


SimpleQueue::SimpleQueue() {
	//_theQueue = new std::queue<Crafter::Packet>;
	_size = 0;
	_isEmpty = true;
	first = NULL;
	last = NULL;
}

SimpleQueue::~SimpleQueue() {
	//delete _theQueue;
	Crafter::Packet* packet;
	while (_size > 0){
		packet = this->pop();
		delete packet;
	}
}

bool SimpleQueue::push(Crafter::Packet* packet){
	//_theQueue->push(packet);
	node* new_node = new node();
	new_node->packet = packet;
	bool useLock = false;
	if (getSize() < 3){
		_mutex.lock();
		useLock = true;
	}
	if (first != NULL){
		first->previous = new_node;
		new_node->next = first;
	}else {
		last = new_node;
	}
	first = new_node;
	if (!useLock) _mutex.lock();
	incSize();
	_mutex.unlock();
	return 1;
}

bool SimpleQueue::push(){
	//_theQueue->push(packet);
	node* new_node = new node();
	Crafter::Packet* packet = new Crafter::Packet();
	new_node->packet = packet;
	bool useLock = false;
	if (getSize() < 3){
		_mutex.lock();
		useLock = true;
	}
	if (first != NULL){
		first->previous = new_node;
		new_node->next = first;
	}else {
		last = new_node;
	}
	first = new_node;
	if (!useLock) _mutex.lock();
	incSize();
	_mutex.unlock();
	return 1;
}

/*Pop and return the packet*/
Crafter::Packet* SimpleQueue::pop(){
	if (last == NULL) return 0;
	_mutex.lock();

	Crafter::Packet* packet = last->packet;

	if (last == first) {
		last = NULL;
		first = NULL;
	}else{
		last = last->previous;
		last->next = NULL;
	}

	decSize();
	_mutex.unlock();
	return packet;
}

/*Pop but not don't return the packet*/
bool SimpleQueue::simplePop(){
	if (last == NULL) return 0;
	bool useLock = false;
	if (getSize() < 3){
		_mutex.lock();
		useLock = true;
	}
	node* temp = last;
	if (last == first) {
		last = NULL;
		first = NULL;
	}else{
		last = last->previous;
	}
	delete temp->packet;
	delete temp;
	if (!useLock) _mutex.lock();
	decSize();
	_mutex.unlock();
	return 1;
}

int SimpleQueue::getSize(){
	return _size;
}

void SimpleQueue::incSize(){

	_size++;
}

void SimpleQueue::decSize(){
	_size--;
}

bool SimpleQueue::isEmpty(){
	return _isEmpty;
}
