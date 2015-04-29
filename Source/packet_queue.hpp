//============================================================================
// Name        : SimpleQueue.h
// Author      : Justin Rohrer
// Adapted by  : Scott Fortner
// Version     :
// Copyright   : 2014 Justin Rohrer
// Description : Queue class that has thread synchronization
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

#ifndef PACKET_QUEUE_H_INCLUDED
#define PACKET_QUEUE_H_INCLUDED

#include <queue>
#include <boost/thread.hpp>

using namespace std;
using namespace boost;
using namespace boost::this_thread;
#include "boost/date_time/posix_time/posix_time.hpp" //include all types plus i/o

namespace NpsTap {

struct time_data {
			boost::posix_time::ptime time;
			int packet_num;
			int q_size;
		};

template <typename T>
class PacketQueue
{
	private:
		queue<T> m_queue;			// Use STL queue to store data
		mutex m_mutex;				// The mutex to synchronise on
		condition_variable m_cond;	// The condition to wait for

	public:

		void Enqueue(const T& data);	// Add data to the queue and notify others
		int Dequeue();					// Get data from the queue. Wait for data if not available
		int Length();
};

// Add data to the queue and notify others
template <typename T> void PacketQueue<T>::Enqueue(const T& data)
{
	// Acquire lock on the queue
	unique_lock<mutex> lock(m_mutex);
 
	// Add the data to the queue
	m_queue.push(data);
 
} // Lock is automatically released here
 
// Get data from the queue. Wait for data if not available
template <typename T> int PacketQueue<T>::Dequeue()
{

	if (m_queue.size()==0) {

		return 0;

	} else {
		// Acquire lock on the queue
		unique_lock<mutex> lock(m_mutex);

		// Retrieve the data from the queue
		m_queue.pop();

		return 1;
	}
 
} // Lock is automatically released here

template <typename T> int PacketQueue<T>::Length() {return m_queue.size();}

}	// namespace NpsTap
#endif
