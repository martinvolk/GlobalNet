/*********************************************
VSL - Virtual Socket Layer
Martin K. Schröder (c) 2012-2013

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
**********************************************/

#include "local.h"

Buffer::Buffer(){
	m_pReadBuf = BIO_new(BIO_s_mem());
	BIO_set_mem_eof_return(m_pReadBuf, -1);
	m_pWriteBuf = BIO_new(BIO_s_mem());
	BIO_set_mem_eof_return(m_pWriteBuf, -1);
}

Buffer::~Buffer(){
	LOG(3, "BUFFER: deleting!");
	BIO_free(m_pReadBuf);
	BIO_free(m_pWriteBuf);
}

int Buffer::recv(char *data, size_t size, size_t minsize) const{
	if(!BIO_ctrl_pending(m_pReadBuf) || BIO_ctrl_pending(m_pReadBuf) < minsize) return 0;
	int rc = BIO_read(m_pReadBuf, data, size);
	LOG(3, "BUFFER: received "<<rc<<" bytes.");
	return rc;
}

int Buffer::send(const char *data, size_t size){
	LOG(3, "BUFFER: send "<<size<<" bytes.");
	return BIO_write(m_pWriteBuf, data, size);
}
int Buffer::recvOutput(char *data, size_t size, size_t minsize) const{
	if(!BIO_ctrl_pending(m_pWriteBuf) || BIO_ctrl_pending(m_pWriteBuf) < minsize) return 0;
	int rc = BIO_read(m_pWriteBuf, data, size);
	LOG(3, "BUFFER: recvOutput: "<<rc<<" bytes.");
	return rc;
}
int Buffer::sendOutput(const char *data, size_t size){
	LOG(3, "BUFFER: sendOutput: "<<size<<" bytes.");
	return BIO_write(m_pReadBuf, data, size);
}
size_t Buffer::input_pending() const{
	return BIO_ctrl_pending(m_pReadBuf);
}
size_t Buffer::output_pending() const{
	return BIO_ctrl_pending(m_pWriteBuf);
}

void Buffer::clear(){
	
}

void Buffer::flush(){
	// do nothing
}
/*
// data<<buffer
const Buffer& operator<<(vector<char> &data, const Buffer &buf){
	size_t minsize = data.size();
	data.resize(min(data.capacity(), buf.input_pending()));
	buf.recv(data.data(), data.size(), minsize);
	return buf;
}
// data>>buffer
Buffer& operator>>(const vector<char> &data, Buffer &buf){
	buf.send(data.data(), data.size());
	return buf;
}
// buffer<<data
Buffer& operator<<(Buffer &buf, const vector<char> &data){
	buf.sendOutput(data.data(), data.size());
	return buf;
}
// buffer>>data
const Buffer& operator>>(const Buffer &buf, vector<char> &data){
	size_t minsize = data.size();
	data.resize(min(data.capacity(), buf.output_pending()));
	buf.recvOutput(data.data(), data.size(), minsize);
	return buf;
}
*/
