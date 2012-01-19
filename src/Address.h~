/*
    <one line to give the program's name and a brief idea of what it does.>
    Copyright (C) 2012  <copyright holder> <email>

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
*/


#ifndef ADDRESS_H
#define ADDRESS_H

#include <pcap.h>
#include <sys/socket.h>

/**
 * @brief This is a helper class to access the network addresses.
 **/
class Address {

public:
	pcap_addr_t addr_t_;
	
    Address(pcap_addr_t const& addr): addr_t_(addr) {}
    
    /**
	 * @brief Copy constructor.. We don't really need this function because there is no heap memory...
	 *
	 * @param other a object for copy
	 **/
	Address ( const Address& other ) {
		if (this != &addr)
			addr_t_ = addr.addr_t_;
		
		return *this;
	}
    
    struct sockaddr const* get_address() const{
		return addr_t_.addr;
	}
    
    struct sockaddr const* get_netmask() const{
		return addr_t_.netmask;
	}
    
    struct sockaddr const* get_bcast_address() const{
		return addr_t_.broadaddr;
    }
    
    struct sockaddr const* get_dst_address() const{
		return addr_t_.dstaddr;
    }
    
    virtual ~Address();
	
    virtual Address& operator= ( const Address& other );
    virtual bool operator== ( const Address& other ) const;
};

#endif // ADDRESS_H
