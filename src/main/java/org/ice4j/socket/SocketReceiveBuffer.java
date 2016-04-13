/*
 * ice4j, the OpenSource Java Solution for NAT and Firewall Traversal.
 *
 * Copyright @ 2015 Atlassian Pty Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.ice4j.socket;

import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.locks.*;

/**
 * Implements a list of <tt>DatagramPacket</tt>s received by a
 * <tt>DatagramSocket</tt> or a <tt>Socket</tt>. The list enforces the
 * <tt>SO_RCVBUF</tt> option for the associated <tt>DatagramSocket</tt> or
 * <tt>Socket</tt>.
 */
abstract class SocketReceiveBuffer
{
    private static final int DEFAULT_RECEIVE_BUFFER_SIZE = 1024 * 1024;

    /**
     * The value of the <tt>SO_RCVBUF</tt> option for the associated
     * <tt>DatagramSocket</tt> or <tt>Socket</tt>. Cached for the sake of
     * performance.
     */
    private int receiveBufferSize;

    /**
     * The (total) size in bytes of this receive buffer.
     */
    private int size;

    /**
     * 
     */
    final LinkedList<DatagramPacket> bufList;

    /**
     * 
     */
    final ReentrantLock lock;
    
    /**
     * 
     */
    final Condition notEmpty;

    /**
     * 
     */
    public SocketReceiveBuffer() {
        bufList = new LinkedList<>();
        lock = new ReentrantLock();
        notEmpty = lock.newCondition();
    }

    /**
     *
     */
    public boolean add(DatagramPacket p)
    {
        if (p == null) throw new NullPointerException();

        final ReentrantLock lock = this.lock;
        lock.lock();
        try {
            size += p.getLength();
            int maxsize = getMaxBufSize();
            DatagramPacket d;
            while (size > maxsize) {
                d = bufList.poll();
                if (d == null)
                    break;
                size -= d.getLength();
            }
            bufList.add(p);
            notEmpty.signal();
            return true;
        } finally {
            lock.unlock();
        }
    }

    public void addAll(Collection<DatagramPacket> c) {
        if (c == null) throw new NullPointerException();

        final ReentrantLock lock = this.lock;
        lock.lock();
        try {
            //add all packet from c
            for(DatagramPacket d: c) {
                if (d == null) throw new NullPointerException();
                bufList.add(d);
                size += d.getLength();
            }

            //remove excessive packet
            int maxsize = getMaxBufSize();
            DatagramPacket d;
            while (size > maxsize) {
                d = bufList.poll();
                if (d == null)
                    break;
                size -= d.getLength();
            }

            notEmpty.signalAll();
        } finally {
            lock.unlock();
        }
    }

    /**
     * 
     * @return
     */
    public int bufNbElem() {
        final ReentrantLock lock = this.lock;
        lock.lock();
        try {
            return bufList.size();
        } finally {
            lock.unlock();
        }
    }

    /**
     * 
     * @return
     */
    public int bufSize() {
        final ReentrantLock lock = this.lock;
        lock.lock();
        try {
            return size;
        } finally {
            lock.unlock();
        }
    }

    /**
     * 
     */
    public DatagramPacket poll()
    {
        final ReentrantLock lock = this.lock;
        lock.lock();
        try {
            DatagramPacket d = bufList.poll();
            if (d != null) {
                size -= d.getLength();
            }
            return d;
        } finally {
            lock.unlock();
        }
    }

    /**
     * 
     * @param timeout
     * @param unit
     * @return
     * @throws InterruptedException
     */
    public DatagramPacket poll(long timeout, TimeUnit unit) throws InterruptedException {
        long nanos = unit.toNanos(timeout);
        final ReentrantLock lock = this.lock;
        lock.lockInterruptibly();
        try {
            DatagramPacket d;
            while ((d = bufList.poll()) == null) {
                if (nanos <= 0)
                    return null;
                nanos = notEmpty.awaitNanos(nanos);
            }
            size -= d.getLength();
            return d;
        } finally {
            lock.unlock();
        }
    }

    /**
     * 
     * @return
     */
    private int getMaxBufSize() {
        // For the sake of performance, we cache the first result of
        // getReceiveBufferSize() of DatagramSocket or Socket
        int receiveBufferSize = this.receiveBufferSize;

        if (receiveBufferSize <= 0)
        {
            try
            {
                receiveBufferSize = getReceiveBufferSize();
            }
            catch (SocketException sex)
            {
            }
            if (receiveBufferSize <= 0)
            {
                receiveBufferSize = DEFAULT_RECEIVE_BUFFER_SIZE;
            }
            else if (receiveBufferSize
                    < DEFAULT_RECEIVE_BUFFER_SIZE)
            {
                // Well, a manual page on SO_RCVBUF talks about
                // doubling. In order to stay on the safe side and
                // given that there was no limit on the size of the
                // buffer before, double the receive buffer size.
                receiveBufferSize *= 2;
            }
            this.receiveBufferSize = receiveBufferSize;
        }

        return receiveBufferSize;
    }

    /**
     * Gets the value of the <tt>SO_RCVBUF</tt> option for the associated
     * <tt>DatagramSocket</tt> or <tt>Socket</tt> which is the buffer size used
     * by the platform for input on the <tt>DatagramSocket</tt> or
     * <tt>Socket</tt>.
     *
     * @return the value of the <tt>SO_RCVBUF</tt> option for the associated
     * <tt>DatagramSocket</tt> or <tt>Socket</tt>
     * @throws SocketException if there is an error in the underlying protocol
     */
    public abstract int getReceiveBufferSize()
        throws SocketException;
}
