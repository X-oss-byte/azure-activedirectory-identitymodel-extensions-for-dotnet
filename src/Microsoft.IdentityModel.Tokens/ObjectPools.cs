// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Threading;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Generic implementation of object pooling pattern with predefined pool size limit. The main
    /// purpose is that limited number of frequently used objects can be kept in the pool for
    /// further recycling.
    ///
    /// Notes: 
    /// 1) it is not the goal to keep all returned objects. Pool is not meant for storage. If there
    ///    is no space in the pool, extra returned objects will be dropped.
    ///
    /// 2) it is implied that if object was obtained from a pool, the caller will return it back in
    ///    a relatively short time. Keeping checked out objects for long durations is ok, but
    ///    reduces usefulness of pooling. Just new up your own.
    ///
    /// Not returning objects to the pool in not detrimental to the pool's work, but is a bad practice.
    /// Rationale:
    ///    If there is no intent for reusing the object, do not use pool - just use "new".
    /// </summary>
    internal sealed class DisposableObjectPool<T> where T : class, IDisposable
    {
        internal struct Element
        {
            internal T Value;
        }

        // factory is stored for the lifetime of the pool. We will call this only when pool needs to
        // expand. compared to "new T()", Func gives more flexibility to implementers and faster
        // than "new T()".
        private readonly Func<T> _factory;

        internal DisposableObjectPool(Func<T> factory)
            : this(factory, Environment.ProcessorCount * 2)
        { }

        internal DisposableObjectPool(Func<T> factory, int size)
        {
            _factory = factory;
            Items = new Element[size];
            Size = size;
        }

        // storage for the pool objects.
        internal Element[] Items { get; }

        internal int Size { get; }

        private T CreateInstance()
        {
            var inst = _factory();
            return inst;
        }

        /// <summary>
        /// Produces an instance.
        /// </summary>
        /// <remarks>
        /// Search strategy is a simple linear probing which is chosen for it cache-friendliness.
        /// Note that Free will try to store recycled objects close to the start thus statistically
        /// reducing how far we will typically search.
        /// </remarks>
        internal T Allocate()
        {
            var items = Items;
            T inst;

            for (int i = 0; i < items.Length; i++)
            {
                // Note that the read is optimistically not synchronized. That is intentional. 
                // We will interlock only when we have a candidate. in a worst case we may miss some
                // recently returned objects. Not a big deal.
                inst = items[i].Value;
                if (inst != null)
                {
                    if (inst == Interlocked.CompareExchange(ref items[i].Value, null, inst))
                    {
                        goto gotInstance;
                    }
                }
            }

            inst = CreateInstance();
        gotInstance:

            return inst;
        }

        /// <summary>
        /// Returns objects to the pool.
        /// </summary>
        /// <remarks>
        /// Search strategy is a simple linear probing which is chosen for it cache-friendliness.
        /// Note that Free will try to store recycled objects close to the start thus statistically
        /// reducing how far we will typically search in Allocate.
        /// </remarks>
        internal void Free(T obj)
        {
            var items = Items;
            bool returned = false;
            for (int i = 0; i < items.Length; i++)
            {
                if (items[i].Value == null)
                {
                    // We need to know if we returned the object. If we didn't, it needs to get disposed.
                    if (null == Interlocked.CompareExchange(ref items[i].Value, obj, null))
                    {
                        returned = true;
                        break;
                    }
                }
            }

            // Our pool is full, we can't hold on to this object, so it will get dropped / garbage collected.
            // However this object was disposable, so we should dispose it now, else the disposal work
            // would have to be done by the finalizer, which may impact high performance scenarios (since the finalizer queue is worked on sequentially.)
            if (!returned)
            {
                obj.Dispose();
            }
        }
    }
}
