# CVE-2023-41993

PoC exploit for CVE-2023-41993.
It's written only up to addrof/fakeobj.
Reliability is not great.
If you want to make it better, try to spray structure IDs.

## POC link

https://po6ix.github.io/POC-for-CVE-2023-41993/pwn.html

I have decided to host with github pages from multiple requests.<br>
Wish me luck that github won't block me...

## Known Affected Versions

- MacOS 14.0
- iOS 17.0, 17.1 beta 1
- iPadOS 17.0

## Known Unaffected Version

- iOS 16.1.1, 16.2, 16.5, 16.5.1, 16.6 beta 1, 16.6.1, 16.7.1, 17.1 RC
- iPadOS 17 beta 1

## Q/A

### It only crashes

It's because the factor value defined in pwn function is not correct for you device.<br>
For such case, I made it to use random value between 87 and 1088.<br>
So you can find correct factor value by just refreshing sometime.<br>
It should work within 100 tries probabilistically.<br>
It would be also nice if you can send me the information shown from the success case.

### So what can I do with this?

This gives you r/w primitive to safari webcontent process.<br>
But to actually make it useful, you will need to chain with other components.

## Brief Explanation

You may want a detailed writeup for this.
but unfortunately I'm not afford the time to write the thing.
So I write some note here so you can understand how this works.

If you see the commit, it's about the change for HeapLocation.
New factor has been added to know whether the nodes are same or not.
It says us that the nodes like GetByOffset, MultiGetByOffset could be confused.
But actualy it's only about the offset.
Let's say if it has two GetByOffset nodes that has different offset.
one of them is going to be CSEed and the leftover will be used instead.
So it's basically offset confusion but it doesn't give you the access to an arbitrary offset.
because to CSE such types of nodes they need to be hoisted by LICMPhase.
For the kinds of node which does write operation is not allowed to be hoisted in this phase.
So same confusion doesn't happens to PutByOffset, MultiPutByOffset nodes.
Also when GetByOffset is hoisted, safeToExecute function is called to see the node is legit to execute and allows to access only the offset less than storage capacity(inline/ool).
So the idea to exploit this was GetterSetter.
If you call `Object.__defineGetter__` to define a property, GetterSetter object is created but stored in the property storage and this not accessible in normally.
But you can with this offset manipulation you have.
Then you call `Object` function to trigger an type confusion.

```
JSObject* JSCell::toObjectSlow(JSGlobalObject* globalObject) const
{
    Integrity::auditStructureID(structureID());
    ASSERT(!isObject());
    if (isString())
        return static_cast<const JSString*>(this)->toObject(globalObject);
    if (isHeapBigInt())
        return static_cast<const JSBigInt*>(this)->toObject(globalObject);
    ASSERT(isSymbol());
    return static_cast<const Symbol*>(this)->toObject(globalObject);
}
```

It will create an SymbolObject which the GetterSetter as an internal value.
And this is incorrect, because this internal value of SymbolObject is supposed to be an Symbol instance not GetterSetter.

```
let getterSetter = jitme(1);
let symbolObject = Object(getterSetter);

symbolObject.description; // call the getter
```

```
String Symbol::description() const
{
    auto& uid = m_privateName.uid();
    return uid.isNullSymbol() ? String() : uid;
}
```

Then when you call the description getter, it will return an String instance.
This is a type confusion between Symbol.m_privateName and GetterSetter.m_getter.
Each time you call this getter, it will increase the reference counter field of m_privateName.m_uid which is at offset 0x0.
This is very useful, because this offset is where the structure ID of getter function is.
By calling this function some times, you can change the structure ID of JSFunction instance.
I have prepared another type which has many property.
Then if you sync the structure ID to be same with it, you can do oob write to property storage.
This directly gives the addrof/fakeobj primitive.

## Reference

- Int64 module: https://github.com/saelo/jscpwn