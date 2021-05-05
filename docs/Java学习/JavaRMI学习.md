### Java RMI学习

为了理解Java相关漏洞的原理，这里对Java RMI的相关原理做一个系统的学习，RMI的基本通信过程这里就不罗说了，网上一找一大堆。
整体过程清楚但是对于细节还是一知半解，故调试一把，看看到底究竟是怎么一个过程，带着以下的疑惑一步步走。

### **远程对象是如何导出的？**
先附上例子：
```java
// 远程对象接口TestRMIInterface
public interface TestRMIInterface extends Remote {
    public String sayHello ( String sth ) throws RemoteException;
}
// 对应的实现
public class TestRMIInterfaceImpl implements TestRMIInterface{
    protected TestRMIInterfaceImpl () {
        super();
    }
    @Override
    public String sayHello(String sth) throws RemoteException {
        String i= "0";
        return "say hello client " + sth;
    }
}
// RMI Server端
public class TestRMIServer {
    public static void main(String[] args) {
        try {
            TestRMIInterfaceImpl obj = new TestRMIInterfaceImpl();
            TestRMIInterface helloService = (TestRMIInterface) UnicastRemoteObject.exportObject(obj, 0);
            //创建Registry，监听于1099端口
            Registry reg = LocateRegistry.createRegistry(1099);
            //将TestRMIInterfaceImpl绑定到Registry
            reg.bind("HelloService", obj);
            System.out.println("TestRMIInterfaceImpl已绑定到Registry ......");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```
在
```
TestRMIInterface helloService = (TestRMIInterface) UnicastRemoteObject.exportObject(obj, 0);
```
处设置断点，调试模式启动Server。

```java
（1）
public static Remote exportObject(Remote obj, int port)
        throws RemoteException{
    // 继续导出，并且创建UnicastServerRef对象，端口暂时未0，
    //UnicastServerRef可理解为和远程对象对应的一个句柄对象，作用是导出对象，
    // 内部LiveRef属性用作建立TCP连接，接受调用请求和转发的作用。
    //new一个UnicastServerRef对象，会发现会创建一个LiveRef类型的属性
    return exportObject(obj, new UnicastServerRef(port));
}
（2）
private static Remote exportObject(Remote obj, UnicastServerRef sref)throws RemoteException{
    // if obj extends UnicastRemoteObject, set its ref.
	if (obj instanceof UnicastRemoteObject) {
		((UnicastRemoteObject) obj).ref = sref;
	}
    // 继续导出
	return sref.exportObject(obj, null, false);
}
（3）
    public Remote exportObject(Remote var1, Object var2, boolean var3) throws RemoteException {
        Class var4 = var1.getClass();

        Remote var5;
        try {
            // 为待导出对象创建动态代理对象，
            var5 = Util.createProxy(var4, this.getClientRef(), this.forceStubUse);
            // var5 : Proxy[TestRMIInterface,RemoteObjectInvocationHandler[UnicastRef [liveRef: [endpoint:[192.168.230.1:0](local),objID:[459ee6d5:1793b64f8da:-7fff, -925579078958796373]]]]]
        } catch (IllegalArgumentException var7) {
            throw new ExportException("remote object implements illegal remote interface", var7);
        }
        // 
        if (var5 instanceof RemoteStub) {
            this.setSkeleton(var1);
        }
        // 创建target，包含了真实远程对象，当前UnicastServerRef句柄对象，代理对象，创建的临时对象ID，var3
        Target var6 = new Target(var1, this, var5, this.ref.getObjID(), var3);
        // 继续导出对象
        this.ref.exportObject(var6);
        this.hashToMethod_Map = (Map)hashToMethod_Maps.get(var4);
        return var5;
    }
//再看this.ref.exportObject(var6); 最终到达TCPTransport.exportObject
  java.lang.Thread.State: RUNNABLE
	  at sun.rmi.transport.tcp.TCPTransport.exportObject(TCPTransport.java:248)
	  at sun.rmi.transport.tcp.TCPEndpoint.exportObject(TCPEndpoint.java:411)
	  at sun.rmi.transport.LiveRef.exportObject(LiveRef.java:147)
	  at sun.rmi.server.UnicastServerRef.exportObject(UnicastServerRef.java:234)
（4）
  public void exportObject(Target var1) throws RemoteException {
        synchronized(this) {
            // 首先创建TCP socket监听，此时端口不再是0，变成了随机端口。
            // Proxy[TestRMIInterface,RemoteObjectInvocationHandler[UnicastRef [liveRef: [endpoint:[192.168.230.1:53398](local),objID:[459ee6d5:1793b64f8da:-7fff, -925579078958796373]]]]]
            this.listen();
            ++this.exportCount;
        }

        boolean var2 = false;
        boolean var12 = false;

        try {
            var12 = true;
            //继续导出
            super.exportObject(var1);
            /*
            public void exportObject(Target var1) throws RemoteException {
                var1.setExportedTransport(this);
                //实际放入导出列表中
                ObjectTable.putTarget(var1);
            }*/
            var2 = true;
            var12 = false;
        } finally {
            if (var12) {
                if (!var2) {
                    synchronized(this) {
                        this.decrementExportCount();
                    }
                }

            }
        }

        if (!var2) {
            synchronized(this) {
                this.decrementExportCount();
            }
        }

    }
至此，远程对象的导出工作已经完成。
```

### **注册中心本身作为远程服务，又是如何发布的？**
```java
//创建注册中心
Registry reg = LocateRegistry.createRegistry(1099);
    // 创建RegistryImpl
    public static Registry createRegistry(int port) throws RemoteException {
        return new RegistryImpl(port);
    }
   
    //接下来，创建LiveRef和UnicastServerRef，var1为端口1099
    LiveRef var2 = new LiveRef(id, var1);
    this.setup(new UnicastServerRef(var2, RegistryImpl::registryFilter));

    private void setup(UnicastServerRef var1) throws RemoteException {
        this.ref = var1;
        //和之前远程对象的导出类似，调用UnicastServerRef的exportObject
        var1.exportObject(this, (Object)null, true);
    }

    // 同样走到UnicastServerRef的exportObject的函数中
    // 首先创建代理对象，因为本地存在 RegistryImpl_Stub，所以这里不会像普通对象一样创建动态代理，而是直接加载RegistryImpl_Stub返回
    1. var5 = Util.createProxy(var4, this.getClientRef(), this.forceStubUse);
    //var5 ： RegistryImpl_Stub[UnicastRef [liveRef: [endpoint:[192.168.230.1:1099](local),objID:[0:0:0, 0]]]]
    // 由于RegistryImpl_Stub继承自RemoteStub，所以会走到这里设置setSkeleton， 由于本地存在RegistryImpl_Skel，所以直接加载，设置skel属性为RegistryImpl_Skel
    2. this.setSkeleton(var1);
    
//至此，RegistryImpl_Stub和RegistryImpl_Skel
```

### 远程对象的方法是如何调用的？
```java
//根据ip和端口获取Registry
Registry registry = LocateRegistry.getRegistry("127.0.0.1", 1099);
（1）获取registry
public static Registry getRegistry(String host, int port,
                                       RMIClientSocketFactory csf)
        throws RemoteException
    {
        Registry registry = null;

        if (port <= 0)
            port = Registry.REGISTRY_PORT;

        if (host == null || host.length() == 0) {
            // If host is blank (as returned by "file:" URL in 1.0.2 used in
            // java.rmi.Naming), try to convert to real local host name so
            // that the RegistryImpl's checkAccess will not fail.
            try {
                host = java.net.InetAddress.getLocalHost().getHostAddress();
            } catch (Exception e) {
                // If that failed, at least try "" (localhost) anyway...
                host = "";
            }
        }
        LiveRef liveRef =
            new LiveRef(new ObjID(ObjID.REGISTRY_ID),
                        new TCPEndpoint(host, port, csf, null),
                        false);
        RemoteRef ref =
            (csf == null) ? new UnicastRef(liveRef) : new UnicastRef2(liveRef);
        //创建代理对象RegistryImpl_Stub[UnicastRef [liveRef: [endpoint:[127.0.0.1:1099](remote),objID:[0:0:0, 0]]]]
        return (Registry) Util.createProxy(RegistryImpl.class, ref, false);
    }
（2）调用RegistryImpl_Stub的lookup函数
public Remote lookup(String var1) throws AccessException, NotBoundException, RemoteException {
        try {
            // a1.封装一个远程调用，
            RemoteCall var2 = super.ref.newCall(this, operations, 2, 4905912898345647071L);

            try {
                ObjectOutput var3 = var2.getOutputStream();
                var3.writeObject(var1);
            } catch (IOException var18) {
                throw new MarshalException("error marshalling arguments", var18);
            }

            super.ref.invoke(var2);

            Remote var23;
            try {
                // 读取返回的对象，即我们要查找的Proxy[TestRMIInterface,RemoteObjectInvocationHandler[UnicastRef [liveRef: [endpoint:[192.168.230.1:54475](local),objID:[54c142d5:1793bc85073:-7fff, 2706845290879889842]]]]]
                ObjectInput var6 = var2.getInputStream();
                var23 = (Remote)var6.readObject();
            } catch (IOException var15) {
                throw new UnmarshalException("error unmarshalling return", var15);
            } catch (ClassNotFoundException var16) {
                throw new UnmarshalException("error unmarshalling return", var16);
            } finally {
                super.ref.done(var2);
            }
            //返回对象
            return var23;
        } catch (RuntimeException var19) {
            throw var19;
        } catch (RemoteException var20) {
            throw var20;
        } catch (NotBoundException var21) {
            throw var21;
        } catch (Exception var22) {
            throw new UnexpectedException("undeclared checked exception", var22);
        }
    }
------------------------------(a1)-------------------------------------------------------------
public RemoteCall newCall(RemoteObject var1, Operation[] var2, int var3, long var4) throws RemoteException {
        clientRefLog.log(Log.BRIEF, "get connection");
        //建立socket连接
        Connection var6 = this.ref.getChannel().newConnection();

        try {
            clientRefLog.log(Log.VERBOSE, "create call context");
            if (clientCallLog.isLoggable(Log.VERBOSE)) {
                this.logClientCall(var1, var2[var3]);
            }
            // a11 创建实际的远程调用封装对象StreamRemoteCall，var6：socket连接对象，var3：调用函数编号2，var4：调用方法的hash
            StreamRemoteCall var7 = new StreamRemoteCall(var6, this.ref.getObjID(), var3, var4);

            try {
                this.marshalCustomCallData(var7.getOutputStream());
            } catch (IOException var9) {
                throw new MarshalException("error marshaling custom call data");
            }

            return var7;
        } catch (RemoteException var10) {
            this.ref.getChannel().free(var6, false);
            throw var10;
        }
    }
------------------------------(a11)-------------------------------------------------------------
public StreamRemoteCall(Connection var1, ObjID var2, int var3, long var4) throws RemoteException {
        try {
            this.conn = var1;
            Transport.transportLog.log(Log.VERBOSE, "write remote call header...");
            this.conn.getOutputStream().write(80); // 向socket中写入80
            this.getOutputStream();
            var2.write(this.out); // ObjID[space=0:0:0, objNum=0],向socket中写入long:objNum=0,然后写入int：0,long:0,short:0,对应space
            this.out.writeInt(var3);  // 向socket中写入2
            this.out.writeLong(var4); //  向socket中写入4905912898345647071
        } catch (IOException var7) {
            throw new MarshalException("Error marshaling call header", var7);
        }
}
再回到（2）中，向socket中写入var3.writeObject(var1);即HelloService，然后调用 super.ref.invoke(var2);

public void invoke(RemoteCall var1) throws Exception {
        try {
            clientRefLog.log(Log.VERBOSE, "execute call");
            var1.executeCall();
        } catch (RemoteException var3) {
            clientRefLog.log(Log.BRIEF, "exception: ", var3);
            this.free(var1, false);
            throw var3;
        } catch (Error var4) {
            clientRefLog.log(Log.BRIEF, "error: ", var4);
            this.free(var1, false);
            throw var4;
        } catch (RuntimeException var5) {
            clientRefLog.log(Log.BRIEF, "exception: ", var5);
            this.free(var1, false);
            throw var5;
        } catch (Exception var6) {
            clientRefLog.log(Log.BRIEF, "exception: ", var6);
            this.free(var1, true);
            throw var6;
        }
    }

然后执行var1.executeCall();

    public void executeCall() throws Exception {
        DGCAckHandler var2 = null;

        byte var1;
        try {
            if (this.out != null) {
                var2 = this.out.getDGCAckHandler();
            }

            this.releaseOutputStream();
            DataInputStream var3 = new DataInputStream(this.conn.getInputStream());
            byte var4 = var3.readByte();
            if (var4 != 81) {
                if (Transport.transportLog.isLoggable(Log.BRIEF)) {
                    Transport.transportLog.log(Log.BRIEF, "transport return code invalid: " + var4);
                }

                throw new UnmarshalException("Transport return code invalid");
            }

            this.getInputStream();
            var1 = this.in.readByte();
            this.in.readID();
        } catch (UnmarshalException var11) {
            throw var11;
        } catch (IOException var12) {
            throw new UnmarshalException("Error unmarshaling return header", var12);
        } finally {
            if (var2 != null) {
                var2.release();
            }

        }

        switch(var1) {
        //下面是判断var1的值，为1直接return，说明没问题，如果为2的话，会先对对象进行反序列化操作，然后判断是否为Exception类型
        case 1:
            return;
        case 2:
            Object var14;
            try {
                var14 = this.in.readObject();
            } catch (Exception var10) {
                throw new UnmarshalException("Error unmarshaling return", var10);
            }

            if (!(var14 instanceof Exception)) {
                throw new UnmarshalException("Return type not Exception");
            } else {
                this.exceptionReceivedFromServer((Exception)var14);
            }
        default:
            if (Transport.transportLog.isLoggable(Log.BRIEF)) {
                Transport.transportLog.log(Log.BRIEF, "return code invalid: " + var1);
            }

            throw new UnmarshalException("Return code invalid");
        }
    }
```

```java
//再看服务端
  java.lang.Thread.State: RUNNABLE
	  at sun.rmi.registry.RegistryImpl.lookup(RegistryImpl.java:207)
	  - locked <0x414> (a java.util.Hashtable)
	  at sun.rmi.registry.RegistryImpl_Skel.dispatch(Unknown Source:-1)
	  at sun.rmi.server.UnicastServerRef.oldDispatch(UnicastServerRef.java:450)
	  at sun.rmi.server.UnicastServerRef.dispatch(UnicastServerRef.java:294)
	  at sun.rmi.transport.Transport$1.run(Transport.java:200)
	  at sun.rmi.transport.Transport$1.run(Transport.java:197)
	  at java.security.AccessController.doPrivileged(AccessController.java:-1)
	  at sun.rmi.transport.Transport.serviceCall(Transport.java:196)
	  at sun.rmi.transport.tcp.TCPTransport.handleMessages(TCPTransport.java:568)
	  at sun.rmi.transport.tcp.TCPTransport$ConnectionHandler.run0(TCPTransport.java:826)
	  at sun.rmi.transport.tcp.TCPTransport$ConnectionHandler.lambda$run$0(TCPTransport.java:683)
	  at sun.rmi.transport.tcp.TCPTransport$ConnectionHandler$$Lambda$5.1656896096.run(Unknown Source:-1)
	  at java.security.AccessController.doPrivileged(AccessController.java:-1)
	  at sun.rmi.transport.tcp.TCPTransport$ConnectionHandler.run(TCPTransport.java:682)
	  at java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1142)
	  at java.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:617)
	  at java.lang.Thread.run(Thread.java:748)

（1）at sun.rmi.transport.tcp.TCPTransport.handleMessages(TCPTransport.java:568)

void handleMessages(Connection var1, boolean var2) {
        int var3 = this.getEndpoint().getPort();

        try {
            DataInputStream var4 = new DataInputStream(var1.getInputStream());

            do {
                int var5 = var4.read(); // 从socket中读取80
                if (var5 == -1) {
                    if (tcpLog.isLoggable(Log.BRIEF)) {
                        tcpLog.log(Log.BRIEF, "(port " + var3 + ") connection closed");
                    }
                    break;
                }

                if (tcpLog.isLoggable(Log.BRIEF)) {
                    tcpLog.log(Log.BRIEF, "(port " + var3 + ") op = " + var5);
                }

                switch(var5) {
                case 80:
                    //创建StreamRemoteCall
                    StreamRemoteCall var6 = new StreamRemoteCall(var1);
                    if (!this.serviceCall(var6)) {
                        return;
                    }
                    break;
                case 81:
                case 83:
                default:
                    throw new IOException("unknown transport op " + var5);
                case 82:
                    DataOutputStream var7 = new DataOutputStream(var1.getOutputStream());
                    var7.writeByte(83);
                    var1.releaseOutputStream();
                    break;
                case 84:
                    DGCAckHandler.received(UID.read(var4));
                }
            } while(var2);
        } catch (IOException var17) {
            if (tcpLog.isLoggable(Log.BRIEF)) {
                tcpLog.log(Log.BRIEF, "(port " + var3 + ") exception: ", var17);
            }
        } finally {
            try {
                var1.close();
            } catch (IOException var16) {
            }

        }

    }

//调用serviceCall,按照客户端的写入，读取相关数据
（1）向socket中写入80
（2）ObjID[space=0:0:0, objNum=0],向socket中写入long:objNum=0,然后写入int：0,long:0,short:0,对应space
（3）向socket中写入2
（4）向socket中写入4905912898345647071
public boolean serviceCall(final RemoteCall var1) {
        try {
            ObjID var39;
            try {
                // 80已经读取过，这里读取（2）ObjID
                var39 = ObjID.read(var1.getInputStream());
            } catch (IOException var33) {
                throw new MarshalException("unable to read objID", var33);
            }

            Transport var40 = var39.equals(dgcID) ? null : this;
            // 获取导出对象时候存放的Target
            Target var5 = ObjectTable.getTarget(new ObjectEndpoint(var39, var40));
            final Remote var37;
            // 从target中获取远程实现类，即RegistryImpl
            if (var5 != null && (var37 = var5.getImpl()) != null) {
                // 获取转发器，即UnicastServerRef
                final Dispatcher var6 = var5.getDispatcher();
                var5.incrementCallCount();

                boolean var8;
                try {
                    transportLog.log(Log.VERBOSE, "call dispatcher");
                    final AccessControlContext var7 = var5.getAccessControlContext();
                    ClassLoader var41 = var5.getContextClassLoader();
                    ClassLoader var9 = Thread.currentThread().getContextClassLoader();

                    try {
                        setContextClassLoader(var41);
                        currentTransport.set(this);

                        try {
                            AccessController.doPrivileged(new PrivilegedExceptionAction<Void>() {
                                public Void run() throws IOException {
                                    Transport.this.checkAcceptPermission(var7);
                                    // 调用UnicastServerRef的dispatch函数
                                    var6.dispatch(var37, var1);
                                    return null;
                                }
                            }, var7);
                            return true;
                        } catch (PrivilegedActionException var31) {
                            throw (IOException)var31.getException();
                        }
                    } finally {
                        setContextClassLoader(var9);
                        currentTransport.set((Object)null);
                    }
                } catch (IOException var34) {
                    transportLog.log(Log.BRIEF, "exception thrown by dispatcher: ", var34);
                    var8 = false;
                } finally {
                    var5.decrementCallCount();
                }

                return var8;
            }

            throw new NoSuchObjectException("no such object in table");
        } catch (RemoteException var36) {
            ......
        }

        return true;
    }

//调用UnicastServerRef的dispatch函数
var6.dispatch(var37, var1);
读取相关数据
（1）向socket中写入80
（2）ObjID[space=0:0:0, objNum=0],向socket中写入long:objNum=0,然后写入int：0,long:0,short:0,对应space
（3）向socket中写入2
（4）向socket中写入4905912898345647071
public void dispatch(Remote var1, RemoteCall var2) throws IOException {
        try {
            long var4;
            ObjectInput var39;
            try {
                var39 = var2.getInputStream();
                int var3 = var39.readInt(); //读取数据2
                if (var3 >= 0) {
                    if (this.skel != null) {
                        this.oldDispatch(var1, var2, var3);
                        return;
                    }

                    throw new UnmarshalException("skeleton class not found but required for client version");
                }

                var4 = var39.readLong();
            } catch (Exception var35) {
                throw new UnmarshalException("error unmarshalling call header", var35);
            }
            ...........
        } finally {
            var2.releaseInputStream();
            var2.releaseOutputStream();
        }

    }
//然后调用到oldDispatch，最终调用到RegistryImpl_Skel的dispatch函数
var3 = 2
var4 = 4905912898345647071
public void dispatch(Remote var1, RemoteCall var2, int var3, long var4) throws Exception {
        if (var4 != 4905912898345647071L) {
            throw new SkeletonMismatchException("interface hash mismatch");
        } else {
            RegistryImpl var6 = (RegistryImpl)var1;
            String var7;
            Remote var8;
            ObjectInput var10;
            ObjectInput var11;
            switch(var3) {
            case 0:
                ........
            case 1:
                ........
            case 2:
                try {
                    var10 = var2.getInputStream();
                    // 读取字符串HelloService
                    var7 = (String)var10.readObject();
                } catch (IOException var89) {
                    throw new UnmarshalException("error unmarshalling arguments", var89);
                } catch (ClassNotFoundException var90) {
                    throw new UnmarshalException("error unmarshalling arguments", var90);
                } finally {
                    var2.releaseInputStream();
                }
                // 查询到对象，Proxy[TestRMIInterface,RemoteObjectInvocationHandler[UnicastRef [liveRef: [endpoint:[192.168.230.1:54475](local),objID:[54c142d5:1793bc85073:-7fff, 2706845290879889842]]]]]
                var8 = var6.lookup(var7);

                try {
                    ObjectOutput var9 = var2.getResultStream(true);
                    // 返回查询到的代理对象。
                    var9.writeObject(var8);
                    break;
                } catch (IOException var88) {
                    throw new MarshalException("error marshalling return", var88);
                }
            case 3:
                .......
            case 4:
                .......
            default:
                throw new UnmarshalException("invalid method number");
            }

        }
    }
```
```java
// 客户端开始调用Proxy的sayHello函数，最终通过RemoteObjectInvocationHandler的invoke函数走到UnicastRef的invoke
(1) 创建连接
Connection var6 = this.ref.getChannel().newConnection();
(2) 创建远程调用的封装
var7 = new StreamRemoteCall(var6, this.ref.getObjID(), -1, var4);
写入80，[54c142d5:1793bc85073:-7fff, 2706845290879889842]，-1，8370655165776887524等封装数据
(3) 传递参数，通过marshalValue函数
(4) 服务的接受调用请求，然后从导出对象列表中获取TestRMIInterfaceImpl对象，并调用其函数sayHello
```
参考文献：
https://blog.csdn.net/sinat_34596644/article/details/52599688
https://blog.csdn.net/qsort_/article/details/104861625
https://www.daqianduan.com/20883.html
https://blog.csdn.net/qsort_/article/details/104874111?spm=1001.2014.3001.5501
https://blog.csdn.net/qsort_/article/details/104969138#comments_12184647

https://paper.seebug.org/1194/
https://www.cnblogs.com/nice0e3/p/13927460.html
https://www.anquanke.com/post/id/194384
https://xz.aliyun.com/t/7079
https://xz.aliyun.com/t/7264