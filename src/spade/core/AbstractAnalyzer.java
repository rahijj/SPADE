package spade.core;


import spade.client.Dig;
import spade.client.QueryParameters;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;

import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * @author raza
 */
public abstract class AbstractAnalyzer
{

    public String QUERY_PORT;
    protected RemoteResolver remoteResolver;
    protected volatile boolean SHUTDOWN = false;

    private static SSLServerSocketFactory sslServerSocketFactory;
    private static Map<String, List<String>> functionToClassMap;

    /**
     * remoteFlag is used by query module to signal the Analyzer
     * to resolve any outstanding remote parts of result graph.
     */
    private static boolean remoteFlag = false;

    public static void setRemoteFlag()
    {
        remoteFlag = true;
    }

    public static void clearRemoteFlag()
    {
        remoteFlag = false;
    }

    public static boolean isSetRemoteFlag()
    {
        return remoteFlag;
    }

    public abstract void init();

    public AbstractAnalyzer()
    {
        // load functionToClassMap here
        String file_name = "cfg/functionToClassMap";
        File file = new File(file_name);
        try
        {
            FileOutputStream fos = new FileOutputStream(file);
            ObjectOutputStream oos = new ObjectOutputStream(fos);
            oos.writeObject(functionToClassMap);
            oos.close();
        }
        catch(IOException ex)
        {
            Logger.getLogger(AbstractAnalyzer.class.getName()).log(Level.WARNING, "Unable to read functionToClassMap from file!", ex);
            // creating ourselves
            functionToClassMap = new HashMap<>();
            registerFunction("GetVertex", "spade.query.sql.postgresql.GetVertex", "Set<AbstractVertex>");
            registerFunction("GetEdge", "spade.query.sql.postgresql.GetEdge", "Set<AbstractEdge>");
            registerFunction("GetChildren", "spade.query.sql.postgresql.GetChildren", "Graph");
            registerFunction("GetParents", "spade.query.sql.postgresql.GetParents", "Graph");
            registerFunction("GetLineage", "spade.query.common.GetLineage", "Graph");
            registerFunction("GetPaths", "spade.query.common.GetPaths", "Graph");
        }
    }

    public void shutdown()
    {
        // store functionToClassMap here
        String file_name = "cfg/functionToClassMap";
        File file = new File(file_name);
        try
        {
            FileInputStream fis = new FileInputStream(file);
            ObjectInputStream ois = new ObjectInputStream(fis);
            functionToClassMap = (Map<String, List<String>>) ois.readObject();
            ois.close();
        }
        catch(IOException | ClassNotFoundException ex)
        {
            Logger.getLogger(AbstractAnalyzer.class.getName()).log(Level.WARNING, "Unable to write functionToClassMap to file!", ex);
        }
        // signal to analyzer instances
        SHUTDOWN = true;
    }

    public static void registerFunction(String func_name, String class_name, String ret_type)
    {
        functionToClassMap.put(func_name, Arrays.asList(class_name, ret_type));
    }

    public String getFunctionClassName(String functionName)
    {
        // key -> values
        // function name -> function class name, function return type
        List<String> values = functionToClassMap.get(functionName);
        if(values == null)
        {
            values = Arrays.asList("spade.query.sql.postgresql." + functionName, "Object");
        }

        return values.get(0);
    }

    public String getReturnType(String functionName)
    {
        List<String> values = functionToClassMap.get(functionName);
        if(values == null)
        {
            values = Arrays.asList("spade.query.sql.postgresql." + functionName, "Object");
        }

        return values.get(1);
    }

    public ServerSocket getServerSocket(String socketName)
    {
        ServerSocket serverSocket = null;
        Integer port = null;
        try
        {
            port = Integer.parseInt(Settings.getProperty(socketName));
            if(port == null)
                return null;
            serverSocket = sslServerSocketFactory.createServerSocket(port);
            ((SSLServerSocket) serverSocket).setNeedClientAuth(true);
            Kernel.addServerSocket(serverSocket);
        }
        catch(IOException ex)
        {
            String message = "Socket " + socketName + " creation unsuccessful at port # " + port;
            Logger.getLogger(AbstractAnalyzer.class.getName()).log(Level.SEVERE, message, ex);
        }

        return serverSocket;
    }

    protected abstract class QueryConnection implements Runnable
    {
        protected Socket querySocket;
        protected Map<String, List<String>> queryParameters;
        protected String queryConstraints;
        protected String functionName;
        protected String queryStorage;
        protected Integer resultLimit = null;
        protected String direction = null;
        protected String maxLength = null;

        public QueryConnection(Socket socket)
        {
            querySocket = socket;
        }

        @Override
        public abstract void run();

        protected abstract void parseQuery(String line);

        protected Graph iterateTransformers(Graph graph, String query)
        {
            synchronized (Kernel.transformers)
            {
                QueryParameters digQueryParams = QueryParameters.parseQuery(query);
                for(int i = 0; i < Kernel.transformers.size(); i++)
                {
                    AbstractTransformer transformer = Kernel.transformers.get(i);
                    if(graph != null)
                    {
                        try
                        {
                            graph = transformer.putGraph(graph, digQueryParams);
                            if(graph != null)
                            {
                                //commit after every transformer to enable reading without error
                                graph.commitIndex();
                            }
                        }
                        catch(Exception ex)
                        {
                            Logger.getLogger(QueryConnection.class.getName()).log(Level.SEVERE, "Error in applying transformer!", ex);
                        }
                    }
                    else
                    {
                        break;
                    }
                }
            }
            return graph;
        }
    }
}
