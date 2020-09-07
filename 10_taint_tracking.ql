import cpp
import semmle.code.cpp.dataflow.TaintTracking
import DataFlow::PathGraph

class NetworkByteSwap extends Expr {
    NetworkByteSwap () {
        exists(MacroInvocation mi |
            mi.getMacro().getName().regexpMatch("ntoh.*") |
            mi.getExpr() = this
        )
    }
}

class Config extends TaintTracking::Configuration {
    Config() { this = "NetworkToMemFuncLength" }

    override predicate isSource(DataFlow::Node source) {
        exists(Expr se | se = source.asExpr() | se instanceof NetworkByteSwap)
    }

    override predicate isSink(DataFlow::Node sink) {
        exists (
            FunctionCall call | 
            call.getTarget().getName() = "memcpy" | 
            sink.asExpr() =  call.getArgument(2))
    }
}

from Config cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, source, sink, "Network byte swap flows to memcpy"
