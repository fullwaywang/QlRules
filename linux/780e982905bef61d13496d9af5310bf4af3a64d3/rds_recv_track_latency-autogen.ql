/**
 * @name linux-780e982905bef61d13496d9af5310bf4af3a64d3-rds_recv_track_latency
 * @id cpp/linux/780e982905bef61d13496d9af5310bf4af3a64d3/rds-recv-track-latency
 * @description linux-780e982905bef61d13496d9af5310bf4af3a64d3-rds_recv_track_latency 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vtrace_304, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getTarget().getName()="rx_traces"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrace_304
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-14"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="14"
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_0))
}

from Function func, Variable vtrace_304
where
not func_0(vtrace_304, func)
and vtrace_304.getType().hasName("rds_rx_trace_so")
and vtrace_304.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
