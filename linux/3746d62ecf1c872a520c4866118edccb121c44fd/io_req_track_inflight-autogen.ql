/**
 * @name linux-3746d62ecf1c872a520c4866118edccb121c44fd-io_req_track_inflight
 * @id cpp/linux/3746d62ecf1c872a520c4866118edccb121c44fd/io-req-track-inflight
 * @description linux-3746d62ecf1c872a520c4866118edccb121c44fd-io_req_track_inflight 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vreq_1404) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="task"
		and target_0.getQualifier().(VariableAccess).getTarget()=vreq_1404)
}

predicate func_1(Function func) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("get_current")
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Parameter vreq_1404) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="flags"
		and target_2.getQualifier().(VariableAccess).getTarget()=vreq_1404)
}

from Function func, Parameter vreq_1404
where
not func_0(vreq_1404)
and func_1(func)
and vreq_1404.getType().hasName("io_kiocb *")
and func_2(vreq_1404)
and vreq_1404.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
