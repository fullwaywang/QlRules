/**
 * @name linux-2ba1fe7a06d3624f9a7586d672b55f08f7c670f3-snd_hrtimer_stop
 * @id cpp/linux/2ba1fe7a06d3624f9a7586d672b55f08f7c670f3/snd_hrtimer_stop
 * @description linux-2ba1fe7a06d3624f9a7586d672b55f08f7c670f3-snd_hrtimer_stop 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vstime_102, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("hrtimer_try_to_cancel")
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="hrt"
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstime_102
		and (func.getEntryPoint().(BlockStmt).getStmt(2)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(2).getFollowingStmt()=target_0))
}

predicate func_1(Variable vstime_102) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="running"
		and target_1.getQualifier().(VariableAccess).getTarget()=vstime_102)
}

from Function func, Variable vstime_102
where
not func_0(vstime_102, func)
and vstime_102.getType().hasName("snd_hrtimer *")
and func_1(vstime_102)
and vstime_102.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
