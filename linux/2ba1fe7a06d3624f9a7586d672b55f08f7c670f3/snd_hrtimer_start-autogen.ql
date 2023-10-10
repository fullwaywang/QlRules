/**
 * @name linux-2ba1fe7a06d3624f9a7586d672b55f08f7c670f3-snd_hrtimer_start
 * @id cpp/linux/2ba1fe7a06d3624f9a7586d672b55f08f7c670f3/snd_hrtimer_start
 * @description linux-2ba1fe7a06d3624f9a7586d672b55f08f7c670f3-snd_hrtimer_start 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vstime_90) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("hrtimer_cancel")
		and not target_0.getTarget().hasName("hrtimer_try_to_cancel")
		and target_0.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="hrt"
		and target_0.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstime_90)
}

from Function func, Variable vstime_90
where
func_0(vstime_90)
and vstime_90.getType().hasName("snd_hrtimer *")
and vstime_90.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
