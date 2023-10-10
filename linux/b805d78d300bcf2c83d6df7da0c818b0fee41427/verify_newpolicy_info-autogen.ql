/**
 * @name linux-b805d78d300bcf2c83d6df7da0c818b0fee41427-verify_newpolicy_info
 * @id cpp/linux/b805d78d300bcf2c83d6df7da0c818b0fee41427/verify_newpolicy_info
 * @description linux-b805d78d300bcf2c83d6df7da0c818b0fee41427-verify_newpolicy_info 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("xfrm_policy_id2dir")
		and target_0.getArgument(0) instanceof PointerFieldAccess
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Parameter vp_1379) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="index"
		and target_1.getQualifier().(VariableAccess).getTarget()=vp_1379)
}

predicate func_2(Function func) {
	exists(BitwiseAndExpr target_2 |
		target_2.getLeftOperand() instanceof PointerFieldAccess
		and target_2.getEnclosingFunction() = func)
}

from Function func, Parameter vp_1379
where
not func_0(func)
and func_1(vp_1379)
and func_2(func)
and vp_1379.getType().hasName("xfrm_userpolicy_info *")
and vp_1379.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
