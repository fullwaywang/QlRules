/**
 * @name linux-a4270d6795b0580287453ea55974d948393e66ef-napi_frags_skb
 * @id cpp/linux/a4270d6795b0580287453ea55974d948393e66ef/napi_frags_skb
 * @description linux-a4270d6795b0580287453ea55974d948393e66ef-napi_frags_skb 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vskb_5769) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="data"
		and target_0.getQualifier().(VariableAccess).getTarget()=vskb_5769)
}

predicate func_2(Variable vskb_5769) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("skb_gro_header_fast")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vskb_5769
		and target_2.getArgument(1).(Literal).getValue()="0")
}

from Function func, Variable vskb_5769
where
not func_0(vskb_5769)
and func_2(vskb_5769)
and vskb_5769.getType().hasName("sk_buff *")
and vskb_5769.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
