/**
 * @name linux-e02f0d3970404bfea385b6edb86f2d936db0ea2b-nft_verdict_init
 * @id cpp/linux/e02f0d3970404bfea385b6edb86f2d936db0ea2b/nft_verdict_init
 * @description linux-e02f0d3970404bfea385b6edb86f2d936db0ea2b-nft_verdict_init 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vchain_9668) {
	exists(IfStmt target_0 |
		target_0.getCondition().(FunctionCall).getTarget().hasName("nft_chain_is_bound")
		and target_0.getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vchain_9668
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-22"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="22")
}

predicate func_1(Variable vchain_9668) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("nft_is_base_chain")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vchain_9668)
}

from Function func, Variable vchain_9668
where
not func_0(vchain_9668)
and vchain_9668.getType().hasName("nft_chain *")
and func_1(vchain_9668)
and vchain_9668.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
