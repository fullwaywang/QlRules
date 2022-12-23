/**
 * @name linux-67f1aee6f45059fd6b0f5b0ecb2c97ad0451f6b3-iwch_cxgb3_ofld_send
 * @id cpp/linux/67f1aee6f45059fd6b0f5b0ecb2c97ad0451f6b3/iwch_cxgb3_ofld_send
 * @description linux-67f1aee6f45059fd6b0f5b0ecb2c97ad0451f6b3-iwch_cxgb3_ofld_send 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable verror_157) {
	exists(ConditionalExpr target_0 |
		target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=verror_157
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_0.getThen().(VariableAccess).getTarget()=verror_157
		and target_0.getElse().(Literal).getValue()="0")
}

predicate func_2(Parameter vskb_155, Variable verror_157) {
	exists(RelationalOperation target_2 |
		 (target_2 instanceof GTExpr or target_2 instanceof LTExpr)
		and target_2.getLesserOperand().(VariableAccess).getTarget()=verror_157
		and target_2.getGreaterOperand().(Literal).getValue()="0"
		and target_2.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("kfree_skb")
		and target_2.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vskb_155)
}

from Function func, Parameter vskb_155, Variable verror_157
where
not func_0(verror_157)
and verror_157.getType().hasName("int")
and func_2(vskb_155, verror_157)
and vskb_155.getParentScope+() = func
and verror_157.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
