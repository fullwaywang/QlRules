/**
 * @name linux-67f1aee6f45059fd6b0f5b0ecb2c97ad0451f6b3-iwch_l2t_send
 * @id cpp/linux/67f1aee6f45059fd6b0f5b0ecb2c97ad0451f6b3/iwch_l2t_send
 * @description linux-67f1aee6f45059fd6b0f5b0ecb2c97ad0451f6b3-iwch_l2t_send 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable verror_141) {
	exists(ConditionalExpr target_0 |
		target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=verror_141
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_0.getThen().(VariableAccess).getTarget()=verror_141
		and target_0.getElse().(Literal).getValue()="0")
}

predicate func_2(Parameter vskb_139, Variable verror_141) {
	exists(RelationalOperation target_2 |
		 (target_2 instanceof GTExpr or target_2 instanceof LTExpr)
		and target_2.getLesserOperand().(VariableAccess).getTarget()=verror_141
		and target_2.getGreaterOperand().(Literal).getValue()="0"
		and target_2.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("kfree_skb")
		and target_2.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vskb_139)
}

from Function func, Parameter vskb_139, Variable verror_141
where
not func_0(verror_141)
and verror_141.getType().hasName("int")
and func_2(vskb_139, verror_141)
and vskb_139.getParentScope+() = func
and verror_141.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
