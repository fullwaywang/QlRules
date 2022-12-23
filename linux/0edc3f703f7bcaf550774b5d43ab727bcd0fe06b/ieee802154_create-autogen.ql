/**
 * @name linux-0edc3f703f7bcaf550774b5d43ab727bcd0fe06b-ieee802154_create
 * @id cpp/linux/0edc3f703f7bcaf550774b5d43ab727bcd0fe06b/ieee802154-create
 * @description linux-0edc3f703f7bcaf550774b5d43ab727bcd0fe06b-ieee802154_create 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vrc_1002) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vrc_1002
		and target_0.getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getValue()="-1"
		and target_0.getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getOperand().(Literal).getValue()="1")
}

predicate func_1(Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("capable")
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(Literal).getValue()="13"
		and target_1.getThen().(GotoStmt).toString() = "goto ..."
		and target_1.getEnclosingFunction() = func)
}

from Function func, Variable vrc_1002
where
not func_0(vrc_1002)
and not func_1(func)
and vrc_1002.getType().hasName("int")
and vrc_1002.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
