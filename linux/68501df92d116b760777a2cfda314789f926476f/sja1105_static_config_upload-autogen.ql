/**
 * @name linux-68501df92d116b760777a2cfda314789f926476f-sja1105_static_config_upload
 * @id cpp/linux/68501df92d116b760777a2cfda314789f926476f/sja1105-static-config-upload
 * @description linux-68501df92d116b760777a2cfda314789f926476f-sja1105_static_config_upload 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vrc_400) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vrc_400
		and target_0.getExpr().(AssignExpr).getRValue() instanceof UnaryMinusExpr
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vrc_400
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0")
}

predicate func_1(Variable vrc_400) {
	exists(GotoStmt target_1 |
		target_1.toString() = "goto ..."
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vrc_400
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0")
}

predicate func_2(Variable vrc_400) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vrc_400
		and target_2.getExpr().(AssignExpr).getRValue() instanceof UnaryMinusExpr
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vrc_400
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0")
}

predicate func_4(Function func) {
	exists(UnaryMinusExpr target_4 |
		target_4.getValue()="-22"
		and target_4.getOperand().(Literal).getValue()="22"
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Function func) {
	exists(UnaryMinusExpr target_5 |
		target_5.getValue()="-6"
		and target_5.getOperand().(Literal).getValue()="6"
		and target_5.getEnclosingFunction() = func)
}

predicate func_6(Variable vrc_400) {
	exists(ReturnStmt target_6 |
		target_6.getExpr() instanceof UnaryMinusExpr
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vrc_400
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0")
}

predicate func_7(Variable vrc_400) {
	exists(ReturnStmt target_7 |
		target_7.getExpr() instanceof UnaryMinusExpr
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vrc_400
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0")
}

from Function func, Variable vrc_400
where
not func_0(vrc_400)
and not func_1(vrc_400)
and not func_2(vrc_400)
and func_4(func)
and func_5(func)
and func_6(vrc_400)
and func_7(vrc_400)
and vrc_400.getType().hasName("int")
and vrc_400.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
