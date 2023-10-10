/**
 * @name linux-dbb2483b2a46fbaf833cfb5deb5ed9cace9c7399-validate_tmpl
 * @id cpp/linux/dbb2483b2a46fbaf833cfb5deb5ed9cace9c7399/validate_tmpl
 * @description linux-dbb2483b2a46fbaf833cfb5deb5ed9cace9c7399-validate_tmpl 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("xfrm_id_proto_valid")
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0) instanceof ValueFieldAccess
		and target_0.getThen() instanceof ReturnStmt
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Parameter vut_1470, Variable vi_1473) {
	exists(ValueFieldAccess target_1 |
		target_1.getTarget().getName()="proto"
		and target_1.getQualifier().(ValueFieldAccess).getTarget().getName()="id"
		and target_1.getQualifier().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vut_1470
		and target_1.getQualifier().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_1473)
}

predicate func_2(Function func) {
	exists(ReturnStmt target_2 |
		target_2.getExpr().(UnaryMinusExpr).getValue()="-22"
		and target_2.getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="22"
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Function func) {
	exists(SwitchStmt target_3 |
		target_3.getExpr() instanceof ValueFieldAccess
		and target_3.getStmt().(BlockStmt).getStmt(3).(SwitchCase).getExpr().(Literal).getValue()="43"
		and target_3.getStmt().(BlockStmt).getStmt(4).(SwitchCase).getExpr().(Literal).getValue()="60"
		and target_3.getStmt().(BlockStmt).getStmt(5).(SwitchCase).getExpr().(Literal).getValue()="255"
		and target_3.getStmt().(BlockStmt).getStmt(6).(BreakStmt).toString() = "break;"
		and target_3.getStmt().(BlockStmt).getStmt(7).(SwitchCase).toString() = "default: "
		and target_3.getStmt().(BlockStmt).getStmt(8) instanceof ReturnStmt
		and target_3.getEnclosingFunction() = func)
}

predicate func_12(Function func) {
	exists(LabelStmt target_12 |
		target_12.toString() = "label ...:"
		and target_12.getEnclosingFunction() = func)
}

from Function func, Parameter vut_1470, Variable vi_1473
where
not func_0(func)
and func_1(vut_1470, vi_1473)
and func_2(func)
and func_3(func)
and func_12(func)
and vut_1470.getType().hasName("xfrm_user_tmpl *")
and vi_1473.getType().hasName("int")
and vut_1470.getParentScope+() = func
and vi_1473.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
