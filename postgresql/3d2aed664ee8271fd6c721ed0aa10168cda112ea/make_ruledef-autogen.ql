/**
 * @name postgresql-3d2aed664ee8271fd6c721ed0aa10168cda112ea-make_ruledef
 * @id cpp/postgresql/3d2aed664ee8271fd6c721ed0aa10168cda112ea/make-ruledef
 * @description postgresql-3d2aed664ee8271fd6c721ed0aa10168cda112ea-src/backend/utils/adt/ruleutils.c-make_ruledef CVE-2018-1058
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vprettyFlags_4623, Variable vev_class_4627, BitwiseAndExpr target_2, BitwiseAndExpr target_3, ExprStmt target_4, FunctionCall target_1) {
	exists(ConditionalExpr target_0 |
		target_0.getCondition().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vprettyFlags_4623
		and target_0.getCondition().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="4"
		and target_0.getThen() instanceof FunctionCall
		and target_0.getElse().(FunctionCall).getTarget().hasName("generate_qualified_relation_name")
		and target_0.getElse().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vev_class_4627
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("appendStringInfo")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("StringInfo")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()=" TO %s"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof FunctionCall
		and target_2.getLeftOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_3.getLeftOperand().(VariableAccess).getLocation())
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getElse().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getElse().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Variable vev_class_4627, FunctionCall target_1) {
		target_1.getTarget().hasName("generate_relation_name")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vev_class_4627
		and target_1.getArgument(1).(Literal).getValue()="0"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("appendStringInfo")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("StringInfo")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()=" TO %s"
}

predicate func_2(Parameter vprettyFlags_4623, BitwiseAndExpr target_2) {
		target_2.getLeftOperand().(VariableAccess).getTarget()=vprettyFlags_4623
		and target_2.getRightOperand().(Literal).getValue()="2"
}

predicate func_3(Parameter vprettyFlags_4623, BitwiseAndExpr target_3) {
		target_3.getLeftOperand().(VariableAccess).getTarget()=vprettyFlags_4623
		and target_3.getRightOperand().(Literal).getValue()="2"
}

predicate func_4(Variable vev_class_4627, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("Relation")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("heap_open")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vev_class_4627
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="1"
}

from Function func, Parameter vprettyFlags_4623, Variable vev_class_4627, FunctionCall target_1, BitwiseAndExpr target_2, BitwiseAndExpr target_3, ExprStmt target_4
where
not func_0(vprettyFlags_4623, vev_class_4627, target_2, target_3, target_4, target_1)
and func_1(vev_class_4627, target_1)
and func_2(vprettyFlags_4623, target_2)
and func_3(vprettyFlags_4623, target_3)
and func_4(vev_class_4627, target_4)
and vprettyFlags_4623.getType().hasName("int")
and vev_class_4627.getType().hasName("Oid")
and vprettyFlags_4623.getFunction() = func
and vev_class_4627.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
