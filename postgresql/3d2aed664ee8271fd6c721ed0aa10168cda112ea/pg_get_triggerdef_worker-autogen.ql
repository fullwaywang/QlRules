/**
 * @name postgresql-3d2aed664ee8271fd6c721ed0aa10168cda112ea-pg_get_triggerdef_worker
 * @id cpp/postgresql/3d2aed664ee8271fd6c721ed0aa10168cda112ea/pg-get-triggerdef-worker
 * @description postgresql-3d2aed664ee8271fd6c721ed0aa10168cda112ea-src/backend/utils/adt/ruleutils.c-pg_get_triggerdef_worker CVE-2018-1058
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vpretty_819, Variable vtrigrec_822, BitwiseAndExpr target_6, FunctionCall target_3) {
	exists(ConditionalExpr target_0 |
		target_0.getCondition().(VariableAccess).getTarget()=vpretty_819
		and target_0.getThen() instanceof FunctionCall
		and target_0.getElse().(FunctionCall).getTarget().hasName("generate_qualified_relation_name")
		and target_0.getElse().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="tgrelid"
		and target_0.getElse().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrigrec_822
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("appendStringInfo")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("StringInfoData")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()=" ON %s "
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof FunctionCall
		and target_6.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getElse().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getElse().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Function func) {
	exists(BitwiseOrExpr target_2 |
		target_2.getValue()="7"
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Variable vtrigrec_822, FunctionCall target_3) {
		target_3.getTarget().hasName("generate_relation_name")
		and target_3.getArgument(0).(PointerFieldAccess).getTarget().getName()="tgrelid"
		and target_3.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrigrec_822
		and target_3.getArgument(1).(Literal).getValue()="0"
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("appendStringInfo")
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("StringInfoData")
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()=" ON %s "
}

predicate func_4(Function func, BitwiseOrExpr target_4) {
		target_4.getValue()="3"
		and target_4.getEnclosingFunction() = func
}

predicate func_5(Parameter vpretty_819, VariableAccess target_5) {
		target_5.getTarget()=vpretty_819
}

predicate func_6(Variable vtrigrec_822, BitwiseAndExpr target_6) {
		target_6.getLeftOperand().(PointerFieldAccess).getTarget().getName()="tgtype"
		and target_6.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrigrec_822
		and target_6.getRightOperand().(BinaryBitwiseOperation).getValue()="32"
}

from Function func, Parameter vpretty_819, Variable vtrigrec_822, FunctionCall target_3, BitwiseOrExpr target_4, VariableAccess target_5, BitwiseAndExpr target_6
where
not func_0(vpretty_819, vtrigrec_822, target_6, target_3)
and not func_2(func)
and func_3(vtrigrec_822, target_3)
and func_4(func, target_4)
and func_5(vpretty_819, target_5)
and func_6(vtrigrec_822, target_6)
and vpretty_819.getType().hasName("bool")
and vtrigrec_822.getType().hasName("Form_pg_trigger")
and vpretty_819.getFunction() = func
and vtrigrec_822.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
