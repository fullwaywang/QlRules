/**
 * @name libtiff-fb3dc46a2fcf6197ff3b93fc76f0c37fddc0333b-main
 * @id cpp/libtiff/fb3dc46a2fcf6197ff3b93fc76f0c37fddc0333b/main
 * @description libtiff-fb3dc46a2fcf6197ff3b93fc76f0c37fddc0333b-tools/tiff2ps.c-main CVE-2017-9403
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vtif_465, LogicalAndExpr target_4, LogicalAndExpr target_5) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("TIFFClose")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtif_465
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_5.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Variable vtif_465, LogicalAndExpr target_5, ExprStmt target_6) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("TIFFClose")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtif_465
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_2(LogicalAndExpr target_4, Function func, ReturnStmt target_2) {
		target_2.getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_2.getParent().(IfStmt).getCondition()=target_4
		and target_2.getEnclosingFunction() = func
}

predicate func_3(LogicalAndExpr target_4, Function func, ReturnStmt target_3) {
		target_3.getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_3.getParent().(IfStmt).getParent().(IfStmt).getCondition()=target_4
		and target_3.getEnclosingFunction() = func
}

predicate func_4(Variable vtif_465, LogicalAndExpr target_4) {
		target_4.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getValue()="-1"
		and target_4.getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("TIFFSetDirectory")
		and target_4.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtif_465
		and target_4.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_5(Variable vtif_465, LogicalAndExpr target_5) {
		target_5.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("uint32")
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_5.getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("TIFFSetSubDirectory")
		and target_5.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtif_465
		and target_5.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("uint32")
}

predicate func_6(Variable vtif_465, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("TIFF2PS")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("FILE *")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vtif_465
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("double")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget().getType().hasName("double")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget().getType().hasName("double")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(VariableAccess).getTarget().getType().hasName("double")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(VariableAccess).getTarget().getType().hasName("int")
}

from Function func, Variable vtif_465, ReturnStmt target_2, ReturnStmt target_3, LogicalAndExpr target_4, LogicalAndExpr target_5, ExprStmt target_6
where
not func_0(vtif_465, target_4, target_5)
and not func_1(vtif_465, target_5, target_6)
and func_2(target_4, func, target_2)
and func_3(target_4, func, target_3)
and func_4(vtif_465, target_4)
and func_5(vtif_465, target_5)
and func_6(vtif_465, target_6)
and vtif_465.getType().hasName("TIFF *")
and vtif_465.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
