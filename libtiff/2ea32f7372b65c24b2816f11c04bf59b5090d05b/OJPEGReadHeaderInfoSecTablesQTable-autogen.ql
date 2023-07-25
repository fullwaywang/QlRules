/**
 * @name libtiff-2ea32f7372b65c24b2816f11c04bf59b5090d05b-OJPEGReadHeaderInfoSecTablesQTable
 * @id cpp/libtiff/2ea32f7372b65c24b2816f11c04bf59b5090d05b/OJPEGReadHeaderInfoSecTablesQTable
 * @description libtiff-2ea32f7372b65c24b2816f11c04bf59b5090d05b-libtiff/tif_ojpeg.c-OJPEGReadHeaderInfoSecTablesQTable CVE-2017-7594
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vob_1757, EqualityOperation target_2, AddressOfExpr target_3, ExprStmt target_4) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("_TIFFfree")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vob_1757
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_3.getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

predicate func_1(EqualityOperation target_2, Function func, ReturnStmt target_1) {
		target_1.getExpr().(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getCondition()=target_2
		and target_1.getEnclosingFunction() = func
}

predicate func_2(EqualityOperation target_2) {
		target_2.getAnOperand().(VariableAccess).getTarget().getType().hasName("uint32")
		and target_2.getAnOperand().(Literal).getValue()="64"
}

predicate func_3(Variable vob_1757, AddressOfExpr target_3) {
		target_3.getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vob_1757
		and target_3.getOperand().(ArrayExpr).getArrayOffset().(AddExpr).getValue()="9"
}

predicate func_4(Variable vob_1757, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="qtable"
		and target_4.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("OJPEGState *")
		and target_4.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("uint8")
		and target_4.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vob_1757
}

from Function func, Variable vob_1757, ReturnStmt target_1, EqualityOperation target_2, AddressOfExpr target_3, ExprStmt target_4
where
not func_0(vob_1757, target_2, target_3, target_4)
and func_1(target_2, func, target_1)
and func_2(target_2)
and func_3(vob_1757, target_3)
and func_4(vob_1757, target_4)
and vob_1757.getType().hasName("uint8 *")
and vob_1757.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
