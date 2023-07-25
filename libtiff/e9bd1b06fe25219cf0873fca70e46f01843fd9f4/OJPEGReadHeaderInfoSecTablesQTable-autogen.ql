/**
 * @name libtiff-e9bd1b06fe25219cf0873fca70e46f01843fd9f4-OJPEGReadHeaderInfoSecTablesQTable
 * @id cpp/libtiff/e9bd1b06fe25219cf0873fca70e46f01843fd9f4/OJPEGReadHeaderInfoSecTablesQTable
 * @description libtiff-e9bd1b06fe25219cf0873fca70e46f01843fd9f4-libtiff/tif_ojpeg.c-OJPEGReadHeaderInfoSecTablesQTable CVE-2017-9404
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vsp_1753, Variable vm_1754, LogicalAndExpr target_1, ArrayExpr target_2, ExprStmt target_3) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="qtable"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_1753
		and target_0.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vm_1754
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_TIFFfree")
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="qtable"
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_1753
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vm_1754
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(13)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vsp_1753, Variable vm_1754, LogicalAndExpr target_1) {
		target_1.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="qtable_offset"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_1753
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vm_1754
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vm_1754
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="qtable_offset"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_1753
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vm_1754
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="qtable_offset"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_1753
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vm_1754
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="1"
}

predicate func_2(Variable vsp_1753, Variable vm_1754, ArrayExpr target_2) {
		target_2.getArrayBase().(PointerFieldAccess).getTarget().getName()="qtable_offset"
		and target_2.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_1753
		and target_2.getArrayOffset().(VariableAccess).getTarget()=vm_1754
}

predicate func_3(Variable vsp_1753, Variable vm_1754, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="qtable"
		and target_3.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_1753
		and target_3.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vm_1754
		and target_3.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget().getType().hasName("uint8 *")
}

from Function func, Variable vsp_1753, Variable vm_1754, LogicalAndExpr target_1, ArrayExpr target_2, ExprStmt target_3
where
not func_0(vsp_1753, vm_1754, target_1, target_2, target_3)
and func_1(vsp_1753, vm_1754, target_1)
and func_2(vsp_1753, vm_1754, target_2)
and func_3(vsp_1753, vm_1754, target_3)
and vsp_1753.getType().hasName("OJPEGState *")
and vm_1754.getType().hasName("uint8")
and vsp_1753.(LocalVariable).getFunction() = func
and vm_1754.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
