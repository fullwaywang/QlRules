/**
 * @name libtiff-e9bd1b06fe25219cf0873fca70e46f01843fd9f4-OJPEGReadHeaderInfoSecTablesAcTable
 * @id cpp/libtiff/e9bd1b06fe25219cf0873fca70e46f01843fd9f4/OJPEGReadHeaderInfoSecTablesAcTable
 * @description libtiff-e9bd1b06fe25219cf0873fca70e46f01843fd9f4-libtiff/tif_ojpeg.c-OJPEGReadHeaderInfoSecTablesAcTable CVE-2017-9404
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vsp_1877, Variable vm_1878, LogicalAndExpr target_1, ArrayExpr target_2, ExprStmt target_3, ExprStmt target_4) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="actable"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_1877
		and target_0.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vm_1878
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_TIFFfree")
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="actable"
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_1877
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vm_1878
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(18)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_4.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation()))
}

predicate func_1(Variable vsp_1877, Variable vm_1878, LogicalAndExpr target_1) {
		target_1.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="actable_offset"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_1877
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vm_1878
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vm_1878
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="actable_offset"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_1877
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vm_1878
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="actable_offset"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_1877
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vm_1878
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="1"
}

predicate func_2(Variable vsp_1877, Variable vm_1878, ArrayExpr target_2) {
		target_2.getArrayBase().(PointerFieldAccess).getTarget().getName()="actable_offset"
		and target_2.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_1877
		and target_2.getArrayOffset().(VariableAccess).getTarget()=vm_1878
}

predicate func_3(Variable vsp_1877, Variable vm_1878, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="actable"
		and target_3.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsp_1877
		and target_3.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vm_1878
		and target_3.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget().getType().hasName("uint8 *")
}

predicate func_4(Variable vm_1878, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType().hasName("uint8 *")
		and target_4.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(AddExpr).getValue()="8"
		and target_4.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(Literal).getValue()="16"
		and target_4.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(VariableAccess).getTarget()=vm_1878
}

from Function func, Variable vsp_1877, Variable vm_1878, LogicalAndExpr target_1, ArrayExpr target_2, ExprStmt target_3, ExprStmt target_4
where
not func_0(vsp_1877, vm_1878, target_1, target_2, target_3, target_4)
and func_1(vsp_1877, vm_1878, target_1)
and func_2(vsp_1877, vm_1878, target_2)
and func_3(vsp_1877, vm_1878, target_3)
and func_4(vm_1878, target_4)
and vsp_1877.getType().hasName("OJPEGState *")
and vm_1878.getType().hasName("uint8")
and vsp_1877.(LocalVariable).getFunction() = func
and vm_1878.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
