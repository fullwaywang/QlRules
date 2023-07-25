/**
 * @name freerdp-795842f4096501fcefc1a7f535ccc8132feb31d7-parallel_process_irp_create
 * @id cpp/freerdp/795842f4096501fcefc1a7f535ccc8132feb31d7/parallel-process-irp-create
 * @description freerdp-795842f4096501fcefc1a7f535ccc8132feb31d7-channels/parallel/client/parallel_main.c-parallel_process_irp_create CVE-2020-11089
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter virp_82, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("Stream_SafeSeek")
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="input"
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=virp_82
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1) instanceof Literal
		and target_0.getThen().(ReturnStmt).getExpr().(Literal).getValue()="13"
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_0))
}

predicate func_1(Parameter virp_82, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("Stream_GetRemainingLength")
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="input"
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=virp_82
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="4"
		and target_1.getThen().(ReturnStmt).getExpr().(Literal).getValue()="13"
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_1))
}

predicate func_2(Function func) {
	exists(AssignExpr target_2 |
		target_2.getLValue().(VariableAccess).getType().hasName("WCHAR *")
		and target_2.getRValue() instanceof FunctionCall
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Variable vPathLength_86, Parameter virp_82, ExprStmt target_11, DivExpr target_12, ExprStmt target_13, FunctionCall target_6, Function func) {
	exists(IfStmt target_3 |
		target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("Stream_SafeSeek")
		and target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="input"
		and target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=virp_82
		and target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vPathLength_86
		and target_3.getThen().(ReturnStmt).getExpr().(Literal).getValue()="13"
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_3)
		and target_11.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_12.getLeftOperand().(VariableAccess).getLocation())
		and target_13.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_5(Parameter virp_82, PointerFieldAccess target_5) {
		target_5.getTarget().getName()="input"
		and target_5.getQualifier().(VariableAccess).getTarget()=virp_82
		and target_5.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_6(Parameter virp_82, FunctionCall target_6) {
		target_6.getTarget().hasName("Stream_Pointer")
		and target_6.getArgument(0).(PointerFieldAccess).getTarget().getName()="input"
		and target_6.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=virp_82
}

predicate func_8(Parameter virp_82, FunctionCall target_8) {
		target_8.getTarget().hasName("Stream_Seek")
		and target_8.getArgument(0).(PointerFieldAccess).getTarget().getName()="input"
		and target_8.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=virp_82
		and target_8.getArgument(1) instanceof Literal
}

predicate func_11(Variable vPathLength_86, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vPathLength_86
		and target_11.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="pointer"
		and target_11.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and target_11.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="16"
		and target_11.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="pointer"
		and target_11.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="3"
		and target_11.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="24"
}

predicate func_12(Variable vPathLength_86, DivExpr target_12) {
		target_12.getLeftOperand().(VariableAccess).getTarget()=vPathLength_86
		and target_12.getRightOperand().(Literal).getValue()="2"
}

predicate func_13(Parameter virp_82, ExprStmt target_13) {
		target_13.getExpr().(FunctionCall).getTarget().hasName("Stream_Seek")
		and target_13.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="input"
		and target_13.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=virp_82
		and target_13.getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_13.getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getValue()="4"
}

from Function func, Variable vPathLength_86, Parameter virp_82, PointerFieldAccess target_5, FunctionCall target_6, FunctionCall target_8, ExprStmt target_11, DivExpr target_12, ExprStmt target_13
where
not func_0(virp_82, func)
and not func_1(virp_82, func)
and not func_2(func)
and not func_3(vPathLength_86, virp_82, target_11, target_12, target_13, target_6, func)
and func_5(virp_82, target_5)
and func_6(virp_82, target_6)
and func_8(virp_82, target_8)
and func_11(vPathLength_86, target_11)
and func_12(vPathLength_86, target_12)
and func_13(virp_82, target_13)
and vPathLength_86.getType().hasName("UINT32")
and virp_82.getType().hasName("IRP *")
and vPathLength_86.getParentScope+() = func
and virp_82.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
