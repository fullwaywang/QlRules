/**
 * @name freerdp-6b485b146a1b9d6ce72dfd7b5f36456c166e7a16-serial_process_irp_create
 * @id cpp/freerdp/6b485b146a1b9d6ce72dfd7b5f36456c166e7a16/serial-process-irp-create
 * @description freerdp-6b485b146a1b9d6ce72dfd7b5f36456c166e7a16-channels/serial/client/serial_main.c-serial_process_irp_create CVE-2020-11089
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter virp_127, Variable vPathLength_132, ReturnStmt target_5, RelationalOperation target_3, ExprStmt target_6) {
	exists(NotExpr target_0 |
		target_0.getOperand().(FunctionCall).getTarget().hasName("Stream_SafeSeek")
		and target_0.getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="input"
		and target_0.getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=virp_127
		and target_0.getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vPathLength_132
		and target_0.getParent().(IfStmt).getThen()=target_5
		and target_3.getLesserOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter virp_127, PointerFieldAccess target_1) {
		target_1.getTarget().getName()="input"
		and target_1.getQualifier().(VariableAccess).getTarget()=virp_127
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_2(Variable vPathLength_132, VariableAccess target_2) {
		target_2.getTarget()=vPathLength_132
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_3(Parameter virp_127, Variable vPathLength_132, ReturnStmt target_5, RelationalOperation target_3) {
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getLesserOperand().(FunctionCall).getTarget().hasName("Stream_GetRemainingLength")
		and target_3.getLesserOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="input"
		and target_3.getLesserOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=virp_127
		and target_3.getGreaterOperand().(VariableAccess).getTarget()=vPathLength_132
		and target_3.getParent().(IfStmt).getThen()=target_5
}

predicate func_4(Parameter virp_127, Variable vPathLength_132, Function func, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("Stream_Seek")
		and target_4.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="input"
		and target_4.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=virp_127
		and target_4.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vPathLength_132
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_4
}

predicate func_5(ReturnStmt target_5) {
		target_5.getExpr().(Literal).getValue()="13"
}

predicate func_6(Parameter virp_127, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="IoStatus"
		and target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=virp_127
		and target_6.getExpr().(AssignExpr).getRValue().(Literal).getValue()="3221225473"
}

from Function func, Parameter virp_127, Variable vPathLength_132, PointerFieldAccess target_1, VariableAccess target_2, RelationalOperation target_3, ExprStmt target_4, ReturnStmt target_5, ExprStmt target_6
where
not func_0(virp_127, vPathLength_132, target_5, target_3, target_6)
and func_1(virp_127, target_1)
and func_2(vPathLength_132, target_2)
and func_3(virp_127, vPathLength_132, target_5, target_3)
and func_4(virp_127, vPathLength_132, func, target_4)
and func_5(target_5)
and func_6(virp_127, target_6)
and virp_127.getType().hasName("IRP *")
and vPathLength_132.getType().hasName("UINT32")
and virp_127.getParentScope+() = func
and vPathLength_132.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
