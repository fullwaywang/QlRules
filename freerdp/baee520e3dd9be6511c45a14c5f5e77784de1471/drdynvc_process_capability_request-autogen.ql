/**
 * @name freerdp-baee520e3dd9be6511c45a14c5f5e77784de1471-drdynvc_process_capability_request
 * @id cpp/freerdp/baee520e3dd9be6511c45a14c5f5e77784de1471/drdynvc-process-capability-request
 * @description freerdp-baee520e3dd9be6511c45a14c5f5e77784de1471-channels/drdynvc/client/drdynvc_main.c-drdynvc_process_capability_request CVE-2018-1000852
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vs_876, BlockStmt target_5, ExprStmt target_6) {
	exists(RelationalOperation target_0 |
		 (target_0 instanceof GTExpr or target_0 instanceof LTExpr)
		and target_0.getLesserOperand().(FunctionCall).getTarget().hasName("Stream_GetRemainingLength")
		and target_0.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_876
		and target_0.getGreaterOperand().(Literal).getValue()="3"
		and target_0.getParent().(IfStmt).getThen()=target_5
		and target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(LogicalOrExpr target_4, Function func) {
	exists(ReturnStmt target_1 |
		target_1.getExpr().(Literal).getValue()="13"
		and target_1.getParent().(IfStmt).getCondition()=target_4
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Parameter vs_876, ExprStmt target_7, Function func) {
	exists(IfStmt target_2 |
		target_2.getCondition() instanceof LogicalOrExpr
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("Stream_GetRemainingLength")
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_876
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="8"
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="13"
		and target_2.getThen().(BlockStmt).getStmt(1).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_2.getThen().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="PriorityCharge0"
		and target_2.getThen().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(Literal).getValue()="1"
		and target_2.getThen().(BlockStmt).getStmt(1).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("Stream_Seek")
		and target_2.getThen().(BlockStmt).getStmt(2).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_2.getThen().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="PriorityCharge1"
		and target_2.getThen().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(Literal).getValue()="1"
		and target_2.getThen().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("Stream_Seek")
		and target_2.getThen().(BlockStmt).getStmt(3).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_2.getThen().(BlockStmt).getStmt(3).(DoStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="PriorityCharge2"
		and target_2.getThen().(BlockStmt).getStmt(3).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(Literal).getValue()="1"
		and target_2.getThen().(BlockStmt).getStmt(3).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("Stream_Seek")
		and target_2.getThen().(BlockStmt).getStmt(4).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_2.getThen().(BlockStmt).getStmt(4).(DoStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="PriorityCharge3"
		and target_2.getThen().(BlockStmt).getStmt(4).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(Literal).getValue()="1"
		and target_2.getThen().(BlockStmt).getStmt(4).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("Stream_Seek")
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_2)
		and target_2.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_7.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

/*predicate func_3(Parameter vs_876, LogicalOrExpr target_4, ExprStmt target_7) {
	exists(IfStmt target_3 |
		target_3.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("Stream_GetRemainingLength")
		and target_3.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_876
		and target_3.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="8"
		and target_3.getThen().(ReturnStmt).getExpr().(Literal).getValue()="13"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
		and target_3.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_7.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
predicate func_4(Parameter vdrdynvc_875, BlockStmt target_5, LogicalOrExpr target_4) {
		target_4.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="version"
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdrdynvc_875
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="2"
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="version"
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdrdynvc_875
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="3"
		and target_4.getParent().(IfStmt).getThen()=target_5
}

predicate func_5(Parameter vdrdynvc_875, Parameter vs_876, BlockStmt target_5) {
		target_5.getStmt(0).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_5.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="PriorityCharge0"
		and target_5.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdrdynvc_875
		and target_5.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(Literal).getValue()="1"
		and target_5.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("Stream_Seek")
		and target_5.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_876
		and target_5.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_5.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getValue()="2"
}

predicate func_6(Parameter vs_876, ExprStmt target_6) {
		target_6.getExpr().(FunctionCall).getTarget().hasName("Stream_Seek")
		and target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_876
		and target_6.getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getType() instanceof LongType
		and target_6.getExpr().(FunctionCall).getArgument(1).(SizeofTypeOperator).getValue()="2"
}

predicate func_7(Parameter vdrdynvc_875, Parameter vs_876, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="PriorityCharge0"
		and target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdrdynvc_875
		and target_7.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="pointer"
		and target_7.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_876
		and target_7.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="pointer"
		and target_7.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
		and target_7.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
}

from Function func, Parameter vdrdynvc_875, Parameter vs_876, LogicalOrExpr target_4, BlockStmt target_5, ExprStmt target_6, ExprStmt target_7
where
not func_0(vs_876, target_5, target_6)
and not func_1(target_4, func)
and not func_2(vs_876, target_7, func)
and func_4(vdrdynvc_875, target_5, target_4)
and func_5(vdrdynvc_875, vs_876, target_5)
and func_6(vs_876, target_6)
and func_7(vdrdynvc_875, vs_876, target_7)
and vdrdynvc_875.getType().hasName("drdynvcPlugin *")
and vs_876.getType().hasName("wStream *")
and vdrdynvc_875.getParentScope+() = func
and vs_876.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
