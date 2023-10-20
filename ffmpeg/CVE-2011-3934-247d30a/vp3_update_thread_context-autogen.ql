/**
 * @name ffmpeg-247d30a7dba6684ccce4508424f35fd58465e535-vp3_update_thread_context
 * @id cpp/ffmpeg/247d30a7dba6684ccce4508424f35fd58465e535/vp3-update-thread-context
 * @description ffmpeg-247d30a7dba6684ccce4508424f35fd58465e535-libavcodec/vp3.c-vp3_update_thread_context CVE-2011-3934
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vs_1853, AddressOfExpr target_3) {
	exists(AddressOfExpr target_0 |
		target_0.getOperand().(PointerFieldAccess).getTarget().getName()="keyframe"
		and target_0.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1853
		and target_0.getParent().(PointerDiffExpr).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_0.getParent().(PointerDiffExpr).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="golden_frame"
		and target_0.getParent().(PointerDiffExpr).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1853
		and target_0.getParent().(PointerDiffExpr).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="golden_frame"
		and target_0.getParent().(PointerDiffExpr).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("Vp3DecodeContext *")
		and target_0.getParent().(PointerDiffExpr).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getLeftOperand() instanceof AddressOfExpr
		and target_0.getParent().(PointerDiffExpr).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getRightOperand().(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="golden_frame"
		and target_0.getParent().(PointerDiffExpr).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getRightOperand().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1853
		and target_3.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vs_1853, VariableAccess target_1) {
		target_1.getTarget()=vs_1853
		and target_1.getParent().(PointerFieldAccess).getParent().(AddressOfExpr).getParent().(PointerDiffExpr).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_1.getParent().(PointerFieldAccess).getParent().(AddressOfExpr).getParent().(PointerDiffExpr).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="golden_frame"
		and target_1.getParent().(PointerFieldAccess).getParent().(AddressOfExpr).getParent().(PointerDiffExpr).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="golden_frame"
		and target_1.getParent().(PointerFieldAccess).getParent().(AddressOfExpr).getParent().(PointerDiffExpr).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getLeftOperand() instanceof AddressOfExpr
}

predicate func_2(Variable vs_1853, AddressOfExpr target_2) {
		target_2.getOperand().(PointerFieldAccess).getTarget().getName()="current_frame"
		and target_2.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1853
		and target_2.getParent().(PointerDiffExpr).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_2.getParent().(PointerDiffExpr).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="golden_frame"
		and target_2.getParent().(PointerDiffExpr).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1853
		and target_2.getParent().(PointerDiffExpr).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="golden_frame"
		and target_2.getParent().(PointerDiffExpr).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("Vp3DecodeContext *")
		and target_2.getParent().(PointerDiffExpr).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getRightOperand().(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="golden_frame"
		and target_2.getParent().(PointerDiffExpr).getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getRightOperand().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1853
}

predicate func_3(Variable vs_1853, AddressOfExpr target_3) {
		target_3.getOperand().(PointerFieldAccess).getTarget().getName()="golden_frame"
		and target_3.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1853
}

from Function func, Variable vs_1853, VariableAccess target_1, AddressOfExpr target_2, AddressOfExpr target_3
where
not func_0(vs_1853, target_3)
and func_1(vs_1853, target_1)
and func_2(vs_1853, target_2)
and func_3(vs_1853, target_3)
and vs_1853.getType().hasName("Vp3DecodeContext *")
and vs_1853.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
