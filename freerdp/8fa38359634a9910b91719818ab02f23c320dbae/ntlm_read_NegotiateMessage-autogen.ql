/**
 * @name freerdp-8fa38359634a9910b91719818ab02f23c320dbae-ntlm_read_NegotiateMessage
 * @id cpp/freerdp/8fa38359634a9910b91719818ab02f23c320dbae/ntlm-read-NegotiateMessage
 * @description freerdp-8fa38359634a9910b91719818ab02f23c320dbae-winpr/libwinpr/sspi/NTLM/ntlm_message.c-ntlm_read_NegotiateMessage CVE-2020-11088
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vs_200, ExprStmt target_3, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("Stream_GetRemainingLength")
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_200
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="4"
		and target_0.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="2148074248"
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_0)
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Variable vs_200, ExprStmt target_5, ExprStmt target_2, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("Stream_Free")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_200
		and target_1.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(22)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(22).getFollowingStmt()=target_1)
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_2(Variable vs_200, Function func, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("Stream_Free")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_200
		and target_2.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2
}

predicate func_3(Variable vs_200, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("Stream_Free")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_200
		and target_3.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
}

predicate func_5(Variable vs_200, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("Stream_Free")
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_200
		and target_5.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
}

from Function func, Variable vs_200, ExprStmt target_2, ExprStmt target_3, ExprStmt target_5
where
not func_0(vs_200, target_3, func)
and not func_1(vs_200, target_5, target_2, func)
and func_2(vs_200, func, target_2)
and func_3(vs_200, target_3)
and func_5(vs_200, target_5)
and vs_200.getType().hasName("wStream *")
and vs_200.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
