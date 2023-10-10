/**
 * @name freerdp-58a3122250d54de3a944c487776bcd4d1da4721e-ntlm_av_pair_next
 * @id cpp/freerdp/58a3122250d54de3a944c487776bcd4d1da4721e/ntlm-av-pair-next
 * @description freerdp-58a3122250d54de3a944c487776bcd4d1da4721e-winpr/libwinpr/sspi/NTLM/ntlm_av_pairs.c-ntlm_av_pair_next CVE-2020-11097
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vpAvPair_148, Parameter vpcbAvPair_148, Variable voffset_150, NotExpr target_4, PointerArithmeticOperation target_5, PointerDereferenceExpr target_6, ExprStmt target_7, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("ntlm_av_pair_get_next_offset")
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpAvPair_148
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vpcbAvPair_148
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=voffset_150
		and target_0.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_0)
		and target_4.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_5.getAnOperand().(VariableAccess).getLocation())
		and target_6.getOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_7.getExpr().(AssignSubExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vpAvPair_148, VariableAccess target_1) {
		target_1.getTarget()=vpAvPair_148
		and target_1.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_2(Variable voffset_150, VariableAccess target_2) {
		target_2.getTarget()=voffset_150
		and target_2.getParent().(AssignExpr).getLValue() = target_2
		and target_2.getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_3(Parameter vpAvPair_148, Variable voffset_150, Function func, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=voffset_150
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ntlm_av_pair_get_next_offset")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpAvPair_148
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_3
}

predicate func_4(Parameter vpAvPair_148, Parameter vpcbAvPair_148, NotExpr target_4) {
		target_4.getOperand().(FunctionCall).getTarget().hasName("ntlm_av_pair_check")
		and target_4.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpAvPair_148
		and target_4.getOperand().(FunctionCall).getArgument(1).(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vpcbAvPair_148
}

predicate func_5(Parameter vpAvPair_148, Variable voffset_150, PointerArithmeticOperation target_5) {
		target_5.getAnOperand().(VariableAccess).getTarget()=vpAvPair_148
		and target_5.getAnOperand().(VariableAccess).getTarget()=voffset_150
}

predicate func_6(Parameter vpcbAvPair_148, PointerDereferenceExpr target_6) {
		target_6.getOperand().(VariableAccess).getTarget()=vpcbAvPair_148
}

predicate func_7(Parameter vpcbAvPair_148, Variable voffset_150, ExprStmt target_7) {
		target_7.getExpr().(AssignSubExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vpcbAvPair_148
		and target_7.getExpr().(AssignSubExpr).getRValue().(VariableAccess).getTarget()=voffset_150
}

from Function func, Parameter vpAvPair_148, Parameter vpcbAvPair_148, Variable voffset_150, VariableAccess target_1, VariableAccess target_2, ExprStmt target_3, NotExpr target_4, PointerArithmeticOperation target_5, PointerDereferenceExpr target_6, ExprStmt target_7
where
not func_0(vpAvPair_148, vpcbAvPair_148, voffset_150, target_4, target_5, target_6, target_7, func)
and func_1(vpAvPair_148, target_1)
and func_2(voffset_150, target_2)
and func_3(vpAvPair_148, voffset_150, func, target_3)
and func_4(vpAvPair_148, vpcbAvPair_148, target_4)
and func_5(vpAvPair_148, voffset_150, target_5)
and func_6(vpcbAvPair_148, target_6)
and func_7(vpcbAvPair_148, voffset_150, target_7)
and vpAvPair_148.getType().hasName("NTLM_AV_PAIR *")
and vpcbAvPair_148.getType().hasName("size_t *")
and voffset_150.getType().hasName("size_t")
and vpAvPair_148.getParentScope+() = func
and vpcbAvPair_148.getParentScope+() = func
and voffset_150.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
