/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_mvm_ftm_target_chandef_v2
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/iwl-mvm-ftm-target-chandef-v2
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_mvm_ftm_target_chandef_v2 CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_2(Function func) {
	exists(DeclStmt target_2 |
		target_2.getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof CTypedefType
		and func.getEntryPoint().(BlockStmt).getStmt(1)=target_2)
}

predicate func_4(Parameter vmvm_321) {
	exists(AssignExpr target_4 |
		target_4.getLValue().(VariableAccess).getType().hasName("u8")
		and target_4.getRValue().(FunctionCall).getTarget().hasName("iwl_fw_lookup_cmd_ver")
		and target_4.getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="fw"
		and target_4.getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmvm_321
		and target_4.getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="99")
}

predicate func_5(Parameter vformat_bw_323) {
	exists(IfStmt target_5 |
		target_5.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("u8")
		and target_5.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="13"
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vformat_bw_323
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignOrExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vformat_bw_323
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignOrExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="4"
		and target_5.getThen().(BlockStmt).getStmt(2).(BreakStmt).toString() = "break;")
}

predicate func_9(Function func) {
	exists(EmptyStmt target_9 |
		target_9.toString() = ";"
		and target_9.getEnclosingFunction() = func)
}

predicate func_10(Parameter vmvm_321, Parameter vpeer_322) {
	exists(ExprStmt target_10 |
		target_10.getExpr().(FunctionCall).getTarget().hasName("__iwl_err")
		and target_10.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="dev"
		and target_10.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmvm_321
		and target_10.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Unsupported BW in FTM request (%d)\n"
		and target_10.getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getTarget().getName()="width"
		and target_10.getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="chandef"
		and target_10.getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpeer_322)
}

predicate func_12(Parameter vformat_bw_323) {
	exists(PointerDereferenceExpr target_12 |
		target_12.getOperand().(VariableAccess).getTarget()=vformat_bw_323)
}

from Function func, Parameter vmvm_321, Parameter vpeer_322, Parameter vformat_bw_323
where
not func_2(func)
and not func_4(vmvm_321)
and not func_5(vformat_bw_323)
and not func_9(func)
and not func_10(vmvm_321, vpeer_322)
and vmvm_321.getType().hasName("iwl_mvm *")
and vpeer_322.getType().hasName("cfg80211_pmsr_request_peer *")
and vformat_bw_323.getType().hasName("u8 *")
and func_12(vformat_bw_323)
and vmvm_321.getParentScope+() = func
and vpeer_322.getParentScope+() = func
and vformat_bw_323.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
