/**
 * @name libtpms-2e6173c273ca14adb11386db4e47622552b1c00e-TPMI_SH_POLICY_Unmarshal
 * @id cpp/libtpms/2e6173c273ca14adb11386db4e47622552b1c00e/TPMI-SH-POLICY-Unmarshal
 * @description libtpms-2e6173c273ca14adb11386db4e47622552b1c00e-src/tpm2/Unmarshal.c-TPMI_SH_POLICY_Unmarshal CVE-2021-3623
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtarget_730, VariableAccess target_1, LogicalOrExpr target_2) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vtarget_730
		and target_0.getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("TPMI_SH_POLICY")
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable visNotPolicySession_738, VariableAccess target_1) {
		target_1.getTarget()=visNotPolicySession_738
}

predicate func_2(Parameter vtarget_730, LogicalOrExpr target_2) {
		target_2.getAnOperand().(RelationalOperation).getLesserOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vtarget_730
		and target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getValue()="50331648"
		and target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vtarget_730
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getValue()="50331711"
}

from Function func, Parameter vtarget_730, Variable visNotPolicySession_738, VariableAccess target_1, LogicalOrExpr target_2
where
not func_0(vtarget_730, target_1, target_2)
and func_1(visNotPolicySession_738, target_1)
and func_2(vtarget_730, target_2)
and vtarget_730.getType().hasName("TPMI_SH_POLICY *")
and visNotPolicySession_738.getType().hasName("BOOL")
and vtarget_730.getParentScope+() = func
and visNotPolicySession_738.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
