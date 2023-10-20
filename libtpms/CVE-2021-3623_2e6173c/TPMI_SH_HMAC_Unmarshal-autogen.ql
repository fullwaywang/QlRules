/**
 * @name libtpms-2e6173c273ca14adb11386db4e47622552b1c00e-TPMI_SH_HMAC_Unmarshal
 * @id cpp/libtpms/2e6173c273ca14adb11386db4e47622552b1c00e/TPMI-SH-HMAC-Unmarshal
 * @description libtpms-2e6173c273ca14adb11386db4e47622552b1c00e-src/tpm2/Unmarshal.c-TPMI_SH_HMAC_Unmarshal CVE-2021-3623
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtarget_711, VariableAccess target_1, LogicalOrExpr target_2) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vtarget_711
		and target_0.getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("TPMI_SH_HMAC")
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable visNotHmacSession_719, VariableAccess target_1) {
		target_1.getTarget()=visNotHmacSession_719
}

predicate func_2(Parameter vtarget_711, LogicalOrExpr target_2) {
		target_2.getAnOperand().(RelationalOperation).getLesserOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vtarget_711
		and target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getValue()="33554432"
		and target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vtarget_711
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getValue()="33554495"
}

from Function func, Parameter vtarget_711, Variable visNotHmacSession_719, VariableAccess target_1, LogicalOrExpr target_2
where
not func_0(vtarget_711, target_1, target_2)
and func_1(visNotHmacSession_719, target_1)
and func_2(vtarget_711, target_2)
and vtarget_711.getType().hasName("TPMI_SH_HMAC *")
and visNotHmacSession_719.getType().hasName("BOOL")
and vtarget_711.getParentScope+() = func
and visNotHmacSession_719.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
