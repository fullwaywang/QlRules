/**
 * @name libtpms-2e6173c273ca14adb11386db4e47622552b1c00e-TPMI_RH_NV_AUTH_Unmarshal
 * @id cpp/libtpms/2e6173c273ca14adb11386db4e47622552b1c00e/TPMI-RH-NV-AUTH-Unmarshal
 * @description libtpms-2e6173c273ca14adb11386db4e47622552b1c00e-src/tpm2/Unmarshal.c-TPMI_RH_NV_AUTH_Unmarshal CVE-2021-3623
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtarget_998, VariableAccess target_1, LogicalOrExpr target_2) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vtarget_998
		and target_0.getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("TPMI_RH_NV_AUTH")
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable visNotNv_1012, VariableAccess target_1) {
		target_1.getTarget()=visNotNv_1012
}

predicate func_2(Parameter vtarget_998, LogicalOrExpr target_2) {
		target_2.getAnOperand().(RelationalOperation).getLesserOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vtarget_998
		and target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getValue()="16777216"
		and target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vtarget_998
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getValue()="33554431"
}

from Function func, Parameter vtarget_998, Variable visNotNv_1012, VariableAccess target_1, LogicalOrExpr target_2
where
not func_0(vtarget_998, target_1, target_2)
and func_1(visNotNv_1012, target_1)
and func_2(vtarget_998, target_2)
and vtarget_998.getType().hasName("TPMI_RH_NV_AUTH *")
and visNotNv_1012.getType().hasName("BOOL")
and vtarget_998.getParentScope+() = func
and visNotNv_1012.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
