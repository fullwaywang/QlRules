/**
 * @name libtpms-2e6173c273ca14adb11386db4e47622552b1c00e-TPMI_RH_AC_Unmarshal
 * @id cpp/libtpms/2e6173c273ca14adb11386db4e47622552b1c00e/TPMI-RH-AC-Unmarshal
 * @description libtpms-2e6173c273ca14adb11386db4e47622552b1c00e-src/tpm2/Unmarshal.c-TPMI_RH_AC_Unmarshal CVE-2021-3623
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtarget_1065, VariableAccess target_1, LogicalOrExpr target_2) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vtarget_1065
		and target_0.getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("TPMI_RH_AC")
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable visNotAC_1073, VariableAccess target_1) {
		target_1.getTarget()=visNotAC_1073
}

predicate func_2(Parameter vtarget_1065, LogicalOrExpr target_2) {
		target_2.getAnOperand().(RelationalOperation).getLesserOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vtarget_1065
		and target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getValue()="2415919104"
		and target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vtarget_1065
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getValue()="2415984639"
}

from Function func, Parameter vtarget_1065, Variable visNotAC_1073, VariableAccess target_1, LogicalOrExpr target_2
where
not func_0(vtarget_1065, target_1, target_2)
and func_1(visNotAC_1073, target_1)
and func_2(vtarget_1065, target_2)
and vtarget_1065.getType().hasName("TPMI_RH_AC *")
and visNotAC_1073.getType().hasName("BOOL")
and vtarget_1065.getParentScope+() = func
and visNotAC_1073.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
