/**
 * @name wireshark-26eee01f57f0a86fb375892c7937eac24ede4610-dissect_rbm_object
 * @id cpp/wireshark/26eee01f57f0a86fb375892c7937eac24ede4610/dissect-rbm-object
 * @description wireshark-26eee01f57f0a86fb375892c7937eac24ede4610-epan/dissectors/file-rbm.c-dissect_rbm_object CVE-2019-10900
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_2(Parameter vtvb_408, Parameter voffset_408, VariableAccess target_5, ExprStmt target_6, SubExpr target_7) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignAddExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=voffset_408
		and target_2.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getTarget().hasName("tvb_reported_length_remaining")
		and target_2.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtvb_408
		and target_2.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(1).(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=voffset_408
		and target_2.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_5
		and target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_2.getExpr().(AssignAddExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_7.getLeftOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_5(Variable vsubtype_410, VariableAccess target_5) {
		target_5.getTarget()=vsubtype_410
}

predicate func_6(Parameter vtvb_408, Parameter voffset_408, ExprStmt target_6) {
		target_6.getExpr().(FunctionCall).getTarget().hasName("dissect_rbm_extended")
		and target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtvb_408
		and target_6.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=voffset_408
}

predicate func_7(Parameter voffset_408, SubExpr target_7) {
		target_7.getLeftOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=voffset_408
}

from Function func, Parameter vtvb_408, Parameter voffset_408, Variable vsubtype_410, VariableAccess target_5, ExprStmt target_6, SubExpr target_7
where
not func_2(vtvb_408, voffset_408, target_5, target_6, target_7)
and func_5(vsubtype_410, target_5)
and func_6(vtvb_408, voffset_408, target_6)
and func_7(voffset_408, target_7)
and vtvb_408.getType().hasName("tvbuff_t *")
and voffset_408.getType().hasName("gint *")
and vsubtype_410.getType().hasName("guint8")
and vtvb_408.getParentScope+() = func
and voffset_408.getParentScope+() = func
and vsubtype_410.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
