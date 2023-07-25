/**
 * @name openjpeg-f8796711e8d8e004d8b73929f0ff87c83abf0c76-opj_t2_decode_packets
 * @id cpp/openjpeg/f8796711e8d8e004d8b73929f0ff87c83abf0c76/opj-t2-decode-packets
 * @description openjpeg-f8796711e8d8e004d8b73929f0ff87c83abf0c76-src/lib/openjp2/t2.c-opj_t2_decode_packets CVE-2014-7945
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vl_pi_342, Variable vl_nb_pocs_348, Variable vl_current_pi_349, ExprStmt target_1, ExprStmt target_2, ExprStmt target_3, FunctionCall target_4) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="prg"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="poc"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vl_current_pi_349
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("opj_pi_destroy")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vl_pi_342
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vl_nb_pocs_348
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Variable vl_pi_342, Variable vl_nb_pocs_348, ExprStmt target_1) {
		target_1.getExpr().(FunctionCall).getTarget().hasName("opj_pi_destroy")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vl_pi_342
		and target_1.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vl_nb_pocs_348
}

predicate func_2(Variable vl_pi_342, Variable vl_nb_pocs_348, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("opj_pi_destroy")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vl_pi_342
		and target_2.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vl_nb_pocs_348
}

predicate func_3(Variable vl_pi_342, Variable vl_current_pi_349, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vl_current_pi_349
		and target_3.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vl_pi_342
}

predicate func_4(Variable vl_current_pi_349, FunctionCall target_4) {
		target_4.getTarget().hasName("opj_pi_next")
		and target_4.getArgument(0).(VariableAccess).getTarget()=vl_current_pi_349
}

from Function func, Variable vl_pi_342, Variable vl_nb_pocs_348, Variable vl_current_pi_349, ExprStmt target_1, ExprStmt target_2, ExprStmt target_3, FunctionCall target_4
where
not func_0(vl_pi_342, vl_nb_pocs_348, vl_current_pi_349, target_1, target_2, target_3, target_4)
and func_1(vl_pi_342, vl_nb_pocs_348, target_1)
and func_2(vl_pi_342, vl_nb_pocs_348, target_2)
and func_3(vl_pi_342, vl_current_pi_349, target_3)
and func_4(vl_current_pi_349, target_4)
and vl_pi_342.getType().hasName("opj_pi_iterator_t *")
and vl_nb_pocs_348.getType().hasName("OPJ_UINT32")
and vl_current_pi_349.getType().hasName("opj_pi_iterator_t *")
and vl_pi_342.getParentScope+() = func
and vl_nb_pocs_348.getParentScope+() = func
and vl_current_pi_349.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
