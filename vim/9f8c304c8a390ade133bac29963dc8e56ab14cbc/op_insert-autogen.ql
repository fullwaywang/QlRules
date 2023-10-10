/**
 * @name vim-9f8c304c8a390ade133bac29963dc8e56ab14cbc-op_insert
 * @id cpp/vim/9f8c304c8a390ade133bac29963dc8e56ab14cbc/op-insert
 * @description vim-9f8c304c8a390ade133bac29963dc8e56ab14cbc-src/ops.c-op_insert CVE-2022-0261
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter voap_1458, LogicalAndExpr target_2, PointerFieldAccess target_0) {
		target_0.getTarget().getName()="end"
		and target_0.getQualifier().(VariableAccess).getTarget()=voap_1458
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getQualifier().(VariableAccess).getLocation())
}

predicate func_1(Parameter voap_1458, ExprStmt target_3, PointerFieldAccess target_1) {
		target_1.getTarget().getName()="end"
		and target_1.getQualifier().(VariableAccess).getTarget()=voap_1458
		and target_1.getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_2(Parameter voap_1458, LogicalAndExpr target_2) {
		target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="op_type"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=voap_1458
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="18"
		and target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="col"
		and target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="end"
		and target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=voap_1458
		and target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="coladd"
		and target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="end"
		and target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=voap_1458
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="col"
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="b_op_start_orig"
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="coladd"
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="b_op_start_orig"
}

predicate func_3(Parameter voap_1458, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="col"
		and target_3.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="start"
		and target_3.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=voap_1458
		and target_3.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="col"
		and target_3.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="b_op_start_orig"
}

from Function func, Parameter voap_1458, PointerFieldAccess target_0, PointerFieldAccess target_1, LogicalAndExpr target_2, ExprStmt target_3
where
func_0(voap_1458, target_2, target_0)
and func_1(voap_1458, target_3, target_1)
and func_2(voap_1458, target_2)
and func_3(voap_1458, target_3)
and voap_1458.getType().hasName("oparg_T *")
and voap_1458.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
