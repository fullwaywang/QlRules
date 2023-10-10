/**
 * @name libarchive-3c7a6dc6694d9b26400d2bd672e04d09ed8a4276-archive_read_format_tar_skip
 * @id cpp/libarchive/3c7a6dc6694d9b26400d2bd672e04d09ed8a4276/archive-read-format-tar-skip
 * @description libarchive-3c7a6dc6694d9b26400d2bd672e04d09ed8a4276-libarchive/archive_read_support_format_tar.c-archive_read_format_tar_skip CVE-2015-8933
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vrequest_598, Variable vp_599, NotExpr target_2, ExprStmt target_3, ExprStmt target_1) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="remaining"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_599
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(Literal).getValue()="9223372036854775807"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vrequest_598
		and target_0.getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-30"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getLocation()))
}

predicate func_1(Variable vrequest_598, Variable vp_599, NotExpr target_2, ExprStmt target_1) {
		target_1.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vrequest_598
		and target_1.getExpr().(AssignAddExpr).getRValue().(PointerFieldAccess).getTarget().getName()="remaining"
		and target_1.getExpr().(AssignAddExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_599
		and target_1.getParent().(IfStmt).getCondition()=target_2
}

predicate func_2(Variable vp_599, NotExpr target_2) {
		target_2.getOperand().(PointerFieldAccess).getTarget().getName()="hole"
		and target_2.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_599
}

predicate func_3(Variable vrequest_598, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vrequest_598
		and target_3.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

from Function func, Variable vrequest_598, Variable vp_599, ExprStmt target_1, NotExpr target_2, ExprStmt target_3
where
not func_0(vrequest_598, vp_599, target_2, target_3, target_1)
and func_1(vrequest_598, vp_599, target_2, target_1)
and func_2(vp_599, target_2)
and func_3(vrequest_598, target_3)
and vrequest_598.getType().hasName("int64_t")
and vp_599.getType().hasName("sparse_block *")
and vrequest_598.getParentScope+() = func
and vp_599.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
