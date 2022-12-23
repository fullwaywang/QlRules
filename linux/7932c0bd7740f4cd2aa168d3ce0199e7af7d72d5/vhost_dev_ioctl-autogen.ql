/**
 * @name linux-7932c0bd7740f4cd2aa168d3ce0199e7af7d72d5-vhost_dev_ioctl
 * @id cpp/linux/7932c0bd7740f4cd2aa168d3ce0199e7af7d72d5/vhost_dev_ioctl
 * @description linux-7932c0bd7740f4cd2aa168d3ce0199e7af7d72d5-vhost_dev_ioctl 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vd_942, Variable veventfp_944) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="log_file"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vd_942
		and target_0.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=veventfp_944
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=veventfp_944
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="log_file"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vd_942)
}

predicate func_1(Parameter vd_942) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="log_file"
		and target_1.getQualifier().(VariableAccess).getTarget()=vd_942)
}

predicate func_2(Parameter vd_942, Variable veventfp_944, Variable vfilep_944, Variable vctx_945) {
	exists(EqualityOperation target_2 |
		target_2.getAnOperand().(VariableAccess).getTarget()=veventfp_944
		and target_2.getAnOperand().(PointerFieldAccess).getTarget().getName()="log_file"
		and target_2.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vd_942
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vfilep_944
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="log_file"
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vd_942
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vctx_945
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="log_ctx"
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vd_942
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="log_ctx"
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vd_942
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(VariableAccess).getTarget()=veventfp_944
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(FunctionCall).getTarget().hasName("eventfd_ctx_fileget")
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=veventfp_944
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(Literal).getValue()="0")
}

from Function func, Parameter vd_942, Variable veventfp_944, Variable vfilep_944, Variable vctx_945
where
not func_0(vd_942, veventfp_944)
and vd_942.getType().hasName("vhost_dev *")
and func_1(vd_942)
and veventfp_944.getType().hasName("file *")
and func_2(vd_942, veventfp_944, vfilep_944, vctx_945)
and vfilep_944.getType().hasName("file *")
and vctx_945.getType().hasName("eventfd_ctx *")
and vd_942.getParentScope+() = func
and veventfp_944.getParentScope+() = func
and vfilep_944.getParentScope+() = func
and vctx_945.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
