/**
 * @name libjpeg-turbo-a46c111d9f3642f0ef3819e7298846ccc61869e0-increment_simple_rowgroup_ctr
 * @id cpp/libjpeg-turbo/a46c111d9f3642f0ef3819e7298846ccc61869e0/increment-simple-rowgroup-ctr
 * @description libjpeg-turbo-a46c111d9f3642f0ef3819e7298846ccc61869e0-jdapistd.c-increment_simple_rowgroup_ctr CVE-2020-35538
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vcinfo_379, Parameter vrows_379, ExprStmt target_3, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="using_merged_upsample"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("my_master_ptr")
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="max_v_samp_factor"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcinfo_379
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="2"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("read_and_discard_scanlines")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcinfo_379
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vrows_379
		and target_0.getThen().(BlockStmt).getStmt(1) instanceof ReturnStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_0)
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignAddExpr).getRValue().(DivExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Function func, ReturnStmt target_2) {
		target_2.toString() = "return ..."
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2
}

predicate func_3(Parameter vcinfo_379, Parameter vrows_379, ExprStmt target_3) {
		target_3.getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="rowgroup_ctr"
		and target_3.getExpr().(AssignAddExpr).getRValue().(DivExpr).getLeftOperand().(VariableAccess).getTarget()=vrows_379
		and target_3.getExpr().(AssignAddExpr).getRValue().(DivExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="max_v_samp_factor"
		and target_3.getExpr().(AssignAddExpr).getRValue().(DivExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcinfo_379
}

from Function func, Parameter vcinfo_379, Parameter vrows_379, ReturnStmt target_2, ExprStmt target_3
where
not func_0(vcinfo_379, vrows_379, target_3, func)
and func_2(func, target_2)
and func_3(vcinfo_379, vrows_379, target_3)
and vcinfo_379.getType().hasName("j_decompress_ptr")
and vrows_379.getType().hasName("JDIMENSION")
and vcinfo_379.getParentScope+() = func
and vrows_379.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
